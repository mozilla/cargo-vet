//! Download contract tests using a loopback HTTP server. The in-memory network
//! mock bypasses HTTP negotiation and decoding, so it cannot verify this boundary.

use super::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

/// Serve one response containing exactly `body`, with the optional
/// `Content-Encoding` header. The caller supplies already-encoded wire bytes;
/// this helper does not compress them. Returns the URL and a thread handle whose
/// result is the request headers. Perform the download before joining the thread.
fn serve_once(
    body: Vec<u8>,
    content_encoding: Option<&'static str>,
) -> (reqwest::Url, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/download", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "no HTTP request received");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() < 16384, "HTTP request headers too large");
        }
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        )
        .unwrap();
        if let Some(encoding) = content_encoding {
            write!(stream, "Content-Encoding: {encoding}\r\n").unwrap();
        }
        stream.write_all(b"\r\n").unwrap();
        stream.write_all(&body).unwrap();
        String::from_utf8(request).unwrap()
    });
    (url, server)
}

/// Check that both in-memory and persisted downloads produce `expected` from
/// the supplied wire bytes and HTTP encoding. For gzip responses, also check
/// that the client advertises support so servers can choose compressed delivery.
fn check_download(body: Vec<u8>, encoding: Option<&'static str>, expected: &[u8]) {
    let _enter = TEST_RUNTIME.enter();
    let network = Network::new_direct();
    for persist in [false, true] {
        let (url, server) = serve_once(body.clone(), encoding);
        let result = TEST_RUNTIME.block_on(async {
            if persist {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("download");
                network.download_and_persist(url, &path).await.unwrap();
                fs::read(path).unwrap()
            } else {
                network.download(url).await.unwrap()
            }
        });
        let request = server.join().unwrap();
        assert_eq!(result, expected);
        if encoding == Some("gzip") {
            assert!(
                request.lines().any(|line| {
                    line.split_once(':').is_some_and(|(name, value)| {
                        name.eq_ignore_ascii_case("accept-encoding")
                            && value.split(',').any(|value| value.trim() == "gzip")
                    })
                }),
                "gzip must be negotiated with the server"
            );
        }
    }
}

#[test]
fn http_gzip_downloads_are_decoded() {
    let contents = b"[audits]\n";
    check_download(gzip(contents), Some("gzip"), contents);
}

#[test]
fn uncompressed_http_downloads_are_preserved() {
    let contents = b"[audits]\n";
    check_download(contents.to_vec(), None, contents);
}

#[test]
fn gzip_files_are_preserved_without_http_content_encoding() {
    let archive = gzip(b"archive contents");
    check_download(archive.clone(), None, &archive);
}
