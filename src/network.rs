//! Networking as a capability
//!
//! All code that wants to hit the network should go through this module.
//!
//! Currently it produces the output all at once, but in the future it would
//! ideally provide hooks to give you streaming access to the download so
//! that you could do a streaming parse and reduce latency on network-bound
//! tasks.

use std::{
    ffi::{OsStr, OsString},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use base64_stream::FromBase64Writer;
use reqwest::{Client, Url};
use tokio::io::AsyncWriteExt;

use crate::{errors::DownloadError, PartialConfig};

pub struct Network {
    /// The HTTP client all requests go through
    client: Client,
    /// Semaphore preventing exceeding the maximum number of connections.
    connection_semaphore: tokio::sync::Semaphore,
}

static DEFAULT_TIMEOUT_SECS: u64 = 60;

const MAX_CONCURRENT_CONNECTIONS: usize = 40;

/// Payload decoder type handling multiple encodings.
///
/// This is only used in `download` (not `download_and_persist`) because (for now) it's only needed
/// in downloading imports (not packages, which is what `download_and_persist` is used for) to
/// workaround known server shortcomings. It could be added to `download_and_persist`, but due to
/// the use of `tokio::io::File` it gets messy and either this or that would need a refactor.
enum PayloadDecoder<W: Write> {
    Plaintext { inner: W },
    Base64 { inner: FromBase64Writer<W> },
}

impl<W: Write> PayloadDecoder<W> {
    /// Create a new decoder based on the response.
    pub fn new(response: &reqwest::Response, target: W) -> Self {
        // gitiles always encodes content in base64
        if response.headers().contains_key("x-gitiles-object-type") {
            Self::Base64 {
                inner: FromBase64Writer::new(target),
            }
        } else {
            Self::Plaintext { inner: target }
        }
    }

    /// Get the encoding name that is decoded.
    pub fn encoding_name(&self) -> &'static str {
        match self {
            Self::Plaintext { .. } => "plaintext",
            Self::Base64 { .. } => "base64",
        }
    }
}

impl<W: Write> Write for PayloadDecoder<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plaintext { inner } => inner.write(buf),
            Self::Base64 { inner } => inner.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plaintext { inner } => inner.flush(),
            Self::Base64 { inner } => inner.flush(),
        }
    }
}

impl Network {
    /// Acquire access to the network
    ///
    /// There should only ever be one Network instance instantiated. Do it early
    /// and then pass it around by-ref.
    pub fn acquire(cfg: &PartialConfig) -> Option<Self> {
        if cfg.cli.frozen {
            None
        } else {
            // TODO: make this configurable on the CLI or something
            let timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECS);
            // TODO: make this configurable on the CLI or something
            let client = Client::builder()
                .timeout(timeout)
                .build()
                .expect("Couldn't construct HTTP Client?");
            Some(Self {
                client,
                connection_semaphore: tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS),
            })
        }
    }

    /// Download a file and persist it to disk
    pub async fn download_and_persist(
        &self,
        url: Url,
        persist_to: &Path,
    ) -> Result<(), DownloadError> {
        let download_tmp_path = PathBuf::from(OsString::from_iter([
            persist_to.as_os_str(),
            OsStr::new(".part"),
        ]));
        {
            let _permit = self
                .connection_semaphore
                .acquire()
                .await
                .expect("Semaphore dropped?!");

            let mut res = self
                .client
                .get(url.clone())
                .send()
                .await
                .and_then(|res| res.error_for_status())
                .map_err(|error| DownloadError::FailedToStartDownload {
                    url: Box::new(url.clone()),
                    error,
                })?;

            let mut download_tmp =
                tokio::fs::File::create(&download_tmp_path)
                    .await
                    .map_err(|error| DownloadError::FailedToCreateDownload {
                        target: download_tmp_path.clone(),
                        error,
                    })?;

            while let Some(chunk) =
                res.chunk()
                    .await
                    .map_err(|error| DownloadError::FailedToReadDownload {
                        url: Box::new(url.clone()),
                        error,
                    })?
            {
                let network_bytes = &chunk[..];
                download_tmp
                    .write_all(network_bytes)
                    .await
                    .map_err(|error| DownloadError::FailedToWriteDownload {
                        target: download_tmp_path.clone(),
                        error,
                    })?;
            }
        }

        // Rename the downloaded file into the final location.
        match tokio::fs::rename(&download_tmp_path, &persist_to).await {
            Ok(()) => {}
            Err(err) => {
                let _ = tokio::fs::remove_file(&download_tmp_path).await;
                return Err(err).map_err(|error| DownloadError::FailedToFinalizeDownload {
                    target: persist_to.to_owned(),
                    error,
                })?;
            }
        }

        Ok(())
    }

    /// Download a file into memory
    pub async fn download(&self, url: Url) -> Result<Vec<u8>, DownloadError> {
        let _permit = self
            .connection_semaphore
            .acquire()
            .await
            .expect("Semaphore dropped?!");

        let mut res = self
            .client
            .get(url.clone())
            .send()
            .await
            .and_then(|res| res.error_for_status())
            .map_err(|error| DownloadError::FailedToStartDownload {
                url: Box::new(url.clone()),
                error,
            })?;

        let mut output = vec![];
        {
            let mut payload_decoder = PayloadDecoder::new(&res, &mut output);
            while let Some(chunk) =
                res.chunk()
                    .await
                    .map_err(|error| DownloadError::FailedToReadDownload {
                        url: Box::new(url.clone()),
                        error,
                    })?
            {
                payload_decoder.write_all(&chunk[..]).map_err(|error| {
                    DownloadError::InvalidEncoding {
                        encoding: payload_decoder.encoding_name().into(),
                        error,
                    }
                })?;
            }
            payload_decoder
                .flush()
                .map_err(|error| DownloadError::InvalidEncoding {
                    encoding: payload_decoder.encoding_name().into(),
                    error,
                })?;
        }

        Ok(output)
    }
}
