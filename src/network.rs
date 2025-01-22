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
    sync::Mutex,
    time::Duration,
};

use base64_stream::FromBase64Writer;
use bytes::Bytes;
use reqwest::{Client, Url};
use tokio::io::AsyncWriteExt;

use crate::{
    errors::{DownloadError, SourceFile},
    PartialConfig,
};

/// Wrapper for the pair of a `reqwest::Response` and the `SemaphorePermit` used
/// to limit concurrent connections, with a test-only variant for mocking.
enum Response<'a> {
    Real(
        reqwest::Response,
        #[allow(unused)] tokio::sync::SemaphorePermit<'a>,
    ),
    #[cfg(test)]
    Mock(Option<Bytes>),
}

impl Response<'_> {
    fn has_header(&self, name: &str) -> bool {
        match self {
            Response::Real(response, _) => response.headers().contains_key(name),
            #[cfg(test)]
            Response::Mock(_) => false,
        }
    }

    /// Get the next chunk in the response stream, or `None` if at the end of
    /// the stream.
    async fn chunk(&mut self) -> Result<Option<Bytes>, DownloadError> {
        match self {
            Response::Real(res, _) => {
                res.chunk()
                    .await
                    .map_err(|error| DownloadError::FailedToReadDownload {
                        url: Box::new(res.url().clone()),
                        error,
                    })
            }
            #[cfg(test)]
            Response::Mock(data) => Ok(data.take()),
        }
    }
}

pub struct Network {
    /// The HTTP client all requests go through
    client: Client,
    /// Semaphore preventing exceeding the maximum number of connections.
    connection_semaphore: tokio::sync::Semaphore,
    /// Cache of source files downloaded by Url
    source_file_cache: Mutex<std::collections::HashMap<Url, SourceFile>>,
    /// Test-only override for download requests.
    #[cfg(test)]
    mock_network: Option<std::collections::HashMap<Url, Bytes>>,
}

const DEFAULT_TIMEOUT_SECS: u64 = 60;
const MAX_CONCURRENT_CONNECTIONS: usize = 40;
const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("CARGO_PKG_HOMEPAGE"),
    ")"
);

/// The network payload encoding.
///
/// This is only used in `download` (not `download_and_persist`) because (for now) it's only needed
/// in downloading imports (not packages, which is what `download_and_persist` is used for) to
/// workaround known server shortcomings. It could be added to `download_and_persist`, but due to
/// the use of `tokio::io::File` it gets messy and either this or that would need a refactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadEncoding {
    Plaintext,
    Base64,
}

impl PayloadEncoding {
    fn for_response(response: &Response) -> Self {
        // gitiles always encodes content in base64
        if response.has_header("x-gitiles-object-type") {
            Self::Base64
        } else {
            Self::Plaintext
        }
    }

    pub fn to_plaintext<'a, W: Write + 'a>(&self, target: W) -> Box<dyn Write + 'a> {
        match self {
            Self::Plaintext => Box::new(target),
            Self::Base64 => Box::new(FromBase64Writer::new(target)),
        }
    }
}

impl std::fmt::Display for PayloadEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Plaintext => write!(f, "plaintext"),
            Self::Base64 => write!(f, "base64"),
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
            let mut client_builder = Client::builder().user_agent(USER_AGENT).timeout(timeout);
            if let Ok(cargo_config) = cargo_config2::Config::load() {
                // Add the cargo `http.cainfo` to the reqwest client if it is set
                if let Some(cainfo) = cargo_config.http.cainfo {
                    match Network::parse_ca_file(&cainfo) {
                        Ok(cert) => client_builder = client_builder.add_root_certificate(cert),
                        Err(e) => println!(
                            "failed to load certificate from Cargo http.cainfo `{}`, attempting to download without it. Error: {e:?}", cainfo
                       ),
                    }
                }
            }

            let client = client_builder
                .build()
                .expect("Couldn't construct HTTP Client?");
            Some(Self {
                client,
                connection_semaphore: tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS),
                source_file_cache: Default::default(),
                #[cfg(test)]
                mock_network: None,
            })
        }
    }

    fn parse_ca_file(path: &str) -> Result<reqwest::Certificate, Box<dyn std::error::Error>> {
        Ok(reqwest::Certificate::from_pem(&std::fs::read(path)?)?)
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
            let mut res = self.fetch_core(url).await?;

            let mut download_tmp =
                tokio::fs::File::create(&download_tmp_path)
                    .await
                    .map_err(|error| DownloadError::FailedToCreateDownload {
                        target: download_tmp_path.clone(),
                        error,
                    })?;

            while let Some(chunk) = res.chunk().await? {
                download_tmp.write_all(&chunk[..]).await.map_err(|error| {
                    DownloadError::FailedToWriteDownload {
                        target: download_tmp_path.clone(),
                        error,
                    }
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
        let mut res = self.fetch_core(url).await?;

        let encoding = PayloadEncoding::for_response(&res);

        let mut output = vec![];
        {
            let mut writer = encoding.to_plaintext(&mut output);
            while let Some(chunk) = res.chunk().await? {
                writer
                    .write_all(&chunk[..])
                    .map_err(|error| DownloadError::InvalidEncoding { encoding, error })?;
            }
            writer
                .flush()
                .map_err(|error| DownloadError::InvalidEncoding { encoding, error })?;
        }
        Ok(output)
    }

    /// Download a file into memory as a SourceFile, with in-memory caching
    pub async fn download_source_file_cached(&self, url: Url) -> Result<SourceFile, DownloadError> {
        if let Some(source_file) = self.source_file_cache.lock().unwrap().get(&url) {
            return Ok(source_file.clone());
        }

        let bytes = self.download(url.clone()).await?;
        match String::from_utf8(bytes) {
            Ok(string) => {
                let source_file = SourceFile::new(url.as_str(), string);
                self.source_file_cache
                    .lock()
                    .unwrap()
                    .insert(url, source_file.clone());
                Ok(source_file)
            }
            Err(error) => Err(DownloadError::InvalidText {
                url: Box::new(url),
                error,
            }),
        }
    }

    /// Internal core implementation of network fetching which is shared between
    /// `download` and `download_and_persist`.
    async fn fetch_core(&self, url: Url) -> Result<Response, DownloadError> {
        #[cfg(test)]
        if let Some(mock_network) = &self.mock_network {
            let chunk = mock_network
                .get(&url)
                .cloned()
                // The error is complete nonsense, but this is test-only.
                .ok_or_else(|| {
                    tracing::warn!("Attempt to fetch unsupported URL from mock network: {url}");
                    DownloadError::FailedToWriteDownload {
                        target: url.to_string().into(),
                        error: std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("mock network does not support URL: {url}"),
                        ),
                    }
                })?;
            return Ok(Response::Mock(Some(chunk)));
        }

        let permit = self
            .connection_semaphore
            .acquire()
            .await
            .expect("Semaphore dropped?!");

        let mut request_builder = self.client.get(url.clone());

        // Add a header from the environment, if present.
        if let Ok(header) = std::env::var("CARGO_VET_AUTH_HEADER") {
            let (name, value) = header.split_once(':').expect("Invalid header format");
            request_builder = request_builder.header(name, value);
        }

        let res = request_builder
            .send()
            .await
            .and_then(|res| res.error_for_status())
            .map_err(|error| DownloadError::FailedToStartDownload {
                url: Box::new(url.clone()),
                error,
            })?;

        Ok(Response::Real(res, permit))
    }
}

#[cfg(test)]
impl Network {
    /// Create a new Network which is serving mocked out resources.
    pub(crate) fn new_mock() -> Self {
        let mut network = Network {
            client: Client::new(),
            connection_semaphore: tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS),
            source_file_cache: Default::default(),
            #[cfg(test)]
            mock_network: Some(Default::default()),
        };
        // Serve an empty registry by default.
        network.mock_serve_toml(
            crate::storage::REGISTRY_URL,
            &crate::format::RegistryFile::default(),
        );
        network
    }

    /// Add a new resource to be served by a mocked-out network.
    pub(crate) fn mock_serve(&mut self, url: impl AsRef<str>, data: impl AsRef<[u8]>) {
        self.mock_network
            .as_mut()
            .expect("not a mock network")
            .insert(
                url.as_ref().parse().unwrap(),
                Bytes::copy_from_slice(data.as_ref()),
            );
    }

    /// Add a new toml resource to be served by a mocked-out network.
    pub(crate) fn mock_serve_toml(&mut self, url: impl AsRef<str>, data: &impl serde::Serialize) {
        self.mock_serve(
            url,
            crate::serialization::to_formatted_toml(data, None)
                .unwrap()
                .to_string(),
        );
    }

    /// Add a new json resource to be served by a mocked-out network.
    pub(crate) fn mock_serve_json(&mut self, url: impl AsRef<str>, data: &impl serde::Serialize) {
        self.mock_serve(url, serde_json::to_string(data).unwrap());
    }
}
