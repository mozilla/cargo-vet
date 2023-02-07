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
use reqwest::{Client, Response, Url};
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
    pub fn for_response(response: &Response) -> Self {
        // gitiles always encodes content in base64
        if response.headers().contains_key("x-gitiles-object-type") {
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

        let encoding = PayloadEncoding::for_response(&res);

        let mut output = vec![];
        {
            let mut writer = encoding.to_plaintext(&mut output);
            while let Some(chunk) =
                res.chunk()
                    .await
                    .map_err(|error| DownloadError::FailedToReadDownload {
                        url: Box::new(url.clone()),
                        error,
                    })?
            {
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
}
