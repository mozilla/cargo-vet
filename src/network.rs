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
    future::Future,
    path::Path,
    time::Duration,
};

use eyre::{eyre, Context};
use reqwest::{Client, Url};
use ring::digest;
use tokio::io::AsyncWriteExt;

use crate::{PartialConfig, VetError};

pub struct Network {
    /// The HTTP client all requests go through
    client: Client,
    /// Semaphore preventing exceeding the maximum number of connections.
    connection_semaphore: tokio::sync::Semaphore,
}

static DEFAULT_TIMEOUT_SECS: u64 = 60;

const MAX_CONCURRENT_CONNECTIONS: usize = 40;

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

    /// Download a file to a location on disk.
    ///
    /// NOTE: If this method fails, the target path may contain a partially
    /// downloaded file. Use `download_and_persist` to handle partial or
    /// interrupted downloads.
    async fn stream_download_to_file(
        &self,
        url: &Url,
        path: &Path,
    ) -> Result<digest::Digest, VetError> {
        let _permit = self.connection_semaphore.acquire().await?;

        let mut res = self
            .client
            .get(url.clone())
            .send()
            .await
            .and_then(|res| res.error_for_status())
            .wrap_err_with(|| format!("Failed to download {}", url))?;

        let mut digest_cx = digest::Context::new(&digest::SHA256);
        let mut file = tokio::fs::File::create(path)
            .await
            .wrap_err("could not create tempfile for download")?;
        while let Some(chunk) = res.chunk().await? {
            let network_bytes = &chunk[..];
            file.write_all(network_bytes).await?;
            digest_cx.update(network_bytes);
        }
        Ok(digest_cx.finish())
    }

    /// Download a file and persist it to disk
    ///
    /// `checksum_fut` is a future which will resolve to the expected sha256
    /// checksum for the given file. If this future resolves to an error, or the
    /// download fails, this method will abort.
    pub async fn download_and_persist(
        &self,
        url: &Url,
        persist_to: &Path,
        checksum_fut: impl Future<Output = Result<[u8; 32], VetError>>,
    ) -> Result<(), VetError> {
        let download_tmp_path = OsString::from_iter([persist_to.as_os_str(), OsStr::new(".part")]);
        match tokio::try_join!(
            checksum_fut,
            self.stream_download_to_file(url, Path::new(&download_tmp_path))
        ) {
            Ok((expected_digest, actual_digest)) if expected_digest != actual_digest.as_ref() => {
                let _ = tokio::fs::remove_file(&download_tmp_path).await;
                return Err(eyre!(
                    "sha256 digest of {} did not match expected value!\n  expected: {}\n  actual: {}",
                    url,
                    hex::encode(expected_digest),
                    hex::encode(actual_digest.as_ref())
                ));
            }
            Ok(_) => {}
            Err(err) => {
                let _ = tokio::fs::remove_file(&download_tmp_path).await;
                return Err(err);
            }
        }

        // Rename the downloaded file into the final location.
        match tokio::fs::rename(&download_tmp_path, &persist_to).await {
            Ok(()) => {}
            Err(err) => {
                let _ = tokio::fs::remove_file(&download_tmp_path).await;
                return Err(err).wrap_err_with(|| {
                    format!(
                        "Couldn't swap download into final location: {}",
                        persist_to.display()
                    )
                });
            }
        }

        Ok(())
    }

    /// Download a file into memory
    pub async fn download(&self, url: &Url) -> Result<Vec<u8>, VetError> {
        let _permit = self.connection_semaphore.acquire().await?;

        let mut res = self
            .client
            .get(url.clone())
            .send()
            .await
            .and_then(|res| res.error_for_status())
            .wrap_err_with(|| format!("Failed to download {}", url))?;

        let mut output = vec![];
        while let Some(chunk) = res.chunk().await? {
            let network_bytes = &chunk[..];
            output.extend_from_slice(network_bytes);
        }

        Ok(output)
    }
}
