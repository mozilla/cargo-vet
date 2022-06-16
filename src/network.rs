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
    path::Path,
    time::Duration,
};

use eyre::Context;
use reqwest::{Client, Url};
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

    /// Download a file and persist it to disk
    pub async fn download_and_persist(&self, url: Url, persist_to: &Path) -> Result<(), VetError> {
        let download_tmp_path = OsString::from_iter([persist_to.as_os_str(), OsStr::new(".part")]);
        {
            let _permit = self.connection_semaphore.acquire().await?;

            let mut res = self
                .client
                .get(url.clone())
                .send()
                .await
                .and_then(|res| res.error_for_status())
                .wrap_err_with(|| format!("Failed to download {}", url))?;

            let mut download_tmp = tokio::fs::File::create(&download_tmp_path)
                .await
                .wrap_err("could not create tempfile for download")?;
            while let Some(chunk) = res.chunk().await? {
                let network_bytes = &chunk[..];
                download_tmp.write_all(network_bytes).await?;
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
    pub async fn download(&self, url: Url) -> Result<Vec<u8>, VetError> {
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
