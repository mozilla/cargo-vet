//! Networking as a capability
//!
//! All code that wants to hit the network should go through this module.
//!
//! Currently it produces the output all at once, but in the future it would
//! ideally provide hooks to give you streaming access to the download so
//! that you could do a streaming parse and reduce latency on network-bound
//! tasks.

use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use eyre::Context;
use reqwest::{Client, Url};
use tempfile::NamedTempFile;

use crate::{PartialConfig, VetError};

pub struct Network {
    /// The HTTP client all requests go through
    client: Client,
    /// A temp dir where partial downloads for things that want to be persisted
    /// to disk will be built up before being transactionally put in their final
    /// destination with a rename.
    in_progress_download_dir: PathBuf,
}

static DEFAULT_TIMEOUT_SECS: u64 = 60;

impl Network {
    /// Acquire access to the network
    ///
    /// There should only ever be one Network instance instantiated. Do it early
    /// and then pass it around by-ref.
    pub fn acquire(cfg: &PartialConfig) -> Option<Arc<Self>> {
        if cfg.cli.frozen {
            None
        } else {
            // TODO: make this configurable on the CLI or something
            let timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECS);
            // TODO: make this configurable on the CLI or something
            let in_progress_download_dir = std::env::temp_dir();
            let client = Client::builder()
                .timeout(timeout)
                .build()
                .expect("Couldn't construct HTTP Client?");
            Some(Arc::new(Self {
                client,
                in_progress_download_dir,
            }))
        }
    }

    /// Download a file and persist it to disk
    pub async fn download_and_persist(
        &self,
        url: Url,
        persist_to: &Path,
    ) -> Result<File, VetError> {
        let mut res = self
            .client
            .get(url.clone())
            .send()
            .await
            .and_then(|res| res.error_for_status())
            .wrap_err_with(|| format!("Failed to download {}", url))?;

        let mut partial_download = NamedTempFile::new_in(&self.in_progress_download_dir)
            .wrap_err("could not create tempfile for download")?;
        while let Some(chunk) = res.chunk().await? {
            let network_bytes = &chunk[..];
            partial_download.write_all(network_bytes)?;
        }

        let file = partial_download
            .persist_noclobber(&persist_to)
            .wrap_err_with(|| {
                format!(
                    "Couldn't swap download into final location: {}",
                    persist_to.display()
                )
            })?;
        Ok(file)
    }

    /// Download a file into memory
    pub async fn download(&self, url: Url) -> Result<Vec<u8>, VetError> {
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
            output.write_all(network_bytes)?;
        }

        Ok(output)
    }
}
