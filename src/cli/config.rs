use crate::errors::{LoadTomlError, SourceFile, TomlParseError};
use miette::SourceOffset;

use std::path::PathBuf;

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(default)]
    pub inspect: Inspect,
}

// Can't use types from `errors` because this may error before `miette` is
// configured. We need to collect the data here then transform it into a report
// once the logger is configured.
pub enum LoadConfigError {
    TomlParse {
        path: PathBuf,
        content: String,
        line: usize,
        col: usize,
        error: toml::de::Error,
    },

    IoError {
        path: PathBuf,
        error: std::io::Error,
    },
}

impl From<LoadConfigError> for miette::Report {
    fn from(err: LoadConfigError) -> Self {
        match err {
            LoadConfigError::TomlParse {
                path,
                content,
                line,
                col,
                error,
            } => TomlParseError {
                span: SourceOffset::from_location(&content, line + 1, col + 1),
                source_code: SourceFile::new(&path.display().to_string(), content),
                error,
            }
            .into(),

            LoadConfigError::IoError { path, error } => {
                miette::Report::from(LoadTomlError::from(error))
                    .context(format!("reading '{}'", path.display()))
            }
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, LoadConfigError> {
        let Some(config_dir) = dirs::config_dir() else {
            return Ok(Self::default());
        };
        let path = config_dir.join("cargo-vet").join("config.toml");
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let config = toml::de::from_str(&content).map_err(|error| {
                    let (line, col) = error.line_col().unwrap_or((0, 0));
                    LoadConfigError::TomlParse {
                        path,
                        content,
                        line,
                        col,
                        error,
                    }
                })?;
                Ok(config)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(LoadConfigError::IoError { path, error }),
        }
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Inspect {
    #[serde(default)]
    pub mode: Option<super::FetchMode>,
}
