use std::path::Path;

/// A small utility for loading Cargo configuration.
/// For moreinfo see: https://doc.rust-lang.org/cargo/reference/config.html
pub struct CargoConfig;

impl CargoConfig {
    /// Path to a Certificate Authority (CA) bundle file, used to verify TLS certificates.
    /// See: https://doc.rust-lang.org/cargo/reference/config.html#httpcainfo
    pub fn http_cainfo() -> Option<String> {
        if let Ok(cainfo) = std::env::var("CARGO_HTTP_CAINFO") {
            return Some(cainfo);
        }

        return Self::find_config_value("http.cainfo");
    }

    /// Finds a config value in the cargo config file.
    /// This method does not consider env vars.
    ///
    /// For the file location priority see: https://doc.rust-lang.org/cargo/reference/config.html#hierarchical-structure
    fn find_config_value(key: &str) -> Option<String> {
        let mut current_dir = std::env::current_dir().ok();

        let key = key.split(".").collect::<Vec<&str>>();

        // Check current directory, then parent directories
        while let Some(dir) = current_dir {
            if let Some(config) = Self::load_cargo_config_file_for_directory(&dir) {
                if let Some(config) = Self::get_config_value(&key, &config) {
                    return Some(config);
                }
            }
            current_dir = dir.parent().map(|p| p.to_path_buf());
        }

        // Once all of the parent directories have been checked, check the home directory
        if let Some(home) = dirs::home_dir().map(|d| d.join(".cargo/config.toml")) {
            if let Some(config) = Self::load_cargo_config_file_for_directory(&home) {
                if let Some(config) = Self::get_config_value(&key, &config) {
                    return Some(config);
                }
            }
        }
        return None;
    }

    /// Get the value of a given key from a given config
    /// Note: This is a naive implmenation that only supports strings
    fn get_config_value(key: &[&str], config: &toml::Value) -> Option<String> {
        let mut v = config;

        for k in key {
            let Some(val) = v.get(k) else {
                return None;
            };

            v = val;
        }

        return v.as_str().map(|s| s.to_string());
    }

    fn load_cargo_config_file_for_directory(dir: &Path) -> Option<toml::Value> {
        if let Ok(config_file) = std::fs::read_to_string(dir.join(".cargo/config.toml")) {
            let content = std::fs::read_to_string(config_file).ok()?;
            return toml::from_str(&content).ok();
        }
        return None;
    }
}
