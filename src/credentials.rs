//! Git credential helper integration
//!
//! This module provides integration with git credential helpers as documented in
//! https://git-scm.com/docs/git-credential and https://git-scm.com/docs/api-credentials
//!
//! It supports both traditional username/password authentication and the newer
//! authtype/credential format for more advanced authentication schemes.

use reqwest::Url;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tracing::debug;

/// Represents credential information returned by git credential helper
#[derive(Debug, Clone)]
pub enum GitCredential {
    /// Username and password for basic authentication
    UsernamePassword { username: String, password: String },
    /// Pre-formatted credential with authentication type
    Formatted {
        auth_type: String,
        credential: String,
    },
}

impl GitCredential {
    /// Apply the credential to a reqwest RequestBuilder
    pub fn apply_to_request(
        self,
        request_builder: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        match self {
            GitCredential::UsernamePassword { username, password } => {
                request_builder.basic_auth(username, Some(password))
            }
            GitCredential::Formatted {
                auth_type,
                credential,
            } => request_builder.header("Authorization", format!("{} {}", auth_type, credential)),
        }
    }
}

/// Execute git credential fill for the given input
///
/// This function is separated to allow for easier testing by mocking the git call.
async fn execute_git_credential_fill(
    credential_input: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // Execute git credential fill
    let mut child = tokio::process::Command::new("git")
        .args(&["credential", "fill"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Write the credential input
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(credential_input.as_bytes()).await?;
        stdin.shutdown().await?;
    }

    // Wait for the command to complete
    let output = child.wait_with_output().await?;

    if !output.status.success() {
        // If git credential helper fails, just return None (no credentials)
        return Ok(None);
    }

    Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
}

/// Create credential input string for git credential helper
fn create_git_credential_input(url: &Url) -> String {
    let mut credential_input = String::new();
    // For authtype to work we need to announce the capability
    credential_input.push_str("capability[]=authtype\n");

    credential_input.push_str(&format!("protocol={}\n", url.scheme()));
    if let Some(host) = url.host_str() {
        let host_with_port = if let Some(port) = url.port() {
            format!("{}:{}", host, port)
        } else {
            host.to_string()
        };
        credential_input.push_str(&format!("host={}\n", host_with_port));
    }
    if !url.path().is_empty() && url.path() != "/" {
        credential_input.push_str(&format!("path={}\n", url.path().trim_start_matches('/')));
    }
    credential_input.push('\n'); // Blank line to terminate input
    credential_input
}

/// Parse git credential output into a GitCredential
fn parse_git_credential_output(output: &str) -> Option<GitCredential> {
    let mut username = None;
    let mut password = None;
    let mut authtype = None;
    let mut credential = None;

    for line in output.lines() {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "username" => username = Some(value.to_string()),
                "password" => password = Some(value.to_string()),
                "authtype" => authtype = Some(value.to_string()),
                "credential" => credential = Some(value.to_string()),
                _ => {} // Ignore unknown fields
            }
        }
    }

    // Return strongly typed credentials
    if let (Some(authtype_str), Some(credential_str)) = (authtype, credential) {
        // Use the new authtype/credential format
        Some(GitCredential::Formatted {
            auth_type: authtype_str,
            credential: credential_str,
        })
    } else if let (Some(username), Some(password)) = (username, password) {
        // Use username and password for basic auth
        Some(GitCredential::UsernamePassword { username, password })
    } else {
        None
    }
}

/// Get credentials for a URL using git credential helper
pub async fn get_credentials_from_git(
    url: &Url,
) -> Result<Option<GitCredential>, Box<dyn std::error::Error>> {
    debug!("Getting credentials for URL: {}", url);

    // Prepare the credential input
    let credential_input = create_git_credential_input(url);
    debug!("Credential input:\n{:?}", credential_input);

    // Execute git credential fill
    let credential_output = execute_git_credential_fill(&credential_input).await?;
    debug!("Credential output:\n{:?}", credential_output);

    // Parse the output if we got one
    let output = match credential_output {
        Some(output_str) => Ok(parse_git_credential_output(&output_str)),
        None => Ok(None),
    };

    debug!("Parsed credentials: {:?}", output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_git_credential_output_username_password() {
        let output = "protocol=https\nhost=example.com\nusername=testuser\npassword=testpass\n\n";
        let result = parse_git_credential_output(output);

        match result {
            Some(GitCredential::UsernamePassword { username, password }) => {
                assert_eq!(username, "testuser");
                assert_eq!(password, "testpass");
            }
            _ => panic!("Expected UsernamePassword credential"),
        }
    }

    #[test]
    fn test_parse_git_credential_output_formatted() {
        let output = "capability[]=authtype\nprotocol=https\nhost=example.com\nauthtype=Bearer\ncredential=token123\n\n";
        let result = parse_git_credential_output(output);

        match result {
            Some(GitCredential::Formatted {
                auth_type,
                credential,
            }) => {
                assert_eq!(auth_type, "Bearer");
                assert_eq!(credential, "token123");
            }
            _ => panic!("Expected Formatted credential"),
        }
    }

    #[test]
    fn test_parse_git_credential_output_custom_authtype() {
        let output =
            "capability[]=authtype\nprotocol=https\nhost=example.com\nauthtype=CustomAuth\ncredential=custom123\n\n";
        let result = parse_git_credential_output(output);

        match result {
            Some(GitCredential::Formatted {
                auth_type,
                credential,
            }) => {
                assert_eq!(auth_type, "CustomAuth");
                assert_eq!(credential, "custom123");
            }
            _ => panic!("Expected Formatted credential with custom auth type"),
        }
    }

    #[test]
    fn test_parse_git_credential_output_empty() {
        let output = "";
        let result = parse_git_credential_output(output);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_git_credential_output_incomplete() {
        let output = "protocol=https\nhost=example.com\nusername=testuser\n\n";
        let result = parse_git_credential_output(output);
        assert!(result.is_none());
    }

    #[test]
    fn test_create_git_credential_input_basic() {
        let url = Url::parse("https://example.com/").unwrap();
        let input = create_git_credential_input(&url);
        assert_eq!(
            input,
            "capability[]=authtype\nprotocol=https\nhost=example.com\n\n"
        );
    }

    #[test]
    fn test_create_git_credential_input_with_port() {
        let url = Url::parse("https://example.com:8080/").unwrap();
        let input = create_git_credential_input(&url);
        assert_eq!(
            input,
            "capability[]=authtype\nprotocol=https\nhost=example.com:8080\n\n"
        );
    }

    #[test]
    fn test_create_git_credential_input_with_path() {
        let url = Url::parse("https://example.com/path/to/resource").unwrap();
        let input = create_git_credential_input(&url);
        assert_eq!(
            input,
            "capability[]=authtype\nprotocol=https\nhost=example.com\npath=path/to/resource\n\n"
        );
    }

    #[test]
    fn test_create_git_credential_input_with_port_and_path() {
        let url = Url::parse("https://example.com:8080/path/to/resource").unwrap();
        let input = create_git_credential_input(&url);
        assert_eq!(
            input,
            "capability[]=authtype\nprotocol=https\nhost=example.com:8080\npath=path/to/resource\n\n"
        );
    }

    #[test]
    fn test_create_git_credential_input_http() {
        let url = Url::parse("http://example.com/path").unwrap();
        let input = create_git_credential_input(&url);
        assert_eq!(
            input,
            "capability[]=authtype\nprotocol=http\nhost=example.com\npath=path\n\n"
        );
    }
}
