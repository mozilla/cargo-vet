//! Helper utilities for opening files in the editor.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::str;

use tempfile::NamedTempFile;
use tracing::warn;

use crate::VetError;

#[cfg(windows)]
fn git_sh_path() -> Option<PathBuf> {
    // Locate the `git` binary using the windows `where` command.
    let output = Command::new("where").arg("git").output().ok()?;
    if !output.status.success() {
        return None;
    }

    // The git binary path should be either in the `cmd` or `bin` subdirectory
    // of the git-for-windows install path, while the `sh.exe` binary is located
    // in the `bin` subdirectory.
    Path::new(str::from_utf8(&output.stdout).ok()?.trim())
        .canonicalize()
        .ok()?
        .parent()?
        .parent()?
        .join(r"bin\sh.exe")
        .canonicalize()
        .ok()
}

#[cfg(not(windows))]
fn git_sh_path() -> Option<PathBuf> {
    Some("/bin/sh".into())
}

/// Read the git configuration to determine the value for GIT_EDITOR.
fn git_editor() -> Option<String> {
    // Testing environment variable to force using the fallback editor instead
    // of GIT_EDITOR.
    if std::env::var("CARGO_VET_USE_FALLBACK_EDITOR").unwrap_or_default() == "1" {
        return None;
    }

    let output = Command::new("git")
        .arg("var")
        .arg("GIT_EDITOR")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(str::from_utf8(&output.stdout).ok()?.trim().to_owned())
}

#[cfg(windows)]
const FALLBACK_EDITOR: &str = "notepad.exe";

// NOTE: This is probably not as reliably available as `vi`, but is easier to
// quit from for users who aren't familiar with vi.
#[cfg(not(windows))]
const FALLBACK_EDITOR: &str = "nano";

/// Get a Command which can be used to invoke the user's EDITOR to edit a
/// document when passed an argument. This will try to use the user's configured
/// GIT_EDITOR when possible.
pub fn editor_command() -> Command {
    // Try to use the user's configured editor if we're able to locate their git
    // install. If this fails, invoke the default editor instead.
    //
    // XXX: If we end up with commands which invoke the editor many times, it
    // may eventually be worth adding some form of caching here.
    match (git_sh_path(), git_editor()) {
        (Some(git_sh), Some(git_editor)) => {
            let mut cmd = Command::new(git_sh);
            cmd.arg("-c")
                .arg(format!("{} \"$@\"", git_editor))
                .arg(git_editor);
            return cmd;
        }
        (_, None) => {
            warn!("Unable to determine user's GIT_EDITOR");
        }
        (None, Some(_)) => {
            warn!("Unable to locate user's git install to invoke GIT_EDITOR");
        }
    }
    warn!("Falling back to running '{}' directly", FALLBACK_EDITOR);
    Command::new(FALLBACK_EDITOR)
}

/// Run the default editor configured through git (GIT_EDITOR) and use it to
/// edit the given file path.
pub fn run_editor(path: &Path) -> io::Result<ExitStatus> {
    editor_command().arg(path).status()
}

// On windows some editors (notably notepad pre-windows 11) don't handle
// unix line endings very well, so make sure to give them windows line
// endings.
#[cfg(windows)]
const LINE_ENDING: &str = "\r\n";

#[cfg(not(windows))]
const LINE_ENDING: &str = "\n";

pub struct Editor {
    tempfile: NamedTempFile,
}

impl Editor {
    /// Create a new editor for a temporary file.
    pub fn new(name: &str) -> Result<Self, VetError> {
        let tempfile = tempfile::Builder::new().prefix(name).tempfile()?;
        Ok(Editor { tempfile })
    }

    /// Add comment lines to the editor. Any newlines in the input will be
    /// normalized to the current platform, and a comment character will be
    /// added.
    pub fn add_comments(&mut self, text: &str) -> io::Result<()> {
        let text = text.trim();
        if text.is_empty() {
            write!(self.tempfile, "#{}", LINE_ENDING)?;
        }
        for line in text.lines() {
            if line.is_empty() {
                write!(self.tempfile, "#{}", LINE_ENDING)?;
            } else {
                write!(self.tempfile, "# {}{}", line, LINE_ENDING)?;
            }
        }
        Ok(())
    }

    /// Add non-comment lines to the editor. These lines must not start with a
    /// `#` character.
    pub fn add_text(&mut self, text: &str) -> io::Result<()> {
        let text = text.trim();
        if text.is_empty() {
            write!(self.tempfile, "{}", LINE_ENDING)?;
        }
        for line in text.lines() {
            // FIXME: Git has multiple comment character modes, including
            // buffering the entire payload to pick a comment character not in
            // the text, and respecting the user's core.commentChar config.
            assert!(
                !line.starts_with('#'),
                "Non-comment lines cannot start with a '#' comment character"
            );
            write!(self.tempfile, "{}{}", line, LINE_ENDING)?;
        }
        Ok(())
    }

    /// Run the editor, collecting and filtering the resulting file, and
    /// returning it as a string.
    pub fn edit(self) -> Result<String, VetError> {
        // Close our handle on the file to allow other programs like the editor
        // to modify it on Windows.
        let path = self.tempfile.into_temp_path();
        run_editor(&path)?;

        // Read in the result, filtering lines, and restoring unix line endings.
        let mut result = String::new();
        let file = BufReader::new(File::open(&path)?);
        for line in file.lines() {
            let line = line?;
            if line.starts_with('#') {
                continue;
            }
            result.push_str(line.trim());
            result.push('\n');
        }

        // Trim off excess whitespace.
        Ok(result.trim().to_owned())
    }
}
