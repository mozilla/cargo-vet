//! Types for abstracting over communicating with the user, with support for
//! mocking in tests.
//!
//! In general, this type should be preferred over directly writing to stdout or
//! stderr.

use crate::editor::Editor;
use console::{Style, Term};
use std::{fs::File, io};

/// Object-safe extension of `std::io::Write` with extra features for
/// interacting with the terminal. Can be mocked in tests to allow them to test
/// other features.
pub trait Out: io::Write {
    /// Check if this output is a real terminal.
    fn is_term(&self) -> bool {
        false
    }

    /// If the user is interacting through a terminal, clear the screen.
    /// Should fail silently if the screen cannot be cleared.
    fn clear_screen(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Ask the user a question, and read in a line with the user's response. If
    /// there's no user able to respond, `None` will be returned instead.
    fn read_line_with_prompt(&mut self, _prompt: &str) -> io::Result<String> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Get a `Style` object which can be used to style text written to this
    /// user. Defaults to a disabled style object.
    fn style(&self) -> Style {
        Style::new().force_styling(false)
    }

    /// Create an editor to prompt the user with.
    /// Exists primarily to allow tests to mock out this feature, and block
    /// editor usage when using a file output.
    fn editor<'a>(&'a mut self, _name: &'a str) -> io::Result<Editor<'a>> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

// "Real" user-facing terminal on stdout
impl Out for Term {
    fn is_term(&self) -> bool {
        self.is_term()
    }

    fn clear_screen(&mut self) -> io::Result<()> {
        (&*self).clear_screen()
    }

    fn read_line_with_prompt(&mut self, prompt: &str) -> io::Result<String> {
        self.write_str(prompt)?;
        self.flush()?;
        (&*self).read_line()
    }

    fn style(&self) -> Style {
        self.style()
    }

    fn editor(&mut self, name: &str) -> io::Result<Editor<'_>> {
        Editor::new(name)
    }
}

// File based output with no special features.
impl Out for File {}
