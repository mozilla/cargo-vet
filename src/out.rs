//! Types for abstracting over communicating with the user, with support for
//! mocking in tests.
//!
//! In general, this type should be preferred over directly writing to stdout or
//! stderr.

use crate::git_tool::Editor;
use console::{Style, Term};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use lazy_static::lazy_static;
use std::{borrow::Cow, fmt, fs::File, io, mem, time::Duration};

/// Object-safe extension of `std::io::Write` with extra features for
/// interacting with the terminal. Can be mocked in tests to allow them to test
/// other features.
pub trait Out: Send + Sync + 'static {
    /// Write to the output.
    fn write(&self, buf: &[u8]) -> io::Result<usize>;

    /// Write to the output
    fn write_fmt(&self, args: fmt::Arguments<'_>) {
        struct AsWrite<'a, T: ?Sized>(&'a T);
        impl<T: ?Sized + Out> io::Write for AsWrite<'_, T> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Out::write(self.0, buf)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        io::Write::write_fmt(&mut AsWrite(self), args).unwrap();
    }

    /// Check if this output is a real terminal.
    fn is_term(&self) -> bool {
        false
    }

    /// If the user is interacting through a terminal, clear the screen.
    /// Should fail silently if the screen cannot be cleared.
    fn clear_screen(&self) -> io::Result<()> {
        Ok(())
    }

    /// Ask the user a question, and read in a line with the user's response. If
    /// there's no user able to respond, an error will be returned instead.
    fn read_line_with_prompt(&self, _prompt: &str) -> io::Result<String> {
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
    fn editor<'a>(&'a self, _name: &'a str) -> io::Result<Editor<'a>> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

// "Real" user-facing terminal on stdout
impl Out for Term {
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        // XXX: Consider suspending the MultiProgress when writing if we ever
        // want to write to `Out` while a progress bar is rendering.
        io::Write::write(&mut &*self, buf)
    }

    fn is_term(&self) -> bool {
        self.is_term()
    }

    fn clear_screen(&self) -> io::Result<()> {
        self.clear_screen()
    }

    fn read_line_with_prompt(&self, prompt: &str) -> io::Result<String> {
        self.write_str(prompt)?;
        self.flush()?;
        self.read_line()
    }

    fn style(&self) -> Style {
        self.style()
    }

    fn editor(&self, name: &str) -> io::Result<Editor<'_>> {
        Editor::new(name)
    }
}

// File based output with no special features.
impl Out for File {
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut &*self, buf)
    }
}

impl io::Write for &'_ dyn Out {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Out::write(*self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

lazy_static! {
    /// The global `MultiProgress` which can be used to write out progress reports.
    ///
    /// By default, this is invisible so that it isn't shown during tests, but
    /// it will be configured to be visible early during main.
    pub static ref MULTIPROGRESS: MultiProgress =
        MultiProgress::with_draw_target(ProgressDrawTarget::hidden());
}

/// Helper for bracketing some region with an indeterminate spinner which shows
/// no meaningful progress.
pub fn indeterminate_spinner(
    prefix: impl Into<Cow<'static, str>>,
    message: impl Into<Cow<'static, str>>,
) -> ProgressBar {
    let progress_bar = MULTIPROGRESS.add(
        ProgressBar::new_spinner()
            .with_style(
                ProgressStyle::with_template("{prefix:>12.cyan.bold} {msg} {spinner}").unwrap(),
            )
            .with_prefix(prefix)
            .with_message(message),
    );
    progress_bar.enable_steady_tick(Duration::from_millis(100));
    progress_bar
}

/// Create a new progress bar with a cargo-inspired style.
pub fn progress_bar(
    prefix: impl Into<Cow<'static, str>>,
    message: impl Into<Cow<'static, str>>,
    len: u64,
) -> ProgressBar {
    let progress_bar = MULTIPROGRESS.add(
        ProgressBar::new(len)
            .with_style(
                ProgressStyle::with_template("{prefix:>12.cyan.bold} {msg} [{bar:57}] {pos}/{len}")
                    .unwrap()
                    .progress_chars("=> "),
            )
            .with_prefix(prefix)
            .with_message(message),
    );
    progress_bar.tick();
    progress_bar
}

/// Helper guard object to increment progress for the given progress bar by the
/// given amount when this object is destroyed.
pub struct IncProgressOnDrop<'a>(pub &'a ProgressBar, pub u64);
impl Drop for IncProgressOnDrop<'_> {
    fn drop(&mut self) {
        self.0.inc(self.1);
    }
}

/// A helper type which implements `io::Write`, and will buffer up input, then
/// suspend the MultiProgress and write it all out when dropped to avoid
/// tearing.
///
/// This is used for tracing logs when no log file is specified.
pub struct StderrLogWriter {
    buffer: Vec<u8>,
}

impl StderrLogWriter {
    pub fn new() -> Self {
        StderrLogWriter { buffer: Vec::new() }
    }
}

impl io::Write for StderrLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.buffer, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let buffer = mem::take(&mut self.buffer);
        MULTIPROGRESS.suspend(|| io::stderr().write_all(&buffer))
    }
}

impl Drop for StderrLogWriter {
    fn drop(&mut self) {
        let _ = io::Write::flush(self);
    }
}
