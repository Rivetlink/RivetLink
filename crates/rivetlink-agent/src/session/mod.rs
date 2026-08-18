//! Host-side session handling: consent, key exchange, screen capture.

pub mod host;

pub(crate) use host::LocalScreenshotCapturer;
pub use host::{
    ConsentPolicy, ConsoleInputSink, ConsoleStateProvider, ScreenshotCapturer, ScreenshotHost,
};
