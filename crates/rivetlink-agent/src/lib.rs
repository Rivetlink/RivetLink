//! RivetLink Host Agent library.
//!
//! Runs on the controlled machine. Authenticates to the relay server, listens
//! for incoming session requests, and (eventually) coordinates screen capture
//! and input injection for each session.

pub mod capture;
pub mod cli;
pub mod config;
pub mod error;
pub mod input;
pub mod keystore;
pub mod lan;
pub mod registration;
pub mod relay;
pub mod runner;
pub mod session;
pub mod trusted;
