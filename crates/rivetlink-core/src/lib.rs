//! Core types and error definitions shared across all RivetLink crates.
//!
//! This crate provides the foundational ID types ([`DeviceId`], [`SessionId`], [`UserId`],
//! [`OrganizationId`]), session roles, and connection mode enums used throughout the platform.

pub mod error;
pub mod secure_file;
pub mod types;

pub use error::{Error, Result};
pub use types::*;
