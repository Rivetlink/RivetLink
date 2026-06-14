//! Wire protocol definitions for RivetLink remote input streaming.
//!
//! This module defines the serializable packet structures used for communicating
//! signaling and input events over the network.

pub mod packets;

pub use packets::*;
