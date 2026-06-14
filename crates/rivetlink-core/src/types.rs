//! Core domain types: strongly-typed UUIDv7 identifiers, session roles, and connection modes.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Generates a newtype wrapper around [`Uuid`] with `new()`, `Default`, `Display`,
/// and full serde/hash support. All IDs use UUIDv7 for time-ordered uniqueness.
macro_rules! define_id {
    ($(#[doc = $doc:expr])* $name:ident) => {
        $(#[doc = $doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(pub Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

define_id!(
    /// Unique identifier for a remote-controlled host device.
    DeviceId
);
define_id!(
    /// Unique identifier for a remote session between client and host.
    SessionId
);
define_id!(
    /// Unique identifier for a support user / operator.
    UserId
);
define_id!(
    /// Unique identifier for a tenant organization.
    OrganizationId
);

/// Role a participant holds within a remote session.
/// Only one controller is allowed at a time; viewers are read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRole {
    Viewer,
    Controller,
    Admin,
}

/// How the client and host device are connected for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    DirectLan,
    DirectP2p,
    Relay,
}
