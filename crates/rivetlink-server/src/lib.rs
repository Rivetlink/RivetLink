//! RivetLink WebRTC signaling server.
//!
//! Core HTTP and WebSocket server for managing P2P device connections, authentication, and real-time signaling.
//! Provides REST endpoints for user/device management and WebSocket gateway for P2P negotiation.

pub mod auth;
pub mod cli;
pub mod config;
pub mod db;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod redis;
pub mod router;
pub mod sessions;
pub mod signaling;
pub mod state;
pub mod websocket;
