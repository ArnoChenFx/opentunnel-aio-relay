//! Wire protocol types for the OpenTunnel bridge and HTTP API.
//!
//! Copied from the `opentunnel` crate in anomalyco/opentunnel (MIT licensed)
//! so this server speaks exactly the same protocol as the official clients.
//! `docs/protocol.md` in that repository is the source of truth.

pub mod api;
pub mod bridge;
pub mod names;
