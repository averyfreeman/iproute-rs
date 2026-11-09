// SPDX-License-Identifier: MIT

//! Linux bridge-port, forwarding-database, and VLAN operations.
//!
//! The bridge command shares link indexes with ordinary route-netlink but
//! uses bridge-specific nested attributes for port state, FDB entries, and
//! VLAN membership.

mod cli;

pub(crate) use self::cli::BridgeCommand;
