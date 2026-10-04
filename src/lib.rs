// SPDX-License-Identifier: MIT

//! Rust implementation building blocks for the Linux `ip` command.
//!
//! The binary in this package translates compatibility-oriented command-line
//! arguments into Linux route-netlink requests through [`rtnetlink`].  Output
//! models implement the small [`CanDisplay`] and [`CanOutput`] traits used by
//! the standalone formatter.  The implementation is Linux-first: kernel
//! capabilities, loaded link modules, and the active network namespace remain
//! part of the runtime contract.

mod color;
mod error;
mod mac;
mod result;

/// Exposes the public `item` value.
pub use self::{
    color::CliColor,
    error::CliError,
    mac::{mac_to_string, parse_mac_str},
    result::{CanDisplay, CanOutput, OutputFormat, print_result_and_exit},
};
