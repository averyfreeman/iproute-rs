// SPDX-License-Identifier: MIT

//! IPv4/IPv6 route, multipath, policy-selector, and table operations.

mod add;
mod cli;
mod delete;
mod flush;
mod get;
mod modify;
mod save;
mod show;

pub(crate) use self::cli::RouteCommand;
