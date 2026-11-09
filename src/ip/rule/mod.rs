// SPDX-License-Identifier: MIT

//! Policy-routing rule support for [`ip rule`](https://man7.org/linux/man-pages/man8/ip-rule.8.html).
//!
//! The kernel represents rules as route-netlink messages.  This module keeps
//! the command-line compatibility layer deliberately thin: parsing is done
//! into a small rule specification, the spec is converted to the typed
//! `rtnetlink`/`netlink-packet-route` message, and dumps are mapped into
//! stable, serializable records for both the human CLI and the Nu adapter.

mod cli;

pub(crate) use self::cli::RuleCommand;
