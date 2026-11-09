// SPDX-License-Identifier: MIT

//! ARP and IPv6 neighbour-table operations for `ip neighbour`.

mod cli;
mod modify;
mod show;

pub(crate) use self::cli::NeighbourCommand;
pub(crate) use self::show::resolve_link_index;
