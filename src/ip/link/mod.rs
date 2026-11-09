// SPDX-License-Identifier: MIT

//! Network-link inventory, mutation, per-type attributes, statistics, and XDP.

mod add;
mod afstats;
mod cli;
mod delete;
mod detail;
pub(crate) mod flags;
mod ifaces;
mod link_info;
mod property;
mod set;
mod show;
mod xdp;
mod xstats;

pub(crate) use self::{
    add::LinkBaseConf,
    cli::LinkCommand,
    show::{CliLinkInfo, handle_show},
};
