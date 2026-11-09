// SPDX-License-Identifier: MIT

//! Interface-address listing, filtering, mutation, and dump handling.

mod add;
mod cli;
mod save;
mod show;

pub(crate) use self::{cli::AddressCommand, show::CliAddressInfo};
