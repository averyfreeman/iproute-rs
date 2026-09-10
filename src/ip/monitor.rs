// SPDX-License-Identifier: MIT

//! Netlink event monitor for the `ip monitor` command.
//!
//! The route-netlink crate already exposes the same multicast socket
//! primitive used by iproute2.  This module keeps event decoding deliberately
//! lossless: callers receive the parsed `RouteNetlinkMessage` debug form, so
//! newer kernel attributes remain visible even before a dedicated structured
//! formatter is added.

use futures_util::StreamExt;
use iproute_rs::CliError;
use rtnetlink::{MulticastGroup, new_multicast_connection};

/// Top-level `ip monitor` command.
pub(crate) struct MonitorCommand;

impl MonitorCommand {
    /// Canonical command name used by clap and the dispatcher.
    pub(crate) const CMD: &'static str = "monitor";

    /// Build the monitor grammar.  Object names are intentionally trailing
    /// arguments because iproute2 accepts several objects in one invocation.
    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("watch for netlink network configuration events")
            .alias("mon")
            .arg(
                clap::Arg::new("options")
                    .action(clap::ArgAction::Append)
                    .trailing_var_arg(true),
            )
    }

    /// Subscribe to the requested multicast groups and print each event.
    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<Vec<String>, CliError> {
        let options = matches
            .get_many::<String>("options")
            .unwrap_or_default()
            .map(String::as_str)
            .collect::<Vec<_>>();
        run_monitor(&options).await
    }
}

fn monitor_groups(options: &[&str]) -> Result<Vec<MulticastGroup>, CliError> {
    let all = [
        MulticastGroup::Link,
        MulticastGroup::Neigh,
        MulticastGroup::Ipv4Ifaddr,
        MulticastGroup::Ipv6Ifaddr,
        MulticastGroup::Ipv4Route,
        MulticastGroup::Ipv6Route,
        MulticastGroup::Ipv4Rule,
        MulticastGroup::Ipv6Rule,
    ];
    let mut groups = Vec::new();
    let mut add = |group| {
        if !groups.contains(&group) {
            groups.push(group);
        }
    };

    if options.is_empty() {
        for group in all {
            add(group);
        }
        return Ok(groups);
    }

    for option in options {
        match *option {
            "all" => {
                for group in all {
                    add(group);
                }
            }
            "link" => add(MulticastGroup::Link),
            "neigh" | "neighbor" | "neighbour" => add(MulticastGroup::Neigh),
            "address" | "addr" => {
                add(MulticastGroup::Ipv4Ifaddr);
                add(MulticastGroup::Ipv6Ifaddr);
            }
            "route" => {
                add(MulticastGroup::Ipv4Route);
                add(MulticastGroup::Ipv6Route);
            }
            "rule" => {
                add(MulticastGroup::Ipv4Rule);
                add(MulticastGroup::Ipv6Rule);
            }
            "nsid" => add(MulticastGroup::Nsid),
            "stats" => add(MulticastGroup::Stats),
            "nexthop" => add(MulticastGroup::Nexthop),
            "bridge" | "brvlan" => add(MulticastGroup::Brvlan),
            "mroute" => {
                add(MulticastGroup::Ipv4Mroute);
                add(MulticastGroup::Ipv6Mroute);
            }
            "label" | "file" | "dev" => {
                return Err(CliError::from(format!(
                    "monitor option `{option}` needs a filter that is not yet supported"
                )));
            }
            other => {
                return Err(CliError::from(format!(
                    "unknown monitor object: {other}"
                )));
            }
        }
    }
    Ok(groups)
}

async fn run_monitor(options: &[&str]) -> Result<Vec<String>, CliError> {
    let groups = monitor_groups(options)?;
    let (connection, _handle, mut messages) =
        new_multicast_connection(&groups)?;
    tokio::spawn(connection);

    while let Some((message, _address)) = messages.next().await {
        if let rtnetlink::packet_core::NetlinkPayload::InnerMessage(payload) =
            message.payload
        {
            println!("{payload:?}");
        } else {
            println!("{message:?}");
        }
    }
    Ok(vec![])
}
