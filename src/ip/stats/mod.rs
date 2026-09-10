// SPDX-License-Identifier: MIT

//! Interface statistics for `ip stats`.
//!
//! Linux exposes statistics through `RTM_GETSTATS`.  This module implements
//! the portable, commonly useful `link` group and keeps the response in a
//! stable structured shape.  The extended hardware/offload groups remain
//! separate because their kernel attributes are driver-specific; the existing
//! `ip link xstats` and `ip link afstats` commands cover the supported parts of
//! those groups.

use std::collections::HashMap;

use futures_util::stream::{StreamExt, TryStreamExt};
use iproute_rs::{CanDisplay, CanOutput, CliError};
use rtnetlink::{
    packet_core::{NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload},
    packet_route::{
        AddressFamily, RouteNetlinkMessage,
        link::Stats64,
        stats::{StatsAttribute, StatsFilterMask, StatsMessage},
    },
};
use serde::Serialize;

/// Top-level `ip stats` command.
pub(crate) struct StatsCommand;

impl StatsCommand {
    /// Canonical command name used by clap and the dispatcher.
    pub(crate) const CMD: &'static str = "stats";

    /// Build the supported statistics grammar.
    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("show interface statistics")
            .subcommand_required(false)
            .disable_help_subcommand(true)
            .subcommand(
                clap::Command::new("show")
                    .about("show interface statistics")
                    .alias("list")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("set")
                    .about("toggle hardware statistics collection")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(clap::Command::new("help").about("show stats help"))
    }

    /// Execute the selected statistics operation.
    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<StatsOutput, CliError> {
        let (operation, child) =
            matches.subcommand().unwrap_or(("show", matches));
        match operation {
            "show" | "list" => {
                let options = child
                    .get_many::<String>("options")
                    .unwrap_or_default()
                    .cloned()
                    .collect::<Vec<_>>();
                handle_show(&options).await
            }
            "set" => Err(CliError::from(
                "ip stats set is not implemented yet; use ip link xstats or ip link afstats for supported read-only groups",
            )),
            "help" => Ok(StatsOutput::Help(STATS_HELP.to_owned())),
            other => Err(format!("unknown ip stats operation: {other}").into()),
        }
    }
}

/// Output returned by `ip stats`.
pub(crate) enum StatsOutput {
    /// Link-level counters returned by `RTM_GETSTATS`.
    Link(Vec<CliStatsInfo>),
    /// Human-readable command help.
    Help(String),
}

impl Serialize for StatsOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Link(values) => values.serialize(serializer),
            Self::Help(value) => value.serialize(serializer),
        }
    }
}

impl CanDisplay for StatsOutput {
    fn gen_string(&self) -> String {
        match self {
            Self::Link(values) => values.gen_string(),
            Self::Help(value) => value.clone(),
        }
    }
}

impl CanOutput for StatsOutput {}

/// Structured representation of the link statistics group.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct CliStatsInfo {
    /// Linux interface index.
    pub(crate) ifindex: u32,
    /// Linux interface name.
    pub(crate) ifname: String,
    /// Statistics group name, currently always `link`.
    pub(crate) group: &'static str,
    /// Standard 64-bit receive/transmit counters.
    pub(crate) stats64: CliStats64,
}

/// JSON-friendly subset of `struct rtnl_link_stats64` used by iproute2.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct CliStats64 {
    /// Receive counters.
    pub(crate) rx: CliStatsRx,
    /// Transmit counters.
    pub(crate) tx: CliStatsTx,
}

/// Receive counters in the link statistics group.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct CliStatsRx {
    /// Bytes received.
    pub(crate) bytes: u64,
    /// Packets received.
    pub(crate) packets: u64,
    /// Receive errors.
    pub(crate) errors: u64,
    /// Packets dropped on receive.
    pub(crate) dropped: u64,
    /// Receiver ring-buffer overrun errors.
    pub(crate) over_errors: u64,
    /// Multicast packets received.
    pub(crate) multicast: u64,
}

/// Transmit counters in the link statistics group.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct CliStatsTx {
    /// Bytes transmitted.
    pub(crate) bytes: u64,
    /// Packets transmitted.
    pub(crate) packets: u64,
    /// Transmit errors.
    pub(crate) errors: u64,
    /// Packets dropped on transmit.
    pub(crate) dropped: u64,
    /// Carrier errors.
    pub(crate) carrier_errors: u64,
    /// Collisions detected.
    pub(crate) collisions: u64,
}

impl From<Stats64> for CliStats64 {
    fn from(value: Stats64) -> Self {
        Self {
            rx: CliStatsRx {
                bytes: value.rx_bytes,
                packets: value.rx_packets,
                errors: value.rx_errors,
                dropped: value.rx_dropped,
                over_errors: value.rx_over_errors,
                multicast: value.multicast,
            },
            tx: CliStatsTx {
                bytes: value.tx_bytes,
                packets: value.tx_packets,
                errors: value.tx_errors,
                dropped: value.tx_dropped,
                carrier_errors: value.tx_carrier_errors,
                collisions: value.collisions,
            },
        }
    }
}

impl std::fmt::Display for CliStatsInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rx = &self.stats64.rx;
        let tx = &self.stats64.tx;
        writeln!(f, "{}: {}: group link", self.ifindex, self.ifname)?;
        writeln!(f, "    RX:  bytes packets errors dropped  missed   mcast")?;
        writeln!(
            f,
            "    {:>10} {:>8} {:>6} {:>7} {:>7} {:>7}",
            rx.bytes,
            rx.packets,
            rx.errors,
            rx.dropped,
            rx.over_errors,
            rx.multicast
        )?;
        writeln!(f, "    TX:  bytes packets errors dropped carrier  collsns")?;
        write!(
            f,
            "    {:>10} {:>8} {:>6} {:>7} {:>7} {:>7}",
            tx.bytes,
            tx.packets,
            tx.errors,
            tx.dropped,
            tx.carrier_errors,
            tx.collisions
        )
    }
}

impl CanDisplay for CliStatsInfo {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliStatsInfo {}

#[derive(Default)]
struct StatsConfig {
    device: Option<String>,
    group: Option<String>,
    subgroup: Option<String>,
    suite: Option<String>,
}

fn parse_show_args(args: &[String]) -> Result<StatsConfig, CliError> {
    let mut config = StatsConfig::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let value = |name: &str, iter: &mut std::slice::Iter<'_, String>| {
            iter.next().cloned().ok_or_else(|| {
                CliError::from(format!("stats: {name} requires a value"))
            })
        };
        match arg.as_str() {
            "dev" => config.device = Some(value("dev", &mut iter)?),
            "group" => config.group = Some(value("group", &mut iter)?),
            "subgroup" => config.subgroup = Some(value("subgroup", &mut iter)?),
            "suite" => config.suite = Some(value("suite", &mut iter)?),
            "help" => return Ok(StatsConfig::default()),
            unknown => {
                return Err(format!(
                    "stats: unknown show argument `{unknown}`"
                )
                .into());
            }
        }
    }
    Ok(config)
}

async fn handle_show(args: &[String]) -> Result<StatsOutput, CliError> {
    let config = parse_show_args(args)?;
    let group = config.group.as_deref().unwrap_or("link");
    if group != "link" {
        return Err(format!(
            "stats group `{group}` is not implemented by ip-rs yet; link statistics are supported, while extended groups remain available through `ip link xstats` and `ip link afstats`"
        )
        .into());
    }
    if config.subgroup.is_some() || config.suite.is_some() {
        return Err("stats group link does not accept subgroup or suite".into());
    }

    let (connection, mut handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut ifindex_map = HashMap::new();
    let mut links = handle.link().get().execute();
    while let Some(link) = links.try_next().await? {
        if let Some(name) = link.attributes.iter().find_map(|attribute| {
            if let rtnetlink::packet_route::link::LinkAttribute::IfName(name) =
                attribute
            {
                Some(name.clone())
            } else {
                None
            }
        }) {
            ifindex_map.insert(link.header.index, name);
        }
    }

    let filter_index = if let Some(device) = config.device.as_deref() {
        Some(
            ifindex_map
                .iter()
                .find_map(|(index, name)| (name == device).then_some(*index))
                .ok_or_else(|| {
                    CliError::from(format!("Device `{device}` does not exist"))
                })?,
        )
    } else {
        None
    };

    let mut stats = StatsMessage::default();
    stats.header.family = AddressFamily::Unspec;
    stats.header.ifindex = filter_index.unwrap_or(0);
    stats.header.filter_mask = StatsFilterMask::Link64;
    let mut request =
        NetlinkMessage::from(RouteNetlinkMessage::GetStats(stats));
    request.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut response = handle.request(request).map_err(|error| {
        CliError::from(format!("stats request failed: {error}"))
    })?;
    let mut values = Vec::new();
    while let Some(message) = response.next().await {
        match message.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewStats(
                stats,
            )) => {
                if filter_index
                    .is_some_and(|index| stats.header.ifindex != index)
                {
                    continue;
                }
                let Some(stats64) =
                    stats.attributes.into_iter().find_map(|attribute| {
                        if let StatsAttribute::Link64(value) = attribute {
                            Some(value)
                        } else {
                            None
                        }
                    })
                else {
                    continue;
                };
                values.push(CliStatsInfo {
                    ifindex: stats.header.ifindex,
                    ifname: ifindex_map
                        .get(&stats.header.ifindex)
                        .cloned()
                        .unwrap_or_else(|| "<unknown>".to_owned()),
                    group: "link",
                    stats64: stats64.into(),
                });
            }
            NetlinkPayload::Error(error) => {
                return Err(format!("stats netlink error: {error}").into());
            }
            NetlinkPayload::Done(_) => break,
            _ => {}
        }
    }
    Ok(StatsOutput::Link(values))
}

const STATS_HELP: &str = "Usage: ip stats show [ dev DEV ] [ group link ]\n";
