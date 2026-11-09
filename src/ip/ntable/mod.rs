// SPDX-License-Identifier: MIT

//! Neighbour-table inspection for `ip ntable`.
//!
//! Neighbour-table messages are part of the route-netlink protocol but are
//! not currently wrapped by a high-level `rtnetlink` request builder.  The
//! implementation therefore uses the crate's public raw request boundary and
//! still keeps decoding strongly typed through `netlink-packet-route`.

use std::collections::BTreeMap;

use futures_util::StreamExt;
use iproute_rs::{CanDisplay, CanOutput, CliError};
use rtnetlink::packet_core::{
    NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
};
use rtnetlink::packet_route::{
    AddressFamily, RouteNetlinkMessage,
    neighbour_table::{
        NeighbourTableAttribute, NeighbourTableConfig, NeighbourTableMessage,
        NeighbourTableParameter, NeighbourTableStats,
    },
};
use serde::Serialize;

use crate::neighbour::resolve_link_index;

/// Top-level `ip ntable` command.
pub(crate) struct NTableCommand;

impl NTableCommand {
    /// Canonical command name used by clap and the dispatcher.
    pub(crate) const CMD: &'static str = "ntable";

    /// Build the supported neighbour-table grammar.
    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("neighbour table configuration")
            .alias("neigh-table")
            .subcommand_required(false)
            .disable_help_subcommand(true)
            .subcommand(
                clap::Command::new("show")
                    .about("show neighbour table parameters")
                    .alias("list")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(clap::Command::new("help").about("show ntable help"))
    }

    /// Execute `show`, optionally restricting the family, table name, or
    /// interface supplied in the trailing compatibility arguments.
    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
        preferred_family: Option<AddressFamily>,
    ) -> Result<Vec<CliNeighbourTableInfo>, CliError> {
        let (operation, child) =
            matches.subcommand().unwrap_or(("show", matches));
        if operation == "help" {
            return Ok(vec![CliNeighbourTableInfo::help()]);
        }
        if operation != "show" && operation != "list" {
            return Err(
                format!("unknown ip ntable operation: {operation}").into()
            );
        }

        let options = child
            .get_many::<String>("options")
            .unwrap_or_default()
            .map(String::as_str)
            .collect::<Vec<_>>();
        handle_show(&options, preferred_family).await
    }
}

/// Stable structured view of one kernel neighbour table.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct CliNeighbourTableInfo {
    family: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threshold1: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threshold2: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threshold3: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gc_interval: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<NeighbourTableConfigInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<NeighbourTableStatsInfo>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    parameters: BTreeMap<String, u64>,
    #[serde(skip)]
    help: Option<String>,
}

impl CliNeighbourTableInfo {
    fn help() -> Self {
        Self {
            family: String::new(),
            name: None,
            threshold1: None,
            threshold2: None,
            threshold3: None,
            gc_interval: None,
            config: None,
            stats: None,
            parameters: BTreeMap::new(),
            help: Some(NTABLE_HELP.to_owned()),
        }
    }

    fn from_message(message: NeighbourTableMessage) -> Self {
        let mut info = Self {
            family: message.header.family.to_string(),
            name: None,
            threshold1: None,
            threshold2: None,
            threshold3: None,
            gc_interval: None,
            config: None,
            stats: None,
            parameters: BTreeMap::new(),
            help: None,
        };
        for attribute in message.attributes {
            match attribute {
                NeighbourTableAttribute::Name(value) => info.name = Some(value),
                NeighbourTableAttribute::Threshold1(value) => {
                    info.threshold1 = Some(value);
                }
                NeighbourTableAttribute::Threshold2(value) => {
                    info.threshold2 = Some(value);
                }
                NeighbourTableAttribute::Threshold3(value) => {
                    info.threshold3 = Some(value);
                }
                NeighbourTableAttribute::GcInterval(value) => {
                    info.gc_interval = Some(value);
                }
                NeighbourTableAttribute::Config(value) => {
                    info.config = Some(value.into());
                }
                NeighbourTableAttribute::Stats(value) => {
                    info.stats = Some(value.into());
                }
                NeighbourTableAttribute::Parms(values) => {
                    for value in values {
                        if let Some((name, value)) = parameter_pair(value) {
                            info.parameters.insert(name.to_owned(), value);
                        }
                    }
                }
                NeighbourTableAttribute::Other(_) => {}
                _ => {}
            }
        }
        info
    }
}

impl std::fmt::Display for CliNeighbourTableInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(help) = &self.help {
            return f.write_str(help);
        }
        write!(f, "{}", self.family)?;
        if let Some(name) = &self.name {
            write!(f, " {name}")?;
        }
        if let Some(value) = self.threshold1 {
            write!(f, " threshold1 {value}")?;
        }
        if let Some(value) = self.threshold2 {
            write!(f, " threshold2 {value}")?;
        }
        if let Some(value) = self.threshold3 {
            write!(f, " threshold3 {value}")?;
        }
        if let Some(value) = self.gc_interval {
            write!(f, " gc_interval {value}")?;
        }
        for (name, value) in &self.parameters {
            write!(f, " {name} {value}")?;
        }
        Ok(())
    }
}

impl CanDisplay for CliNeighbourTableInfo {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliNeighbourTableInfo {}

/// The serializable subset of `struct ndt_config`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct NeighbourTableConfigInfo {
    key_len: u16,
    entry_size: u16,
    entries: u32,
    last_flush: u32,
    last_rand: u32,
    hash_rand: u32,
    hash_mask: u32,
    hash_chain_gc: u32,
    proxy_qlen: u32,
}

impl From<NeighbourTableConfig> for NeighbourTableConfigInfo {
    fn from(value: NeighbourTableConfig) -> Self {
        Self {
            key_len: value.key_len,
            entry_size: value.entry_size,
            entries: value.entries,
            last_flush: value.last_flush,
            last_rand: value.last_rand,
            hash_rand: value.hash_rand,
            hash_mask: value.hash_mask,
            hash_chain_gc: value.hash_chain_gc,
            proxy_qlen: value.proxy_qlen,
        }
    }
}

/// The serializable subset of `struct ndt_stats`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct NeighbourTableStatsInfo {
    allocs: u64,
    destroys: u64,
    hash_grows: u64,
    res_failed: u64,
    lookups: u64,
    hits: u64,
    multicast_probes_received: u64,
    unicast_probes_received: u64,
    periodic_gc_runs: u64,
    forced_gc_runs: u64,
    table_fulls: u64,
}

impl From<NeighbourTableStats> for NeighbourTableStatsInfo {
    fn from(value: NeighbourTableStats) -> Self {
        Self {
            allocs: value.allocs,
            destroys: value.destroys,
            hash_grows: value.hash_grows,
            res_failed: value.res_failed,
            lookups: value.lookups,
            hits: value.hits,
            multicast_probes_received: value.multicast_probes_received,
            unicast_probes_received: value.unicast_probes_received,
            periodic_gc_runs: value.periodic_gc_runs,
            forced_gc_runs: value.forced_gc_runs,
            table_fulls: value.table_fulls,
        }
    }
}

fn parameter_pair(
    value: NeighbourTableParameter,
) -> Option<(&'static str, u64)> {
    Some(match value {
        NeighbourTableParameter::Ifindex(value) => ("ifindex", value.into()),
        NeighbourTableParameter::ReferenceCount(value) => {
            ("refcnt", value.into())
        }
        NeighbourTableParameter::ReachableTime(value) => ("reachable", value),
        NeighbourTableParameter::BaseReachableTime(value) => {
            ("base_reachable", value)
        }
        NeighbourTableParameter::RetransTime(value) => ("retrans", value),
        NeighbourTableParameter::GcStaletime(value) => ("gc_stale", value),
        NeighbourTableParameter::DelayProbeTime(value) => {
            ("delay_probe", value)
        }
        NeighbourTableParameter::QueueLen(value) => ("queue_len", value.into()),
        NeighbourTableParameter::AppProbes(value) => {
            ("app_probes", value.into())
        }
        NeighbourTableParameter::UcastProbes(value) => {
            ("ucast_probes", value.into())
        }
        NeighbourTableParameter::McastProbes(value) => {
            ("mcast_probes", value.into())
        }
        NeighbourTableParameter::AnycastDelay(value) => {
            ("anycast_delay", value)
        }
        NeighbourTableParameter::ProxyDelay(value) => ("proxy_delay", value),
        NeighbourTableParameter::ProxyQlen(value) => {
            ("proxy_qlen", value.into())
        }
        NeighbourTableParameter::Locktime(value) => ("locktime", value),
        NeighbourTableParameter::QueueLenbytes(value) => {
            ("queue_len_bytes", value.into())
        }
        NeighbourTableParameter::McastReprobes(value) => {
            ("mcast_reprobes", value.into())
        }
        NeighbourTableParameter::IntervalProbeTimeMs(value) => {
            ("interval_probe_time_ms", value)
        }
        NeighbourTableParameter::Other(_) => return None,
        _ => return None,
    })
}

async fn handle_show(
    options: &[&str],
    preferred_family: Option<AddressFamily>,
) -> Result<Vec<CliNeighbourTableInfo>, CliError> {
    let mut name_filter = None;
    let mut device_filter = None;
    let mut options = options.iter().copied();
    while let Some(option) = options.next() {
        match option {
            "name" => {
                name_filter = Some(
                    options.next().ok_or("missing table name after `name`")?,
                );
            }
            "dev" => {
                device_filter =
                    Some(options.next().ok_or("missing device after `dev`")?);
            }
            other => {
                return Err(format!("unknown ntable option `{other}`").into());
            }
        }
    }

    let (connection, mut handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    let device_index = if let Some(device) = device_filter {
        Some(resolve_link_index(&handle, device).await?)
    } else {
        None
    };

    let family = preferred_family.unwrap_or(AddressFamily::Unspec);
    let mut request_message = NeighbourTableMessage::default();
    request_message.header.family = family;
    let mut request = NetlinkMessage::from(
        RouteNetlinkMessage::GetNeighbourTable(request_message),
    );
    request.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut stream = handle.request(request)?;
    let mut tables = Vec::new();
    while let Some(message) = stream.next().await {
        match message.payload {
            NetlinkPayload::InnerMessage(
                RouteNetlinkMessage::NewNeighbourTable(table),
            ) => {
                let info = CliNeighbourTableInfo::from_message(table);
                let matches_name = name_filter
                    .is_none_or(|name| info.name.as_deref() == Some(name));
                let matches_device = device_index.is_none_or(|index| {
                    info.parameters.get("ifindex") == Some(&(index as u64))
                });
                if matches_name && matches_device {
                    tables.push(info);
                }
            }
            NetlinkPayload::Error(error) => {
                return Err(
                    format!("neighbour-table netlink error: {error}").into()
                );
            }
            NetlinkPayload::Done(_) => break,
            _ => {}
        }
    }
    Ok(tables)
}

const NTABLE_HELP: &str = "Usage: ip ntable show [ name NAME ] [ dev DEV ]\n";
