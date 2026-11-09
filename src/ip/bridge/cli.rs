// SPDX-License-Identifier: MIT

use std::{
    collections::BTreeMap,
    fmt::{self, Write as _},
    net::IpAddr,
};

use futures_util::TryStreamExt;
use iproute_rs::{
    CanDisplay, CanOutput, CliError, mac_to_string, parse_mac_str,
};
use rtnetlink::{
    Handle, LinkBridgePort, LinkBridgeVlan,
    packet_route::{
        AddressFamily,
        link::{
            AfSpecBridge, BridgeFlag, BridgeMulticastRouterType,
            BridgePortState, BridgeVlanInfoFlags, InfoBridgePort, InfoPortData,
            LinkAttribute, LinkExtentMask, LinkInfo, LinkMessage,
        },
        neighbour::{
            NeighbourAddress, NeighbourAttribute, NeighbourFlags,
            NeighbourMessage, NeighbourState,
        },
        route::RouteType,
    },
};
use serde::Serialize;

use crate::link::flags::link_flags_to_string;

pub(crate) struct BridgeCommand;

impl BridgeCommand {
    pub(crate) const CMD: &'static str = "bridge";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("bridge link, forwarding database, and VLAN management")
            .subcommand_required(false)
            .subcommand(
                clap::Command::new("link")
                    .about("bridge port management")
                    .subcommand_required(false)
                    .subcommand(
                        clap::Command::new("show")
                            .alias("list")
                            .arg(options_arg()),
                    )
                    .subcommand(clap::Command::new("set").arg(options_arg())),
            )
            .subcommand(
                clap::Command::new("fdb")
                    .about("forwarding database management")
                    .subcommand_required(false)
                    .subcommand(
                        clap::Command::new("show")
                            .alias("list")
                            .arg(options_arg()),
                    )
                    .subcommand(clap::Command::new("get").arg(options_arg()))
                    .subcommand(clap::Command::new("add").arg(options_arg()))
                    .subcommand(clap::Command::new("append").arg(options_arg()))
                    .subcommand(
                        clap::Command::new("del")
                            .alias("delete")
                            .arg(options_arg()),
                    )
                    .subcommand(
                        clap::Command::new("replace").arg(options_arg()),
                    )
                    .subcommand(clap::Command::new("flush").arg(options_arg())),
            )
            .subcommand(
                clap::Command::new("vlan")
                    .about("bridge VLAN filtering management")
                    .subcommand_required(false)
                    .subcommand(
                        clap::Command::new("show")
                            .alias("list")
                            .arg(options_arg()),
                    )
                    .subcommand(clap::Command::new("add").arg(options_arg()))
                    .subcommand(
                        clap::Command::new("del")
                            .alias("delete")
                            .arg(options_arg()),
                    ),
            )
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<BridgeOutput, CliError> {
        match matches.subcommand() {
            Some(("link", link_matches)) => handle_link(link_matches).await,
            Some(("fdb", fdb_matches)) => handle_fdb(fdb_matches).await,
            Some(("vlan", vlan_matches)) => handle_vlan(vlan_matches).await,
            _ => Err("bridge requires one of: link, fdb, vlan".into()),
        }
    }
}

fn options_arg() -> clap::Arg {
    clap::Arg::new("options")
        .action(clap::ArgAction::Append)
        .trailing_var_arg(true)
}

pub(crate) enum BridgeOutput {
    Link(Vec<CliBridgeLink>),
    Fdb(Vec<CliFdbEntry>),
    Vlan(Vec<CliBridgeVlan>),
}

impl Serialize for BridgeOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Link(entries) => entries.serialize(serializer),
            Self::Fdb(entries) => entries.serialize(serializer),
            Self::Vlan(entries) => entries.serialize(serializer),
        }
    }
}

impl CanDisplay for BridgeOutput {
    fn gen_string(&self) -> String {
        match self {
            Self::Link(entries) => entries
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
            Self::Fdb(entries) => entries
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
            Self::Vlan(entries) => format_vlan_text(entries),
        }
    }
}

impl CanOutput for BridgeOutput {}

#[derive(Debug, Default, Serialize)]
pub(crate) struct CliBridgeLink {
    ifindex: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    link: Option<String>,
    ifname: String,
    flags: Vec<String>,
    mtu: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "master")]
    master: Option<String>,
    state: String,
    priority: u32,
    cost: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    hairpin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guard: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_block: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fastleave: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    learning: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flood: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcast_flood: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bcast_flood: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcast_router: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcast_to_unicast: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    neigh_suppress: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    neigh_vlan_suppress: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    neigh_forward_grat: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vlan_tunnel: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    isolated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mab: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcast_n_groups: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcast_max_groups: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_nhid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_port: Option<String>,
}

impl fmt::Display for CliBridgeLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let link = self
            .link
            .as_deref()
            .map(|name| format!("@{name}"))
            .unwrap_or_default();
        write!(
            f,
            "{}: {}{}: <{}> mtu {}",
            self.ifindex,
            self.ifname,
            link,
            self.flags.join(","),
            self.mtu
        )?;
        if let Some(master) = &self.master {
            write!(f, " master {master}")?;
        }
        write!(
            f,
            " state {} priority {} cost {} ",
            self.state, self.priority, self.cost
        )?;
        let has_details = [
            self.hairpin.is_some(),
            self.guard.is_some(),
            self.root_block.is_some(),
            self.fastleave.is_some(),
            self.learning.is_some(),
            self.flood.is_some(),
            self.mcast_flood.is_some(),
            self.bcast_flood.is_some(),
            self.mcast_router.is_some(),
            self.mcast_to_unicast.is_some(),
            self.neigh_suppress.is_some(),
            self.neigh_vlan_suppress.is_some(),
            self.neigh_forward_grat.is_some(),
            self.vlan_tunnel.is_some(),
            self.isolated.is_some(),
            self.locked.is_some(),
            self.mab.is_some(),
            self.mcast_n_groups.is_some(),
            self.mcast_max_groups.is_some(),
            self.backup_nhid.is_some(),
            self.backup_port.is_some(),
        ]
        .into_iter()
        .any(std::convert::identity);
        if !has_details {
            return Ok(());
        }

        write!(f, "\n    ")?;
        for (name, value) in [
            ("hairpin", self.hairpin),
            ("guard", self.guard),
            ("root_block", self.root_block),
            ("fastleave", self.fastleave),
            ("learning", self.learning),
            ("flood", self.flood),
            ("mcast_flood", self.mcast_flood),
            ("bcast_flood", self.bcast_flood),
        ] {
            if let Some(value) = value {
                write!(f, "{name} {} ", on_off(value))?;
            }
        }
        if let Some(value) = self.mcast_router {
            write!(f, "mcast_router {value} ")?;
        }
        for (name, value) in [
            ("mcast_to_unicast", self.mcast_to_unicast),
            ("neigh_suppress", self.neigh_suppress),
            ("neigh_vlan_suppress", self.neigh_vlan_suppress),
            ("neigh_forward_grat", self.neigh_forward_grat),
            ("vlan_tunnel", self.vlan_tunnel),
        ] {
            if let Some(value) = value {
                write!(f, "{name} {} ", on_off(value))?;
            }
        }
        if let Some(value) = &self.backup_port {
            write!(f, "backup_port {value} ")?;
        }
        if let Some(value) = self.backup_nhid {
            write!(f, "backup_nhid {value} ")?;
        }
        for (name, value) in [
            ("isolated", self.isolated),
            ("locked", self.locked),
            ("mab", self.mab),
        ] {
            if let Some(value) = value {
                write!(f, "{name} {} ", on_off(value))?;
            }
        }
        if let Some(value) = self.mcast_n_groups {
            write!(f, "mcast_n_groups {value} ")?;
        }
        if let Some(value) = self.mcast_max_groups {
            write!(f, "mcast_max_groups {value} ")?;
        }
        Ok(())
    }
}

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

fn link_name(message: &LinkMessage) -> Option<String> {
    message.attributes.iter().find_map(|attr| match attr {
        LinkAttribute::IfName(name) => Some(name.clone()),
        _ => None,
    })
}

fn link_index(message: &LinkMessage) -> Option<u32> {
    message.attributes.iter().find_map(|attr| match attr {
        LinkAttribute::Link(index) => Some(*index),
        _ => None,
    })
}

fn controller_index(message: &LinkMessage) -> Option<u32> {
    message.attributes.iter().find_map(|attr| match attr {
        LinkAttribute::Controller(index) => Some(*index),
        _ => None,
    })
}

fn link_mtu(message: &LinkMessage) -> u32 {
    message
        .attributes
        .iter()
        .find_map(|attr| match attr {
            LinkAttribute::Mtu(mtu) => Some(*mtu),
            _ => None,
        })
        .unwrap_or_default()
}

fn bridge_port_data(message: &LinkMessage) -> Option<Vec<InfoBridgePort>> {
    message.attributes.iter().find_map(|attr| {
        let LinkAttribute::LinkInfo(infos) = attr else {
            return None;
        };
        infos.iter().find_map(|info| match info {
            LinkInfo::PortData(InfoPortData::BridgePort(data)) => {
                Some(data.clone())
            }
            _ => None,
        })
    })
}

async fn new_handle() -> Result<Handle, CliError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    Ok(handle)
}

async fn dump_links(
    handle: &Handle,
    include_vlan_data: bool,
) -> Result<Vec<LinkMessage>, CliError> {
    let mut request = handle.link().get();
    if include_vlan_data {
        request = request.set_filter_mask(
            AddressFamily::Bridge,
            vec![LinkExtentMask::BrvlanCompressed],
        );
    }
    let mut links = request.execute();
    let mut messages = Vec::new();
    while let Some(message) = links.try_next().await? {
        messages.push(message);
    }
    Ok(messages)
}

fn link_name_map(messages: &[LinkMessage]) -> BTreeMap<u32, String> {
    messages
        .iter()
        .filter_map(|message| {
            link_name(message).map(|name| (message.header.index, name))
        })
        .collect()
}

async fn resolve_link_index(
    handle: &Handle,
    name: &str,
) -> Result<u32, CliError> {
    if let Ok(index) = name.parse::<u32>() {
        return Ok(index);
    }
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let Some(message) = links.try_next().await? else {
        return Err(format!("Cannot find device \"{name}\"").into());
    };
    Ok(message.header.index)
}

fn parse_bridge_link_message(
    message: &LinkMessage,
    names: &BTreeMap<u32, String>,
    include_details: bool,
) -> Option<CliBridgeLink> {
    let data = bridge_port_data(message)?;
    let ifname = link_name(message)?;
    let mut result = CliBridgeLink {
        ifindex: message.header.index,
        link: link_index(message).and_then(|index| names.get(&index).cloned()),
        ifname,
        flags: link_flags_to_string(message.header.flags),
        mtu: link_mtu(message),
        master: controller_index(message)
            .and_then(|index| names.get(&index).cloned()),
        ..Default::default()
    };

    for attr in data {
        match attr {
            InfoBridgePort::State(value) => result.state = value.to_string(),
            InfoBridgePort::Priority(value) => result.priority = value as u32,
            InfoBridgePort::Cost(value) => result.cost = value,
            InfoBridgePort::HairpinMode(value) if include_details => {
                result.hairpin = Some(value)
            }
            InfoBridgePort::Guard(value) if include_details => {
                result.guard = Some(value)
            }
            InfoBridgePort::Protect(value) if include_details => {
                result.root_block = Some(value)
            }
            InfoBridgePort::FastLeave(value) if include_details => {
                result.fastleave = Some(value)
            }
            InfoBridgePort::Learning(value) if include_details => {
                result.learning = Some(value)
            }
            InfoBridgePort::UnicastFlood(value) if include_details => {
                result.flood = Some(value)
            }
            InfoBridgePort::MulticastFlood(value) if include_details => {
                result.mcast_flood = Some(value)
            }
            InfoBridgePort::BroadcastFlood(value) if include_details => {
                result.bcast_flood = Some(value)
            }
            InfoBridgePort::MulticastRouter(value) if include_details => {
                result.mcast_router = Some(value.into())
            }
            InfoBridgePort::MulticastToUnicast(value) if include_details => {
                result.mcast_to_unicast = Some(value)
            }
            InfoBridgePort::NeighSupress(value) if include_details => {
                result.neigh_suppress = Some(value)
            }
            InfoBridgePort::NeighVlanSuppress(value) if include_details => {
                result.neigh_vlan_suppress = Some(value)
            }
            InfoBridgePort::NeighForwardGrat(value) if include_details => {
                result.neigh_forward_grat = Some(value)
            }
            InfoBridgePort::VlanTunnel(value) if include_details => {
                result.vlan_tunnel = Some(value)
            }
            InfoBridgePort::Isolated(value) if include_details => {
                result.isolated = Some(value)
            }
            InfoBridgePort::Locked(value) if include_details => {
                result.locked = Some(value)
            }
            InfoBridgePort::Mab(value) if include_details => {
                result.mab = Some(value)
            }
            InfoBridgePort::BackupPort(value)
                if include_details && value != 0 =>
            {
                result.backup_port = names
                    .get(&value)
                    .cloned()
                    .or_else(|| Some(value.to_string()))
            }
            InfoBridgePort::BackupNextHopId(value) if include_details => {
                result.backup_nhid = Some(value)
            }
            InfoBridgePort::MulticastNGroups(value) if include_details => {
                result.mcast_n_groups = Some(value)
            }
            InfoBridgePort::MulticastMaxGroups(value) if include_details => {
                result.mcast_max_groups = Some(value)
            }
            _ => {}
        }
    }

    Some(result)
}

#[derive(Default)]
struct LinkShowOptions {
    dev: Option<String>,
    master: Option<String>,
}

fn parse_link_show_options(
    options: &[&str],
) -> Result<LinkShowOptions, CliError> {
    let mut parsed = LinkShowOptions::default();
    let mut iter = options.iter().copied();
    while let Some(option) = iter.next() {
        match option {
            "dev" | "name" => parsed.dev = Some(next_value(&mut iter, option)?),
            "master" => parsed.master = Some(next_value(&mut iter, option)?),
            "oneline" | "details" => {}
            other => {
                return Err(format!(
                    "Unknown bridge link show option: {other}"
                )
                .into());
            }
        }
    }
    Ok(parsed)
}

async fn handle_link_show(
    options: &[&str],
    include_details: bool,
) -> Result<BridgeOutput, CliError> {
    let options = parse_link_show_options(options)?;
    let handle = new_handle().await?;
    let messages = dump_links(&handle, false).await?;
    let names = link_name_map(&messages);
    let entries = messages
        .iter()
        .filter_map(|message| {
            parse_bridge_link_message(message, &names, include_details)
        })
        .filter(|entry| {
            options.dev.as_deref().is_none_or(|dev| entry.ifname == dev)
        })
        .filter(|entry| {
            options
                .master
                .as_deref()
                .is_none_or(|master| entry.master.as_deref() == Some(master))
        })
        .collect();
    Ok(BridgeOutput::Link(entries))
}

enum LinkPortSetting {
    FdbFlush,
    State(BridgePortState),
    Priority(u16),
    Cost(u32),
    Hairpin(bool),
    Guard(bool),
    RootBlock(bool),
    FastLeave(bool),
    Learning(bool),
    Flood(bool),
    McastRouter(BridgeMulticastRouterType),
    McastFlood(bool),
    BcastFlood(bool),
    McastToUnicast(bool),
    McastMaxGroups(u32),
    NeighSuppress(bool),
    NeighVlanSuppress(bool),
    VlanTunnel(bool),
    Isolated(bool),
    Locked(bool),
    Mab(bool),
    BackupPort(String),
    NoBackupPort,
    BackupNextHopId(u32),
}

struct LinkSetOptions {
    dev: String,
    settings: Vec<LinkPortSetting>,
}

fn parse_link_set_options(
    options: &[&str],
) -> Result<LinkSetOptions, CliError> {
    let mut dev = None;
    let mut settings = Vec::new();
    let mut iter = options.iter().copied();
    while let Some(option) = iter.next() {
        match option {
            "dev" => dev = Some(next_value(&mut iter, option)?),
            "state" => settings.push(LinkPortSetting::State(parse_value(
                next_value(&mut iter, option)?.as_str(),
                option,
            )?)),
            "priority" => settings.push(LinkPortSetting::Priority(parse_u16(
                next_value(&mut iter, option)?.as_str(),
                option,
            )?)),
            "cost" => settings.push(LinkPortSetting::Cost(parse_u32(
                next_value(&mut iter, option)?.as_str(),
                option,
            )?)),
            "hairpin" => settings.push(LinkPortSetting::Hairpin(parse_bool(
                next_value(&mut iter, option)?.as_str(),
            )?)),
            "guard" => settings.push(LinkPortSetting::Guard(parse_bool(
                next_value(&mut iter, option)?.as_str(),
            )?)),
            "root_block" => settings.push(LinkPortSetting::RootBlock(
                parse_bool(next_value(&mut iter, option)?.as_str())?,
            )),
            "fastleave" | "mcast_fast_leave" => {
                settings.push(LinkPortSetting::FastLeave(parse_bool(
                    next_value(&mut iter, option)?.as_str(),
                )?));
            }
            "learning" => settings.push(LinkPortSetting::Learning(parse_bool(
                next_value(&mut iter, option)?.as_str(),
            )?)),
            "flood" => settings.push(LinkPortSetting::Flood(parse_bool(
                next_value(&mut iter, option)?.as_str(),
            )?)),
            "mcast_router" => settings.push(LinkPortSetting::McastRouter(
                parse_value(next_value(&mut iter, option)?.as_str(), option)?,
            )),
            "mcast_flood" => settings.push(LinkPortSetting::McastFlood(
                parse_bool(next_value(&mut iter, option)?.as_str())?,
            )),
            "bcast_flood" => settings.push(LinkPortSetting::BcastFlood(
                parse_bool(next_value(&mut iter, option)?.as_str())?,
            )),
            "mcast_to_unicast" => {
                settings.push(LinkPortSetting::McastToUnicast(parse_bool(
                    next_value(&mut iter, option)?.as_str(),
                )?))
            }
            "mcast_max_groups" => {
                settings.push(LinkPortSetting::McastMaxGroups(parse_u32(
                    next_value(&mut iter, option)?.as_str(),
                    option,
                )?))
            }
            "neigh_suppress" => settings.push(LinkPortSetting::NeighSuppress(
                parse_bool(next_value(&mut iter, option)?.as_str())?,
            )),
            "neigh_vlan_suppress" => {
                settings.push(LinkPortSetting::NeighVlanSuppress(parse_bool(
                    next_value(&mut iter, option)?.as_str(),
                )?))
            }
            "vlan_tunnel" => settings.push(LinkPortSetting::VlanTunnel(
                parse_bool(next_value(&mut iter, option)?.as_str())?,
            )),
            "isolated" => settings.push(LinkPortSetting::Isolated(parse_bool(
                next_value(&mut iter, option)?.as_str(),
            )?)),
            "locked" => settings.push(LinkPortSetting::Locked(parse_bool(
                next_value(&mut iter, option)?.as_str(),
            )?)),
            "mab" => settings.push(LinkPortSetting::Mab(parse_bool(
                next_value(&mut iter, option)?.as_str(),
            )?)),
            "backup_port" => settings.push(LinkPortSetting::BackupPort(
                next_value(&mut iter, option)?,
            )),
            "nobackup_port" => settings.push(LinkPortSetting::NoBackupPort),
            "backup_nhid" => settings.push(LinkPortSetting::BackupNextHopId(
                parse_u32(next_value(&mut iter, option)?.as_str(), option)?,
            )),
            "fdb_flush" => settings.push(LinkPortSetting::FdbFlush),
            "learning_sync" | "hwmode" | "self" | "master" => {
                return Err(format!(
                    "bridge link option `{option}` is not supported by the current netlink API"
                ).into());
            }
            other => {
                return Err(
                    format!("Unknown bridge link set option: {other}").into()
                );
            }
        }
    }
    let Some(dev) = dev else {
        return Err("bridge link set requires `dev DEV`".into());
    };
    if settings.is_empty() {
        return Err("bridge link set requires at least one setting".into());
    }
    Ok(LinkSetOptions { dev, settings })
}

async fn handle_link_set(options: &[&str]) -> Result<BridgeOutput, CliError> {
    let options = parse_link_set_options(options)?;
    let handle = new_handle().await?;
    let index = resolve_link_index(&handle, &options.dev).await?;
    let mut builder = LinkBridgePort::new(index);
    for setting in options.settings {
        builder = match setting {
            LinkPortSetting::FdbFlush => builder.fdb_flush(),
            LinkPortSetting::State(value) => builder.state(value),
            LinkPortSetting::Priority(value) => builder.priority(value),
            LinkPortSetting::Cost(value) => builder.cost(value),
            LinkPortSetting::Hairpin(value) => builder.hairpin(value),
            LinkPortSetting::Guard(value) => builder.guard(value),
            LinkPortSetting::RootBlock(value) => builder.root_block(value),
            LinkPortSetting::FastLeave(value) => {
                builder.mcast_fast_leave(value)
            }
            LinkPortSetting::Learning(value) => builder.learning(value),
            LinkPortSetting::Flood(value) => builder.flood(value),
            LinkPortSetting::McastRouter(value) => builder.mcast_router(value),
            LinkPortSetting::McastFlood(value) => builder.mcast_flood(value),
            LinkPortSetting::BcastFlood(value) => builder.bcast_flood(value),
            LinkPortSetting::McastToUnicast(value) => {
                builder.mcast_to_unicast(value)
            }
            LinkPortSetting::McastMaxGroups(value) => builder
                .append_info_data(InfoBridgePort::MulticastMaxGroups(value)),
            LinkPortSetting::NeighSuppress(value) => {
                builder.neigh_suppress(value)
            }
            LinkPortSetting::NeighVlanSuppress(value) => {
                builder.neigh_vlan_suppress(value)
            }
            LinkPortSetting::VlanTunnel(value) => builder.vlan_tunnel(value),
            LinkPortSetting::Isolated(value) => builder.isolated(value),
            LinkPortSetting::Locked(value) => builder.locked(value),
            LinkPortSetting::Mab(value) => builder.mab(value),
            LinkPortSetting::BackupPort(device) => {
                let backup_index = resolve_link_index(&handle, &device).await?;
                builder.backup_port(backup_index)
            }
            LinkPortSetting::NoBackupPort => builder.nobackup_port(),
            LinkPortSetting::BackupNextHopId(value) => {
                builder.backup_nhid(value)
            }
        };
    }
    handle.link().set_port(builder.build()).execute().await?;
    Ok(BridgeOutput::Link(Vec::new()))
}

async fn handle_link(
    matches: &clap::ArgMatches,
) -> Result<BridgeOutput, CliError> {
    let include_details = matches.get_count("DETAILS") > 0;
    let options = matches
        .subcommand_matches("show")
        .or_else(|| matches.subcommand_matches("list"))
        .map(|m| {
            m.get_many::<String>("options")
                .unwrap_or_default()
                .map(String::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if let Some(set_matches) = matches.subcommand_matches("set") {
        let options = set_matches
            .get_many::<String>("options")
            .unwrap_or_default()
            .map(String::as_str)
            .collect::<Vec<_>>();
        handle_link_set(&options).await
    } else {
        handle_link_show(&options, include_details).await
    }
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a str>,
    option: &str,
) -> Result<String, CliError> {
    iter.next().map(str::to_string).ok_or_else(|| {
        format!("bridge option `{option}` requires a value").into()
    })
}

fn parse_bool(value: &str) -> Result<bool, CliError> {
    match value {
        "on" | "1" => Ok(true),
        "off" | "0" => Ok(false),
        _ => Err(format!("expected on/off or 0/1, got {value}").into()),
    }
}

fn parse_u16(value: &str, option: &str) -> Result<u16, CliError> {
    value
        .parse()
        .map_err(|_| format!("invalid {option} value: {value}").into())
}

fn parse_u32(value: &str, option: &str) -> Result<u32, CliError> {
    value
        .parse()
        .map_err(|_| format!("invalid {option} value: {value}").into())
}

fn parse_value<T>(value: &str, option: &str) -> Result<T, CliError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    value.parse().map_err(|error| {
        format!("invalid {option} value `{value}`: {error}").into()
    })
}

#[derive(Debug, Default)]
struct FdbOptions {
    mac: Option<Vec<u8>>,
    dev: Option<String>,
    bridge: Option<String>,
    vlan: Option<u16>,
    vni: Option<u32>,
    dst: Option<IpAddr>,
    port: Option<u16>,
    src_vni: Option<u32>,
    flags: NeighbourFlags,
    state: Option<NeighbourState>,
    kind: RouteType,
    dynamic: bool,
}

fn parse_fdb_options(
    options: &[&str],
    require_mac: bool,
) -> Result<FdbOptions, CliError> {
    let mut parsed = FdbOptions::default();
    let mut iter = options.iter().copied();
    while let Some(option) = iter.next() {
        match option {
            "to" => {
                let value = next_value(&mut iter, option)?;
                parsed.mac = Some(parse_mac_str(&value)?);
            }
            "dev" | "brport" => {
                parsed.dev = Some(next_value(&mut iter, option)?);
            }
            "br" => {
                parsed.bridge = Some(next_value(&mut iter, option)?);
            }
            "vlan" => {
                parsed.vlan = Some(parse_u16(
                    next_value(&mut iter, option)?.as_str(),
                    option,
                )?);
            }
            "vni" => {
                parsed.vni = Some(parse_u32(
                    next_value(&mut iter, option)?.as_str(),
                    option,
                )?);
            }
            "src_vni" => {
                parsed.src_vni = Some(parse_u32(
                    next_value(&mut iter, option)?.as_str(),
                    option,
                )?);
            }
            "dst" => {
                let value = next_value(&mut iter, option)?;
                parsed.dst = Some(value.parse().map_err(|_| {
                    CliError::from(format!("invalid dst address: {value}"))
                })?);
            }
            "port" => {
                parsed.port = Some(parse_u16(
                    next_value(&mut iter, option)?.as_str(),
                    option,
                )?);
            }
            "nhid" => {
                return Err("bridge fdb nhid is not supported by the current netlink API".into());
            }
            "self" => parsed.flags |= NeighbourFlags::Own,
            "master" => parsed.flags |= NeighbourFlags::Controller,
            "use" => parsed.flags |= NeighbourFlags::Use,
            "router" => parsed.flags |= NeighbourFlags::Router,
            "extern_learn" => parsed.flags |= NeighbourFlags::ExtLearned,
            "offloaded" => parsed.flags |= NeighbourFlags::Offloaded,
            "sticky" => parsed.flags |= NeighbourFlags::Sticky,
            "dynamic" => {
                parsed.dynamic = true;
                parsed.state = Some(NeighbourState::Reachable);
            }
            "permanent" => parsed.state = Some(NeighbourState::Permanent),
            "static" => parsed.state = Some(NeighbourState::Noarp),
            "local" => {
                parsed.state = Some(NeighbourState::Permanent);
                parsed.kind = RouteType::Local;
            }
            "state" => {
                parsed.state = Some(parse_value(
                    next_value(&mut iter, option)?.as_str(),
                    option,
                )?);
            }
            "temporary" => parsed.state = Some(NeighbourState::None),
            "activity_notify" | "inactive" | "norefresh" | "via" => {
                return Err(format!(
                    "bridge fdb option `{option}` is not supported by the current netlink API"
                ).into());
            }
            other if parsed.mac.is_none() => {
                parsed.mac = Some(parse_mac_str(other)?);
            }
            other => {
                return Err(
                    format!("Unknown bridge fdb option: {other}").into()
                );
            }
        }
    }
    if require_mac && parsed.mac.is_none() {
        return Err("bridge fdb operation requires a MAC address".into());
    }
    Ok(parsed)
}

#[derive(Debug, Serialize)]
pub(crate) struct CliFdbEntry {
    mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ifname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vlan: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vni: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    src_vni: Option<u32>,
    flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    master: Option<String>,
    state: String,
}

impl fmt::Display for CliFdbEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mac)?;
        if let Some(ifname) = &self.ifname {
            write!(f, " dev {ifname}")?;
        }
        if let Some(dst) = &self.dst {
            write!(f, " dst {dst}")?;
        }
        if let Some(vlan) = self.vlan {
            write!(f, " vlan {vlan}")?;
        }
        if let Some(port) = self.port {
            write!(f, " port {port}")?;
        }
        if let Some(vni) = self.vni {
            write!(f, " vni {vni}")?;
        }
        if let Some(src_vni) = self.src_vni {
            write!(f, " src_vni {src_vni}")?;
        }
        for flag in &self.flags {
            write!(f, " {flag}")?;
        }
        if let Some(master) = &self.master {
            write!(f, " master {master}")?;
        }
        if !self.state.is_empty() {
            write!(f, " {}", self.state)?;
        }
        Ok(())
    }
}

fn fdb_state(state: NeighbourState) -> String {
    match state {
        NeighbourState::None | NeighbourState::Reachable => String::new(),
        NeighbourState::Noarp => "static".into(),
        NeighbourState::Stale => "stale".into(),
        other => other.to_string(),
    }
}

fn fdb_flags(flags: NeighbourFlags) -> Vec<String> {
    let mut values = Vec::new();
    for (flag, name) in [
        (NeighbourFlags::Own, "self"),
        (NeighbourFlags::Controller, "master"),
        (NeighbourFlags::Use, "use"),
        (NeighbourFlags::Router, "router"),
        (NeighbourFlags::ExtLearned, "extern_learn"),
        (NeighbourFlags::Offloaded, "offloaded"),
        (NeighbourFlags::Sticky, "sticky"),
    ] {
        if flags.contains(flag) {
            values.push(name.to_string());
        }
    }
    values
}

fn fdb_destination(address: NeighbourAddress) -> String {
    match address {
        NeighbourAddress::Inet(value) => value.to_string(),
        NeighbourAddress::Inet6(value) => value.to_string(),
        NeighbourAddress::Other(value) => mac_to_string(&value),
        _ => String::new(),
    }
}

fn parse_fdb_message(
    message: &NeighbourMessage,
    names: &BTreeMap<u32, String>,
    include_ifname: bool,
) -> Option<CliFdbEntry> {
    let flags = message.header.flags;
    let mut mac = None;
    let mut vlan = None;
    let mut dst = None;
    let mut port = None;
    let mut vni = None;
    let mut src_vni = None;
    let mut master = None;
    for attr in &message.attributes {
        match attr {
            NeighbourAttribute::LinkLayerAddress(value) => {
                mac = Some(mac_to_string(value));
            }
            NeighbourAttribute::Vlan(value) => vlan = Some(*value),
            NeighbourAttribute::Destination(value) => {
                dst = Some(fdb_destination(value.clone()))
            }
            NeighbourAttribute::Port(value) => port = Some(*value),
            NeighbourAttribute::Vni(value) => vni = Some(*value),
            NeighbourAttribute::SourceVni(value) => src_vni = Some(*value),
            NeighbourAttribute::Controller(value) => {
                master = names
                    .get(value)
                    .cloned()
                    .or_else(|| Some(value.to_string()))
            }
            _ => {}
        }
    }
    Some(CliFdbEntry {
        mac: mac?,
        ifname: include_ifname.then(|| {
            names
                .get(&message.header.ifindex)
                .cloned()
                .unwrap_or_else(|| message.header.ifindex.to_string())
        }),
        vlan,
        dst,
        port,
        vni,
        src_vni,
        master,
        flags: fdb_flags(flags),
        state: fdb_state(message.header.state),
    })
}

fn fdb_matches(
    message: &NeighbourMessage,
    options: &FdbOptions,
    dev_index: Option<u32>,
    bridge_index: Option<u32>,
) -> bool {
    if let Some(index) = dev_index
        && message.header.ifindex != index
    {
        return false;
    }
    if let Some(mac) = &options.mac {
        let matches = message.attributes.iter().any(|attr| {
            matches!(attr, NeighbourAttribute::LinkLayerAddress(value) if value == mac)
        });
        if !matches {
            return false;
        }
    }
    if let Some(index) = bridge_index {
        let matches = message.attributes.iter().any(|attr| {
            matches!(attr, NeighbourAttribute::Controller(value) if *value == index)
        });
        if !matches {
            return false;
        }
    }
    if let Some(vlan) = options.vlan
        && !message.attributes.iter().any(|attr| {
            matches!(attr, NeighbourAttribute::Vlan(value) if *value == vlan)
        })
    {
        return false;
    }
    if let Some(vni) = options.vni
        && !message.attributes.iter().any(|attr| {
            matches!(attr, NeighbourAttribute::Vni(value) if *value == vni)
        })
    {
        return false;
    }
    if let Some(dst) = options.dst {
        let expected = NeighbourAddress::from(dst);
        if !message.attributes.iter().any(|attr| {
            matches!(attr, NeighbourAttribute::Destination(value) if *value == expected)
        }) {
            return false;
        }
    }
    if let Some(port) = options.port
        && !message.attributes.iter().any(|attr| {
            matches!(attr, NeighbourAttribute::Port(value) if *value == port)
        })
    {
        return false;
    }
    if let Some(src_vni) = options.src_vni
        && !message.attributes.iter().any(|attr| {
            matches!(attr, NeighbourAttribute::SourceVni(value) if *value == src_vni)
        })
    {
        return false;
    }
    if !message.header.flags.contains(options.flags) {
        return false;
    }
    if let Some(state) = options.state
        && !(options.dynamic && state == NeighbourState::Reachable)
        && message.header.state != state
    {
        return false;
    }
    if options.dynamic
        && matches!(
            message.header.state,
            NeighbourState::Permanent | NeighbourState::Noarp
        )
    {
        return false;
    }
    true
}

async fn resolve_fdb_indices(
    handle: &Handle,
    options: &FdbOptions,
) -> Result<(Option<u32>, Option<u32>), CliError> {
    let dev_index = match options.dev.as_deref() {
        Some(value) => Some(resolve_link_index(handle, value).await?),
        None => None,
    };
    let bridge_index = match options.bridge.as_deref() {
        Some(value) => Some(resolve_link_index(handle, value).await?),
        None => None,
    };
    Ok((dev_index, bridge_index))
}

async fn fetch_fdb(
    handle: &Handle,
    options: &FdbOptions,
) -> Result<Vec<(NeighbourMessage, CliFdbEntry)>, CliError> {
    let messages = dump_links(handle, false).await?;
    let names = link_name_map(&messages);
    let (dev_index, bridge_index) =
        resolve_fdb_indices(handle, options).await?;
    let mut neighbours = handle
        .neighbours()
        .get()
        .set_address_family(AddressFamily::Bridge)
        .execute();
    let mut entries = Vec::new();
    while let Some(message) = neighbours.try_next().await? {
        if !fdb_matches(&message, options, dev_index, bridge_index) {
            continue;
        }
        let Some(entry) =
            parse_fdb_message(&message, &names, options.dev.is_none())
        else {
            continue;
        };
        entries.push((message, entry));
    }
    Ok(entries)
}

fn fdb_attributes(options: &FdbOptions) -> Vec<NeighbourAttribute> {
    let mut attributes = Vec::new();
    if let Some(vlan) = options.vlan {
        attributes.push(NeighbourAttribute::Vlan(vlan));
    }
    if let Some(vni) = options.vni {
        attributes.push(NeighbourAttribute::Vni(vni));
    }
    if let Some(dst) = options.dst {
        attributes.push(NeighbourAttribute::Destination(dst.into()));
    }
    if let Some(port) = options.port {
        attributes.push(NeighbourAttribute::Port(port));
    }
    if let Some(src_vni) = options.src_vni {
        attributes.push(NeighbourAttribute::SourceVni(src_vni));
    }
    attributes
}

fn fdb_mutation_flags(mut flags: NeighbourFlags) -> NeighbourFlags {
    if !flags.intersects(NeighbourFlags::Own | NeighbourFlags::Controller) {
        flags |= NeighbourFlags::Own;
    }
    flags
}

fn fdb_message(
    index: u32,
    options: &FdbOptions,
) -> Result<NeighbourMessage, CliError> {
    let Some(mac) = &options.mac else {
        return Err("bridge fdb operation requires a MAC address".into());
    };
    let mut message = NeighbourMessage::default();
    message.header.family = AddressFamily::Bridge;
    message.header.ifindex = index;
    message.header.state = options.state.unwrap_or(NeighbourState::Noarp);
    message.header.flags = fdb_mutation_flags(options.flags);
    message.header.kind = options.kind;
    message
        .attributes
        .push(NeighbourAttribute::LinkLayerAddress(mac.clone()));
    message.attributes.extend(fdb_attributes(options));
    Ok(message)
}

async fn handle_fdb_mutation(
    operation: &str,
    options: &[&str],
) -> Result<BridgeOutput, CliError> {
    let parsed = parse_fdb_options(options, true)?;
    let handle = new_handle().await?;
    let Some(dev) = parsed.dev.as_deref() else {
        return Err(format!("bridge fdb {operation} requires `dev DEV`").into());
    };
    let index = resolve_link_index(&handle, dev).await?;
    let bridge_index = match parsed.bridge.as_deref() {
        Some(value) => Some(resolve_link_index(&handle, value).await?),
        None => None,
    };
    match operation {
        "add" | "append" | "replace" => {
            let mac = parsed.mac.as_deref().unwrap();
            let mut request = handle.neighbours().add_bridge(index, mac);
            request = request
                .state(parsed.state.unwrap_or(NeighbourState::Permanent))
                .flags(fdb_mutation_flags(parsed.flags))
                .kind(parsed.kind);
            request
                .message_mut()
                .attributes
                .extend(fdb_attributes(&parsed));
            if let Some(bridge_index) = bridge_index {
                request
                    .message_mut()
                    .attributes
                    .push(NeighbourAttribute::Controller(bridge_index));
            }
            if operation == "replace" {
                request.replace().execute().await?;
            } else {
                request.execute().await?;
            }
        }
        "del" => {
            let mut message = fdb_message(index, &parsed)?;
            if let Some(bridge_index) = bridge_index {
                message
                    .attributes
                    .push(NeighbourAttribute::Controller(bridge_index));
            }
            handle.neighbours().del(message).execute().await?;
        }
        _ => unreachable!(),
    }
    Ok(BridgeOutput::Fdb(Vec::new()))
}

async fn handle_fdb_flush(options: &[&str]) -> Result<BridgeOutput, CliError> {
    let parsed = parse_fdb_options(options, false)?;
    if parsed.dev.is_none() {
        return Err("bridge fdb flush requires `dev DEV`".into());
    }
    let handle = new_handle().await?;
    let entries = fetch_fdb(&handle, &parsed).await?;
    for (message, _) in entries {
        handle.neighbours().del(message).execute().await?;
    }
    Ok(BridgeOutput::Fdb(Vec::new()))
}

async fn handle_fdb_show(
    options: &[&str],
    require_mac: bool,
) -> Result<BridgeOutput, CliError> {
    let parsed = parse_fdb_options(options, require_mac)?;
    if require_mac && parsed.dev.is_none() && parsed.bridge.is_none() {
        return Err("bridge fdb get requires `dev DEV` or `br BRIDGE`".into());
    }
    let handle = new_handle().await?;
    let entries = fetch_fdb(&handle, &parsed).await?;
    Ok(BridgeOutput::Fdb(
        entries.into_iter().map(|(_, entry)| entry).collect(),
    ))
}

async fn handle_fdb(
    matches: &clap::ArgMatches,
) -> Result<BridgeOutput, CliError> {
    let (operation, child) = matches.subcommand().unwrap_or(("show", matches));
    let options = child
        .get_many::<String>("options")
        .unwrap_or_default()
        .map(String::as_str)
        .collect::<Vec<_>>();
    match operation {
        "add" | "append" | "replace" | "del" | "delete" => {
            handle_fdb_mutation(
                if operation == "delete" {
                    "del"
                } else {
                    operation
                },
                &options,
            )
            .await
        }
        "flush" => handle_fdb_flush(&options).await,
        "get" => handle_fdb_show(&options, true).await,
        "show" | "list" => handle_fdb_show(&options, false).await,
        _ => Err(format!("Unknown bridge fdb operation: {operation}").into()),
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct CliBridgeVlan {
    ifname: String,
    vlans: Vec<CliVlanInfo>,
}

#[derive(Debug, Serialize)]
struct CliVlanInfo {
    vlan: u16,
    flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcast_router: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    neigh_suppress: Option<bool>,
}

fn vlan_flags(flags: BridgeVlanInfoFlags) -> Vec<String> {
    let mut result = Vec::new();
    for (flag, name) in [
        (BridgeVlanInfoFlags::Pvid, "PVID"),
        (BridgeVlanInfoFlags::Untagged, "Egress Untagged"),
        (BridgeVlanInfoFlags::Controller, "MASTER"),
        (BridgeVlanInfoFlags::Brentry, "BR_ENTRY"),
        (BridgeVlanInfoFlags::RangeBegin, "RANGE_BEGIN"),
        (BridgeVlanInfoFlags::RangeEnd, "RANGE_END"),
        (BridgeVlanInfoFlags::OnlyOpts, "ONLY_OPTS"),
    ] {
        if flags.contains(flag) {
            result.push(name.to_string());
        }
    }
    result
}

fn parse_vlan_message(message: &LinkMessage) -> Option<CliBridgeVlan> {
    let ifname = link_name(message)?;
    let port_data = bridge_port_data(message).unwrap_or_default();
    let state = port_data.iter().find_map(|attr| match attr {
        InfoBridgePort::State(value) => Some(value.to_string()),
        _ => None,
    });
    let mcast_router = port_data.iter().find_map(|attr| match attr {
        InfoBridgePort::MulticastRouter(value) => Some((*value).into()),
        _ => None,
    });
    let neigh_suppress = port_data.iter().find_map(|attr| match attr {
        InfoBridgePort::NeighSupress(value) => Some(*value),
        _ => None,
    });
    let mut current_flags = BridgeVlanInfoFlags::empty();
    let mut vlans = Vec::new();
    for attr in &message.attributes {
        let LinkAttribute::AfSpecBridge(specs) = attr else {
            continue;
        };
        for spec in specs {
            match spec {
                AfSpecBridge::Flags(flag) => {
                    current_flags = match flag {
                        BridgeFlag::Controller => {
                            BridgeVlanInfoFlags::Controller
                        }
                        BridgeFlag::LowerDev => BridgeVlanInfoFlags::empty(),
                        BridgeFlag::Other(_) => BridgeVlanInfoFlags::empty(),
                        _ => BridgeVlanInfoFlags::empty(),
                    };
                }
                AfSpecBridge::VlanInfo(info) => vlans.push(CliVlanInfo {
                    vlan: info.vid,
                    flags: vlan_flags(info.flags | current_flags),
                    state: state.clone(),
                    mcast_router,
                    neigh_suppress,
                }),
                _ => {}
            }
        }
    }
    if vlans.is_empty() {
        return None;
    }
    Some(CliBridgeVlan { ifname, vlans })
}

#[derive(Default)]
struct VlanShowOptions {
    dev: Option<String>,
    vid: Option<u16>,
}

fn parse_vlan_show_options(
    options: &[&str],
) -> Result<VlanShowOptions, CliError> {
    let mut parsed = VlanShowOptions::default();
    let mut iter = options.iter().copied();
    while let Some(option) = iter.next() {
        match option {
            "dev" => parsed.dev = Some(next_value(&mut iter, option)?),
            "vid" => {
                parsed.vid = Some(parse_u16(
                    next_value(&mut iter, option)?.as_str(),
                    option,
                )?);
            }
            other => {
                return Err(format!(
                    "Unknown bridge vlan show option: {other}"
                )
                .into());
            }
        }
    }
    Ok(parsed)
}

async fn handle_vlan_show(options: &[&str]) -> Result<BridgeOutput, CliError> {
    let options = parse_vlan_show_options(options)?;
    let handle = new_handle().await?;
    let messages = dump_links(&handle, true).await?;
    let entries = messages
        .iter()
        .filter_map(parse_vlan_message)
        .filter(|entry| {
            options.dev.as_deref().is_none_or(|dev| entry.ifname == dev)
        })
        .map(|mut entry| {
            if let Some(vid) = options.vid {
                entry.vlans.retain(|vlan| vlan.vlan == vid);
            }
            entry
        })
        .filter(|entry| !entry.vlans.is_empty())
        .collect();
    Ok(BridgeOutput::Vlan(entries))
}

struct VlanMutationOptions {
    dev: String,
    vid: u16,
    flags: BridgeVlanInfoFlags,
    master: bool,
    self_flag: bool,
}

fn parse_vlan_mutation_options(
    options: &[&str],
) -> Result<VlanMutationOptions, CliError> {
    let mut dev = None;
    let mut vid = None;
    let mut flags = BridgeVlanInfoFlags::empty();
    let mut master = false;
    let mut self_flag = false;
    let mut iter = options.iter().copied();
    while let Some(option) = iter.next() {
        match option {
            "dev" => dev = Some(next_value(&mut iter, option)?),
            "vid" => {
                vid = Some(parse_u16(
                    next_value(&mut iter, option)?.as_str(),
                    option,
                )?);
            }
            "pvid" => flags |= BridgeVlanInfoFlags::Pvid,
            "untagged" => flags |= BridgeVlanInfoFlags::Untagged,
            "self" => self_flag = true,
            "master" => master = true,
            "tunnel_info" => {
                return Err("bridge vlan tunnel_info is not supported by the current CLI".into());
            }
            other => {
                return Err(
                    format!("Unknown bridge vlan option: {other}").into()
                );
            }
        }
    }
    let Some(dev) = dev else {
        return Err("bridge vlan operation requires `dev DEV`".into());
    };
    let Some(vid) = vid else {
        return Err("bridge vlan operation requires `vid VLAN_ID`".into());
    };
    if master && self_flag {
        return Err("bridge vlan accepts only one of `self` or `master`".into());
    }
    Ok(VlanMutationOptions {
        dev,
        vid,
        flags,
        master,
        self_flag,
    })
}

async fn handle_vlan_mutation(
    operation: &str,
    options: &[&str],
) -> Result<BridgeOutput, CliError> {
    let options = parse_vlan_mutation_options(options)?;
    let handle = new_handle().await?;
    let index = resolve_link_index(&handle, &options.dev).await?;
    let mut builder =
        LinkBridgeVlan::new(index).vlan(options.vid, options.flags);
    if options.self_flag {
        builder = builder.bridge_self();
    } else if options.master {
        builder =
            builder.append_af_spec(AfSpecBridge::Flags(BridgeFlag::Controller));
    }
    let message = builder.build();
    if operation == "add" {
        handle.link().set(message).execute().await?;
    } else {
        handle.link().del_with_message(message).execute().await?;
    }
    Ok(BridgeOutput::Vlan(Vec::new()))
}

fn format_vlan_text(entries: &[CliBridgeVlan]) -> String {
    let mut result = String::from("port              vlan-id  \n");
    for entry in entries {
        for vlan in &entry.vlans {
            let flags = if vlan.flags.is_empty() {
                String::new()
            } else {
                format!(" {}", vlan.flags.join(" "))
            };
            let _ =
                writeln!(result, "{:<18} {}{}", entry.ifname, vlan.vlan, flags);
            if vlan.state.is_some()
                || vlan.mcast_router.is_some()
                || vlan.neigh_suppress.is_some()
            {
                let _ = write!(result, "                    ");
                if let Some(state) = &vlan.state {
                    let _ = write!(result, "state {state} ");
                }
                if let Some(router) = vlan.mcast_router {
                    let _ = write!(result, "mcast_router {router} ");
                }
                if let Some(neigh_suppress) = vlan.neigh_suppress {
                    let _ = write!(
                        result,
                        "neigh_suppress {} ",
                        on_off(neigh_suppress)
                    );
                }
                result.push('\n');
            }
        }
    }
    result.trim_end_matches('\n').to_string()
}

async fn handle_vlan(
    matches: &clap::ArgMatches,
) -> Result<BridgeOutput, CliError> {
    let (operation, child) = matches.subcommand().unwrap_or(("show", matches));
    let options = child
        .get_many::<String>("options")
        .unwrap_or_default()
        .map(String::as_str)
        .collect::<Vec<_>>();
    match operation {
        "show" | "list" => handle_vlan_show(&options).await,
        "add" => handle_vlan_mutation("add", &options).await,
        "del" | "delete" => handle_vlan_mutation("del", &options).await,
        _ => Err(format!("Unknown bridge vlan operation: {operation}").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fdb_mac_and_filters() {
        let options = parse_fdb_options(
            &["02:00:00:00:00:01", "dev", "eth0", "vlan", "100", "master"],
            true,
        )
        .unwrap();
        assert_eq!(options.mac, Some(vec![2, 0, 0, 0, 0, 1]));
        assert_eq!(options.dev.as_deref(), Some("eth0"));
        assert_eq!(options.vlan, Some(100));
        assert!(options.flags.contains(NeighbourFlags::Controller));
    }

    #[test]
    fn parses_bridge_link_flush_without_value() {
        let options =
            parse_link_set_options(&["dev", "eth0", "fdb_flush"]).unwrap();
        assert_eq!(options.dev, "eth0");
        assert!(matches!(
            options.settings.as_slice(),
            [LinkPortSetting::FdbFlush]
        ));
    }

    #[test]
    fn parses_vlan_flags() {
        let options = parse_vlan_mutation_options(&[
            "vid", "10", "dev", "br0", "pvid", "untagged", "self",
        ])
        .unwrap();
        assert_eq!(options.vid, 10);
        assert!(options.flags.contains(BridgeVlanInfoFlags::Pvid));
        assert!(options.flags.contains(BridgeVlanInfoFlags::Untagged));
        assert!(options.self_flag);
    }

    #[test]
    fn formats_fdb_json_like_bridge() {
        let entry = CliFdbEntry {
            mac: "02:00:00:00:00:01".into(),
            ifname: Some("eth0".into()),
            dst: Some("192.0.2.1".into()),
            vlan: Some(100),
            port: Some(4789),
            vni: Some(10),
            src_vni: Some(20),
            flags: vec!["master".into()],
            master: Some("br0".into()),
            state: String::new(),
        };
        let json =
            serde_json::to_string(&BridgeOutput::Fdb(vec![entry])).unwrap();
        assert_eq!(
            json,
            r#"[{"mac":"02:00:00:00:00:01","ifname":"eth0","dst":"192.0.2.1","vlan":100,"port":4789,"vni":10,"src_vni":20,"flags":["master"],"master":"br0","state":""}]"#
        );
    }

    #[test]
    fn formats_dynamic_fdb_state_as_empty() {
        assert_eq!(fdb_state(NeighbourState::Reachable), "");
        assert_eq!(fdb_state(NeighbourState::Stale), "stale");
    }

    #[test]
    fn defaults_fdb_mutations_to_self() {
        assert!(
            fdb_mutation_flags(NeighbourFlags::empty())
                .contains(NeighbourFlags::Own)
        );
        assert!(
            fdb_mutation_flags(NeighbourFlags::Controller)
                .contains(NeighbourFlags::Controller)
        );
    }
}
