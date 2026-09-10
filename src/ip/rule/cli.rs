// SPDX-License-Identifier: MIT

//! The `ip rule` command implementation.

use std::{fmt, net::IpAddr};

use futures_util::TryStreamExt;
use iproute_rs::{CanDisplay, CanOutput, CliError};
use rtnetlink::{
    IpVersion,
    packet_route::{
        AddressFamily,
        route::RouteHeader,
        rule::{
            RuleAction, RuleAttribute, RuleFlags, RuleMessage, RulePortRange,
            RuleUidRange,
        },
    },
};
use serde::Serialize;

/// Top-level `ip rule` command.
pub(crate) struct RuleCommand;

impl RuleCommand {
    /// Canonical command name used by clap and the dispatcher.
    pub(crate) const CMD: &'static str = "rule";

    /// Build the command-line grammar for policy routing.
    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("routing policy database management")
            .alias("rules")
            .subcommand_required(false)
            .disable_help_subcommand(true)
            .subcommand(command_with_options("show", "list rules"))
            .subcommand(command_with_options("list", "list rules"))
            .subcommand(command_with_options("add", "add a rule"))
            .subcommand(
                command_with_options("delete", "delete a rule").alias("del"),
            )
            .subcommand(command_with_options("flush", "flush matching rules"))
            .subcommand(clap::Command::new("help").about("show rule help"))
    }

    /// Execute a rule command for one family, or both IPv4 and IPv6 when no
    /// family selector was supplied.
    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
        preferred_family: Option<AddressFamily>,
    ) -> Result<RuleOutput, CliError> {
        let (operation, child) =
            matches.subcommand().unwrap_or(("show", matches));
        if operation == "help" {
            return Ok(RuleOutput::Help(RULE_HELP.to_owned()));
        }

        let options = child
            .get_many::<String>("options")
            .unwrap_or_default()
            .map(String::as_str)
            .collect::<Vec<_>>();

        let family = match preferred_family {
            Some(AddressFamily::Inet) => Some(AddressFamily::Inet),
            Some(AddressFamily::Inet6) => Some(AddressFamily::Inet6),
            Some(other) => {
                return Err(
                    format!("ip rule does not support family {other}").into()
                );
            }
            None => None,
        };

        match operation {
            "show" | "list" => handle_show(&options, family).await,
            "add" => handle_add(&options, family, false).await,
            "delete" | "del" => handle_delete(&options, family).await,
            "flush" => handle_flush(&options, family).await,
            other => Err(format!("unknown ip rule operation: {other}").into()),
        }
    }
}

fn command_with_options(
    name: &'static str,
    about: &'static str,
) -> clap::Command {
    clap::Command::new(name).about(about).arg(
        clap::Arg::new("options")
            .action(clap::ArgAction::Append)
            .trailing_var_arg(true),
    )
}

/// Output returned by the rule command.
pub(crate) enum RuleOutput {
    /// Structured rule records.
    Rules(Vec<CliRuleInfo>),
    /// Help text is kept in the normal output path so JSON/YAML remain valid.
    Help(String),
}

impl Serialize for RuleOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Rules(rules) => rules.serialize(serializer),
            Self::Help(help) => help.serialize(serializer),
        }
    }
}

impl CanDisplay for RuleOutput {
    fn gen_string(&self) -> String {
        match self {
            Self::Rules(rules) => rules
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
            Self::Help(help) => help.clone(),
        }
    }
}

impl CanOutput for RuleOutput {}

/// A JSON-compatible view of a policy-routing rule.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct CliRuleInfo {
    family: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u32>,
    from: String,
    to: String,
    #[serde(skip_serializing_if = "is_zero")]
    tos: u8,
    table: u32,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    iif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fwmark: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fwmask: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uidrange: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipproto: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppress_prefixlength: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppress_ifgroup: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tun_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    goto: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    l3mdev: Option<bool>,
    invert: bool,
}

impl fmt::Display for CliRuleInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(priority) = self.priority {
            write!(f, "{priority}: ")?;
        }
        if self.invert {
            write!(f, "not ")?;
        }
        write!(f, "from {} to {}", self.from, self.to)?;
        if self.tos != 0 {
            write!(f, " tos {}", self.tos)?;
        }
        if let Some(iif) = &self.iif {
            write!(f, " iif {iif}")?;
        }
        if let Some(oif) = &self.oif {
            write!(f, " oif {oif}")?;
        }
        if let Some(mark) = self.fwmark {
            write!(f, " fwmark {mark:#x}")?;
            if let Some(mask) = self.fwmask {
                write!(f, "/{mask:#x}")?;
            }
        }
        if let Some(uidrange) = &self.uidrange {
            write!(f, " uidrange {uidrange}")?;
        }
        if let Some(ipproto) = &self.ipproto {
            write!(f, " ipproto {ipproto}")?;
        }
        if let Some(sport) = &self.sport {
            write!(f, " sport {sport}")?;
        }
        if let Some(dport) = &self.dport {
            write!(f, " dport {dport}")?;
        }
        if let Some(tun_id) = self.tun_id {
            write!(f, " tun_id {tun_id}")?;
        }
        if let Some(l3mdev) = self.l3mdev
            && l3mdev
        {
            write!(f, " l3mdev")?;
        }
        match self.action.as_str() {
            "lookup" => write!(f, " lookup {}", table_name(self.table))?,
            "goto" => write!(f, " goto {}", self.goto.unwrap_or_default())?,
            action => write!(f, " {action}")?,
        }
        if let Some(protocol) = &self.protocol {
            write!(f, " protocol {protocol}")?;
        }
        if let Some(prefix) = self.suppress_prefixlength {
            write!(f, " suppress_prefixlength {prefix}")?;
        }
        if let Some(group) = self.suppress_ifgroup {
            write!(f, " suppress_ifgroup {group}")?;
        }
        Ok(())
    }
}

fn is_zero(value: &u8) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RuleSpec {
    family: Option<AddressFamily>,
    source: Option<(IpAddr, u8)>,
    destination: Option<(IpAddr, u8)>,
    tos: u8,
    table: Option<u32>,
    action: RuleAction,
    priority: Option<u32>,
    iif: Option<String>,
    oif: Option<String>,
    fwmark: Option<u32>,
    fwmask: Option<u32>,
    uidrange: Option<RuleUidRange>,
    ipproto: Option<u8>,
    sport: Option<RulePortRange>,
    dport: Option<RulePortRange>,
    protocol: Option<u8>,
    suppress_prefixlength: Option<u32>,
    suppress_ifgroup: Option<u32>,
    tun_id: Option<u32>,
    goto: Option<u32>,
    l3mdev: bool,
    invert: bool,
}

impl RuleSpec {
    fn parse(
        options: &[&str],
        preferred_family: Option<AddressFamily>,
    ) -> Result<Self, CliError> {
        let mut spec = Self {
            family: preferred_family,
            action: RuleAction::Unspec,
            ..Self::default()
        };
        let mut iter = options.iter().copied();
        while let Some(option) = iter.next() {
            match option {
                "not" => spec.invert = true,
                "from" => {
                    let value = next_value(&mut iter, option)?;
                    if value != "all" {
                        spec.source = Some(parse_prefix(value)?);
                    }
                }
                "to" => {
                    let value = next_value(&mut iter, option)?;
                    if value != "all" {
                        spec.destination = Some(parse_prefix(value)?);
                    }
                }
                "tos" | "dsfield" => {
                    spec.tos = parse_u8(
                        next_value(&mut iter, option)?.as_str(),
                        option,
                    )?
                }
                "priority" | "pref" | "preference" | "order" => {
                    spec.priority = Some(parse_u32(
                        next_value(&mut iter, option)?.as_str(),
                        option,
                    )?)
                }
                "table" | "lookup" => {
                    spec.table = Some(parse_table(
                        next_value(&mut iter, option)?.as_str(),
                    )?);
                    spec.action = RuleAction::ToTable;
                }
                "iif" | "dev" => {
                    spec.iif = Some(next_value(&mut iter, option)?)
                }
                "oif" => spec.oif = Some(next_value(&mut iter, option)?),
                "fwmark" => {
                    let (mark, mask) =
                        parse_mark(&next_value(&mut iter, option)?)?;
                    spec.fwmark = Some(mark);
                    spec.fwmask = mask;
                }
                "uidrange" => {
                    spec.uidrange =
                        Some(parse_uid_range(&next_value(&mut iter, option)?)?)
                }
                "ipproto" => {
                    spec.ipproto = Some(parse_ip_protocol(&next_value(
                        &mut iter, option,
                    )?)?)
                }
                "sport" => {
                    spec.sport =
                        Some(parse_port_range(&next_value(&mut iter, option)?)?)
                }
                "dport" => {
                    spec.dport =
                        Some(parse_port_range(&next_value(&mut iter, option)?)?)
                }
                "protocol" => {
                    spec.protocol = Some(parse_u8(
                        next_value(&mut iter, option)?.as_str(),
                        option,
                    )?)
                }
                "suppress_prefixlength" => {
                    spec.suppress_prefixlength = Some(parse_u32(
                        next_value(&mut iter, option)?.as_str(),
                        option,
                    )?)
                }
                "suppress_ifgroup" => {
                    spec.suppress_ifgroup = Some(parse_u32(
                        next_value(&mut iter, option)?.as_str(),
                        option,
                    )?)
                }
                "tun_id" => {
                    spec.tun_id = Some(parse_u32(
                        next_value(&mut iter, option)?.as_str(),
                        option,
                    )?)
                }
                "l3mdev" => spec.l3mdev = true,
                "blackhole" => spec.action = RuleAction::Blackhole,
                "unreachable" => spec.action = RuleAction::Unreachable,
                "prohibit" => spec.action = RuleAction::Prohibit,
                "goto" => {
                    spec.action = RuleAction::Goto;
                    spec.goto = Some(parse_u32(
                        next_value(&mut iter, option)?.as_str(),
                        option,
                    )?);
                }
                "nat" | "map-to" => {
                    return Err("ip rule nat/map-to is not represented by the current rtnetlink RuleAction API".into());
                }
                other => {
                    return Err(
                        format!("unknown ip rule option: {other}").into()
                    );
                }
            }
        }
        if spec.family.is_none() {
            spec.family = spec
                .source
                .as_ref()
                .map(|(address, _)| family_for_address(*address))
                .or_else(|| {
                    spec.destination
                        .as_ref()
                        .map(|(address, _)| family_for_address(*address))
                });
        }
        Ok(spec)
    }

    fn message(&self) -> Result<RuleMessage, CliError> {
        let family = self.family.unwrap_or(AddressFamily::Inet);
        if let Some((address, _)) = self.source
            && family_for_address(address) != family
        {
            return Err(
                "rule source address family does not match the selected family"
                    .into(),
            );
        }
        if let Some((address, _)) = self.destination
            && family_for_address(address) != family
        {
            return Err("rule destination address family does not match the selected family".into());
        }
        let mut message = RuleMessage::default();
        message.header.family = family;
        message.header.tos = self.tos;
        message.header.action = self.action;
        message.header.flags = if self.invert {
            RuleFlags::Invert
        } else {
            RuleFlags::empty()
        };
        if let Some((address, prefix)) = self.source {
            message.header.src_len = prefix;
            message.attributes.push(RuleAttribute::Source(address));
        }
        if let Some((address, prefix)) = self.destination {
            message.header.dst_len = prefix;
            message.attributes.push(RuleAttribute::Destination(address));
        }
        if let Some(table) = self.table {
            if table <= u8::MAX as u32 {
                message.header.table = table as u8;
            } else {
                message.attributes.push(RuleAttribute::Table(table));
            }
        }
        if let Some(goto) = self.goto {
            message.attributes.push(RuleAttribute::Goto(goto));
        }
        push_rule_attribute(&mut message, self);
        Ok(message)
    }
}

fn push_rule_attribute(message: &mut RuleMessage, spec: &RuleSpec) {
    if let Some(priority) = spec.priority {
        message.attributes.push(RuleAttribute::Priority(priority));
    }
    if let Some(iif) = &spec.iif {
        message.attributes.push(RuleAttribute::Iifname(iif.clone()));
    }
    if let Some(oif) = &spec.oif {
        message.attributes.push(RuleAttribute::Oifname(oif.clone()));
    }
    if let Some(mark) = spec.fwmark {
        message.attributes.push(RuleAttribute::FwMark(mark));
    }
    if let Some(mask) = spec.fwmask {
        message.attributes.push(RuleAttribute::FwMask(mask));
    }
    if let Some(range) = spec.uidrange {
        message.attributes.push(RuleAttribute::UidRange(range));
    }
    if let Some(protocol) = spec.ipproto {
        message
            .attributes
            .push(RuleAttribute::IpProtocol(protocol.into()));
    }
    if let Some(range) = spec.sport {
        message
            .attributes
            .push(RuleAttribute::SourcePortRange(range));
    }
    if let Some(range) = spec.dport {
        message
            .attributes
            .push(RuleAttribute::DestinationPortRange(range));
    }
    if let Some(protocol) = spec.protocol {
        message
            .attributes
            .push(RuleAttribute::Protocol(protocol.into()));
    }
    if let Some(prefix) = spec.suppress_prefixlength {
        message
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(prefix));
    }
    if let Some(group) = spec.suppress_ifgroup {
        message
            .attributes
            .push(RuleAttribute::SuppressIfGroup(group));
    }
    if let Some(tun_id) = spec.tun_id {
        message.attributes.push(RuleAttribute::TunId(tun_id));
    }
    if spec.l3mdev {
        message.attributes.push(RuleAttribute::L3MDev(true));
    }
}

async fn new_handle() -> Result<rtnetlink::Handle, CliError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    Ok(handle)
}

async fn fetch_rules(
    family: Option<AddressFamily>,
) -> Result<Vec<RuleMessage>, CliError> {
    let handle = new_handle().await?;
    let families = match family {
        Some(AddressFamily::Inet) => vec![IpVersion::V4],
        Some(AddressFamily::Inet6) => vec![IpVersion::V6],
        None => vec![IpVersion::V4, IpVersion::V6],
        Some(other) => {
            return Err(
                format!("ip rule does not support family {other}").into()
            );
        }
    };
    let mut rules = Vec::new();
    for version in families {
        let mut stream = handle.rule().get(version).execute();
        while let Some(rule) = stream.try_next().await? {
            rules.push(rule);
        }
    }
    rules.sort_by_key(|rule| {
        rule.attributes
            .iter()
            .find_map(|attr| match attr {
                RuleAttribute::Priority(priority) => Some(*priority),
                _ => None,
            })
            .unwrap_or(u32::MAX)
    });
    Ok(rules)
}

async fn handle_show(
    options: &[&str],
    family: Option<AddressFamily>,
) -> Result<RuleOutput, CliError> {
    let filter = if options.is_empty() {
        None
    } else {
        Some(RuleSpec::parse(options, family)?)
    };
    let rules = fetch_rules(family).await?;
    let records = rules
        .into_iter()
        .map(CliRuleInfo::from_message)
        .filter(|rule| filter.as_ref().is_none_or(|spec| rule.matches(spec)))
        .collect();
    Ok(RuleOutput::Rules(records))
}

async fn handle_add(
    options: &[&str],
    family: Option<AddressFamily>,
    replace: bool,
) -> Result<RuleOutput, CliError> {
    let spec = RuleSpec::parse(options, family)?;
    if spec.action == RuleAction::Unspec {
        return Err("ip rule add requires an action such as `table TABLE` or `blackhole`".into());
    }
    let mut request = new_handle().await?.rule().add();
    *request.message_mut() = spec.message()?;
    if replace {
        request = request.replace();
    }
    request.execute().await?;
    Ok(RuleOutput::Rules(Vec::new()))
}

async fn handle_delete(
    options: &[&str],
    family: Option<AddressFamily>,
) -> Result<RuleOutput, CliError> {
    let spec = RuleSpec::parse(options, family)?;
    let message = spec.message()?;
    new_handle().await?.rule().del(message).execute().await?;
    Ok(RuleOutput::Rules(Vec::new()))
}

async fn handle_flush(
    options: &[&str],
    family: Option<AddressFamily>,
) -> Result<RuleOutput, CliError> {
    let filter = if options.is_empty() {
        None
    } else {
        Some(RuleSpec::parse(options, family)?)
    };
    let handle = new_handle().await?;
    let rules = fetch_rules(family).await?;
    for rule in rules {
        let record = CliRuleInfo::from_message(rule.clone());
        if filter.as_ref().is_some_and(|spec| !record.matches(spec)) {
            continue;
        }
        // The three kernel-installed rules are normally not flushable.  Let
        // the kernel make the final decision, but avoid removing them by
        // default when the caller asked for a broad flush.
        if record
            .priority
            .is_some_and(|priority| matches!(priority, 0 | 32_766 | 32_767))
            && filter.is_none()
        {
            continue;
        }
        handle.rule().del(rule).execute().await?;
    }
    Ok(RuleOutput::Rules(Vec::new()))
}

impl CliRuleInfo {
    fn from_message(message: RuleMessage) -> Self {
        let family = message.header.family;
        let mut result = Self {
            family: family.to_string(),
            priority: None,
            from: prefix_text(None, message.header.src_len),
            to: prefix_text(None, message.header.dst_len),
            tos: message.header.tos,
            table: u32::from(message.header.table),
            action: action_text(message.header.action),
            iif: None,
            oif: None,
            fwmark: None,
            fwmask: None,
            uidrange: None,
            ipproto: None,
            sport: None,
            dport: None,
            protocol: None,
            suppress_prefixlength: None,
            suppress_ifgroup: None,
            tun_id: None,
            goto: None,
            l3mdev: None,
            invert: message.header.flags.contains(RuleFlags::Invert),
        };
        for attribute in message.attributes {
            match attribute {
                RuleAttribute::Source(address) => {
                    result.from =
                        prefix_text(Some(address), message.header.src_len)
                }
                RuleAttribute::Destination(address) => {
                    result.to =
                        prefix_text(Some(address), message.header.dst_len)
                }
                RuleAttribute::Priority(priority) => {
                    result.priority = Some(priority)
                }
                RuleAttribute::Iifname(value) => result.iif = Some(value),
                RuleAttribute::Oifname(value) => result.oif = Some(value),
                RuleAttribute::FwMark(value) => result.fwmark = Some(value),
                RuleAttribute::FwMask(value) => result.fwmask = Some(value),
                RuleAttribute::Table(value) => result.table = value,
                RuleAttribute::UidRange(value) => {
                    result.uidrange =
                        Some(format!("{}-{}", value.start, value.end))
                }
                RuleAttribute::IpProtocol(value) => {
                    result.ipproto = Some(ip_protocol_text(value))
                }
                RuleAttribute::SourcePortRange(value) => {
                    result.sport = Some(port_range_text(value))
                }
                RuleAttribute::DestinationPortRange(value) => {
                    result.dport = Some(port_range_text(value))
                }
                RuleAttribute::Protocol(value) => {
                    result.protocol = Some(value.to_string())
                }
                RuleAttribute::SuppressPrefixLen(value) => {
                    result.suppress_prefixlength = Some(value)
                }
                RuleAttribute::SuppressIfGroup(value) => {
                    result.suppress_ifgroup = Some(value)
                }
                RuleAttribute::TunId(value) => result.tun_id = Some(value),
                RuleAttribute::Goto(value) => result.goto = Some(value),
                RuleAttribute::L3MDev(value) => result.l3mdev = Some(value),
                _ => {}
            }
        }
        result
    }

    fn matches(&self, spec: &RuleSpec) -> bool {
        if let Some(family) = spec.family
            && self.family != family.to_string()
        {
            return false;
        }
        if let Some(priority) = spec.priority
            && self.priority != Some(priority)
        {
            return false;
        }
        if let Some((address, prefix)) = spec.source
            && self.from != prefix_text(Some(address), prefix)
        {
            return false;
        }
        if let Some((address, prefix)) = spec.destination
            && self.to != prefix_text(Some(address), prefix)
        {
            return false;
        }
        if let Some(table) = spec.table
            && self.table != table
        {
            return false;
        }
        true
    }
}

fn family_for_address(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    }
}

fn prefix_text(address: Option<IpAddr>, prefix: u8) -> String {
    address.map_or_else(
        || "all".to_owned(),
        |address| format!("{address}/{prefix}"),
    )
}

fn action_text(action: RuleAction) -> String {
    match action {
        RuleAction::Unspec | RuleAction::ToTable => "lookup".to_owned(),
        RuleAction::Goto => "goto".to_owned(),
        RuleAction::Nop => "nop".to_owned(),
        RuleAction::Blackhole => "blackhole".to_owned(),
        RuleAction::Unreachable => "unreachable".to_owned(),
        RuleAction::Prohibit => "prohibit".to_owned(),
        RuleAction::Other(value) => format!("action-{value}"),
        _ => "action-unknown".to_owned(),
    }
}

fn ip_protocol_text(protocol: rtnetlink::packet_route::IpProtocol) -> String {
    match protocol {
        rtnetlink::packet_route::IpProtocol::Other(value) => value.to_string(),
        value => format!("{value:?}").to_ascii_lowercase(),
    }
}

fn port_range_text(range: RulePortRange) -> String {
    if range.start == range.end {
        range.start.to_string()
    } else {
        format!("{}-{}", range.start, range.end)
    }
}

fn table_name(table: u32) -> String {
    match table {
        255 => "local".to_owned(),
        254 => "main".to_owned(),
        253 => "default".to_owned(),
        other => other.to_string(),
    }
}

fn parse_prefix(value: String) -> Result<(IpAddr, u8), CliError> {
    if value == "all" {
        return Err("`all` is only valid as an implicit rule prefix; omit `from` or `to`".into());
    }
    let (address, prefix) = value.split_once('/').map_or_else(
        || Ok((value.as_str(), None)),
        |(address, prefix)| {
            prefix
                .parse::<u8>()
                .map(|prefix| (address, Some(prefix)))
                .map_err(|_| CliError::from(format!("invalid prefix: {value}")))
        },
    )?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid rule prefix: {value}"))?;
    let prefix = prefix.unwrap_or(match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    });
    let max = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return Err(
            format!("invalid prefix length {prefix} for {address}").into()
        );
    }
    Ok((address, prefix))
}

fn parse_table(value: &str) -> Result<u32, CliError> {
    match value {
        "local" => Ok(255),
        "main" => Ok(u32::from(RouteHeader::RT_TABLE_MAIN)),
        "default" => Ok(253),
        value => parse_number(value, "table"),
    }
}

fn parse_mark(value: &str) -> Result<(u32, Option<u32>), CliError> {
    let (mark, mask) = value
        .split_once('/')
        .map_or((value, None), |(mark, mask)| (mark, Some(mask)));
    Ok((
        parse_number(mark, "fwmark")?,
        mask.map(|mask| parse_number(mask, "fwmask")).transpose()?,
    ))
}

fn parse_uid_range(value: &str) -> Result<RuleUidRange, CliError> {
    let (start, end) = value
        .split_once('-')
        .ok_or_else(|| CliError::from("uidrange requires START-END"))?;
    Ok(RuleUidRange {
        start: parse_number(start, "uidrange")?,
        end: parse_number(end, "uidrange")?,
    })
}

fn parse_port_range(value: &str) -> Result<RulePortRange, CliError> {
    let (start, end) = value
        .split_once('-')
        .map_or((value, value), |(start, end)| (start, end));
    Ok(RulePortRange {
        start: parse_number(start, "port")?,
        end: parse_number(end, "port")?,
    })
}

fn parse_ip_protocol(value: &str) -> Result<u8, CliError> {
    let known = match value.to_ascii_lowercase().as_str() {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "icmpv6" => Some(58),
        "gre" => Some(47),
        "esp" => Some(50),
        "ah" => Some(51),
        "sctp" => Some(132),
        _ => None,
    };
    known.map_or_else(|| parse_number(value, "ipproto"), Ok)
}

fn parse_u8(value: &str, option: &str) -> Result<u8, CliError> {
    parse_number(value, option)
}

fn parse_u32(value: &str, option: &str) -> Result<u32, CliError> {
    parse_number(value, option)
}

fn parse_number<T>(value: &str, option: &str) -> Result<T, CliError>
where
    T: TryFrom<u64>,
{
    let radix = if value.starts_with("0x") { 16 } else { 10 };
    let digits = value.strip_prefix("0x").unwrap_or(value);
    let parsed = u64::from_str_radix(digits, radix)
        .map_err(|_| format!("invalid {option} value: {value}"))?;
    T::try_from(parsed)
        .map_err(|_| format!("{option} value is out of range: {value}").into())
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a str>,
    option: &str,
) -> Result<String, CliError> {
    iter.next().map(str::to_owned).ok_or_else(|| {
        format!("ip rule option `{option}` requires a value").into()
    })
}

const RULE_HELP: &str = "Usage: ip rule { show | add | delete | flush } [ SELECTOR ]\n\nSelectors: from PREFIX, to PREFIX, tos TOS, fwmark MARK[/MASK], iif NAME, oif NAME, priority NUMBER, uidrange START-END, ipproto PROTOCOL, sport PORT[-PORT], dport PORT[-PORT], l3mdev\nActions: table TABLE, blackhole, unreachable, prohibit, goto NUMBER\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_rule_spec() {
        let spec = RuleSpec::parse(
            &[
                "from",
                "192.0.2.0/24",
                "fwmark",
                "0x10/0xff",
                "table",
                "100",
                "priority",
                "1000",
            ],
            None,
        )
        .unwrap();
        assert_eq!(spec.family, Some(AddressFamily::Inet));
        assert_eq!(spec.table, Some(100));
        assert_eq!(spec.fwmark, Some(16));
        assert_eq!(spec.fwmask, Some(255));
        assert_eq!(spec.priority, Some(1000));
        let message = spec.message().unwrap();
        assert_eq!(message.header.family, AddressFamily::Inet);
        assert_eq!(message.header.src_len, 24);
    }

    #[test]
    fn formats_special_tables() {
        assert_eq!(table_name(255), "local");
        assert_eq!(table_name(254), "main");
        assert_eq!(table_name(253), "default");
    }

    #[test]
    fn parses_ipv6_prefix_and_ports() {
        let spec = RuleSpec::parse(
            &["to", "2001:db8::/32", "sport", "443-8443", "blackhole"],
            None,
        )
        .unwrap();
        assert_eq!(spec.family, Some(AddressFamily::Inet6));
        assert_eq!(
            spec.sport,
            Some(RulePortRange {
                start: 443,
                end: 8443
            })
        );
        assert_eq!(spec.action, RuleAction::Blackhole);
    }

    #[test]
    fn renders_rule_text() {
        let info = CliRuleInfo {
            family: "inet".into(),
            priority: Some(100),
            from: "all".into(),
            to: "all".into(),
            tos: 0,
            table: 254,
            action: "lookup".into(),
            iif: None,
            oif: None,
            fwmark: None,
            fwmask: None,
            uidrange: None,
            ipproto: None,
            sport: None,
            dport: None,
            protocol: None,
            suppress_prefixlength: None,
            suppress_ifgroup: None,
            tun_id: None,
            goto: None,
            l3mdev: None,
            invert: false,
        };
        assert_eq!(info.to_string(), "100: from all to all lookup main");
    }
}
