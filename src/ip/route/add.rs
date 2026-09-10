// SPDX-License-Identifier: MIT

//! Parser and typed configuration model for route mutations.
//!
//! The parser accepts the compatibility-oriented `ip route` node syntax and
//! leaves interface-name resolution to the asynchronous modify path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_util::TryStreamExt;
use rtnetlink::{
    packet_core::DefaultNla,
    packet_route::{
        AddressFamily,
        route::{
            MplsLabel, RouteMetric, RouteMplsTtlPropagation, RouteNextHopFlags,
            RouteProtocol, RouteRealm, RouteScope, RouteType, Seg6Mode,
        },
    },
};

use crate::CliError;

pub(crate) struct RouteAddConfig {
    pub(crate) dst: Option<IpAddr>,
    pub(crate) dst_len: u8,
    pub(crate) src: Option<IpAddr>,
    pub(crate) src_len: u8,
    pub(crate) via: Option<IpAddr>,
    pub(crate) dev: Option<String>,
    pub(crate) table: Option<u32>,
    pub(crate) protocol: Option<RouteProtocol>,
    pub(crate) scope: Option<RouteScope>,
    pub(crate) kind: Option<RouteType>,
    pub(crate) metric: Option<u32>,
    pub(crate) prefsrc: Option<IpAddr>,
    pub(crate) onlink: bool,
    pub(crate) expires: Option<u32>,
    pub(crate) mark: Option<u32>,
    pub(crate) uid: Option<u32>,
    pub(crate) preference: Option<u8>,
    /// Type-of-service selector stored in the route header.
    pub(crate) tos: Option<u8>,
    /// MPLS TTL propagation policy carried by `RTA_TTL_PROPAGATE`.
    pub(crate) ttl_propagate: Option<RouteMplsTtlPropagation>,
    /// Shared nexthop ID, when the route refers to a kernel nexthop object.
    pub(crate) nhid: Option<u32>,
    /// Flow dissector attributes used by `ip route get` and policy routes.
    pub(crate) ip_proto: Option<u8>,
    pub(crate) sport: Option<u16>,
    pub(crate) dport: Option<u16>,
    pub(crate) flowlabel: Option<u32>,
    /// Route-level `pervasive` flag.
    pub(crate) pervasive: bool,
    /// Inline multipath entries from repeated `nexthop` clauses.
    pub(crate) nexthops: Vec<RouteNextHopConfig>,
    /// Supported lightweight tunnel encapsulation attributes.
    pub(crate) encap: Option<RouteEncapConfig>,
    pub(crate) family: Option<AddressFamily>,
    pub(crate) metrics: Vec<RouteMetric>,
    pub(crate) realm: Option<RouteRealm>,
}

/// One inline `nexthop` clause in a multipath route.
#[derive(Debug, Default)]
pub(crate) struct RouteNextHopConfig {
    pub(crate) via: Option<IpAddr>,
    pub(crate) dev: Option<String>,
    /// Kernel stores weight minus one in `rtnexthop::rtnh_hops`.
    pub(crate) weight: Option<u8>,
    pub(crate) flags: RouteNextHopFlags,
}

/// Encapsulation forms whose wire representation is available in
/// `netlink-packet-route`.
#[derive(Debug, Clone)]
pub(crate) enum RouteEncapConfig {
    /// MPLS labels carried by an IPv4/IPv6 route.
    Mpls {
        labels: Vec<MplsLabel>,
        ttl: Option<u8>,
    },
    /// Segment-routing IPv6 header.
    Seg6 {
        mode: Seg6Mode,
        segments: Vec<Ipv6Addr>,
    },
    /// IPv6 tunnel metadata used by the lightweight tunnel family.
    Ip6 {
        id: Option<u64>,
        destination: Option<Ipv6Addr>,
        source: Option<Ipv6Addr>,
        hoplimit: Option<u8>,
        traffic_class: Option<u8>,
        /// Raw `LWTUNNEL_IP6_FLAGS` bits; the packet crate keeps this type
        /// private, so they are encoded as a two-byte big-endian NLA.
        flags: u16,
    },
}

pub(crate) fn parse_route_config(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<RouteAddConfig, CliError> {
    let mut dst: Option<IpAddr> = None;
    let mut dst_len: u8 = 0;
    let mut src: Option<IpAddr> = None;
    let mut src_len: u8 = 0;
    let mut via: Option<IpAddr> = None;
    let mut dev: Option<String> = None;
    let mut table: Option<u32> = None;
    let mut protocol: Option<RouteProtocol> = None;
    let mut scope: Option<RouteScope> = None;
    let mut kind: Option<RouteType> = None;
    let mut metric: Option<u32> = None;
    let mut prefsrc: Option<IpAddr> = None;
    let mut onlink = false;
    let mut expires: Option<u32> = None;
    let mut mark: Option<u32> = None;
    let mut uid: Option<u32> = None;
    let mut preference: Option<u8> = None;
    let mut tos: Option<u8> = None;
    let mut ttl_propagate: Option<RouteMplsTtlPropagation> = None;
    let mut nhid: Option<u32> = None;
    let mut ip_proto: Option<u8> = None;
    let mut sport: Option<u16> = None;
    let mut dport: Option<u16> = None;
    let mut flowlabel: Option<u32> = None;
    let mut pervasive = false;
    let mut nexthops = Vec::new();
    let mut encap = None;
    let mut family: Option<AddressFamily> = preferred_family;
    let mut metrics: Vec<RouteMetric> = Vec::new();
    let mut realm: Option<RouteRealm> = None;
    let mut positional_prefix_seen = false;

    let mut iter = opts.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "via" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"via\" requires a value")
                })?;
                let (addr, fam) = parse_via_address(val, family, &mut iter)?;
                via = Some(addr);
                family = fam.or(family).or(addr_to_family(&addr));
            }
            "dev" => {
                dev = Some(
                    iter.next()
                        .ok_or_else(|| {
                            CliError::from("\"dev\" requires a value")
                        })?
                        .clone(),
                );
            }
            "src" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"src\" requires a value")
                })?;
                let addr: IpAddr = val.parse().map_err(|_| {
                    CliError::from(format!("invalid source address: {val}"))
                })?;
                prefsrc = Some(addr);
            }
            "from" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"from\" requires a value")
                })?;
                let (addr, plen) = parse_prefix(val)?;
                src = Some(addr);
                src_len = plen;
                if family.is_none() {
                    family = addr_to_family(&addr);
                }
            }
            "to" => {
                let val = iter
                    .next()
                    .ok_or_else(|| CliError::from("\"to\" requires a value"))?;
                let (addr, plen) = parse_prefix(val)?;
                dst = Some(addr);
                dst_len = plen;
                positional_prefix_seen = true;
                if family.is_none() {
                    family = addr_to_family(&addr);
                }
            }
            "table" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"table\" requires a value")
                })?;
                table = Some(parse_table_id(val)?);
            }
            "proto" | "protocol" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"proto\" requires a value")
                })?;
                protocol = Some(parse_route_protocol(val)?);
            }
            "scope" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"scope\" requires a value")
                })?;
                scope = Some(parse_route_scope(val)?);
            }
            "type" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"type\" requires a value")
                })?;
                kind = Some(parse_route_type(val)?);
            }
            "tos" | "dsfield" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"tos\" requires a value")
                })?;
                let value = parse_u32_any_base(val)?;
                if value > u8::MAX as u32 {
                    return Err(CliError::from(format!(
                        "invalid tos value: {val}"
                    )));
                }
                tos = Some(value as u8);
            }
            "metric" | "priority" | "preference" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"metric\" requires a value")
                })?;
                metric = Some(val.parse::<u32>().map_err(|_| {
                    CliError::from(format!("invalid metric value: {val}"))
                })?);
            }
            "onlink" => onlink = true,
            "pervasive" => pervasive = true,
            "ttl-propagate" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from(
                        "\"ttl-propagate\" requires enabled or disabled",
                    )
                })?;
                ttl_propagate = Some(parse_ttl_propagation(val)?);
            }
            "nhid" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"nhid\" requires a value")
                })?;
                nhid = Some(parse_u32_any_base(val)?);
            }
            "ipproto" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"ipproto\" requires a value")
                })?;
                ip_proto = Some(parse_ip_protocol(val)?);
            }
            "sport" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"sport\" requires a value")
                })?;
                sport = Some(parse_u16_any_base(val, "sport")?);
            }
            "dport" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"dport\" requires a value")
                })?;
                dport = Some(parse_u16_any_base(val, "dport")?);
            }
            "flowlabel" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"flowlabel\" requires a value")
                })?;
                flowlabel = Some(parse_u32_any_base(val)?);
            }
            "nexthop" => {
                let (nexthop, nexthop_family) =
                    parse_route_nexthop(&mut iter, family)?;
                family = nexthop_family.or(family);
                nexthops.push(nexthop);
            }
            "encap" => {
                let kind = iter.next().ok_or_else(|| {
                    CliError::from("\"encap\" requires a type")
                })?;
                encap = Some(parse_route_encap(&mut iter, kind)?);
            }
            "expires" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"expires\" requires a value")
                })?;
                expires = Some(parse_time_seconds(val)?);
            }
            "mark" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"mark\" requires a value")
                })?;
                mark = Some(parse_mark_value(val)?);
            }
            "uid" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"uid\" requires a value")
                })?;
                uid = Some(val.parse::<u32>().map_err(|_| {
                    CliError::from(format!("invalid uid value: {val}"))
                })?);
            }
            "pref" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"pref\" requires a value")
                })?;
                preference = Some(match val.as_str() {
                    "low" => 0x3,
                    "medium" => 0x0,
                    "high" => 0x1,
                    _ => {
                        return Err(CliError::from(format!(
                            "invalid preference: {val}"
                        )));
                    }
                });
            }
            "mtu" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"mtu\" requires a value")
                })?;
                metrics.push(RouteMetric::Mtu(parse_u32_any_base(val)?));
            }
            "advmss" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"advmss\" requires a value")
                })?;
                metrics.push(RouteMetric::Advmss(parse_u32_any_base(val)?));
            }
            "rtt" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"rtt\" requires a value")
                })?;
                let (value, raw) = parse_time_rtt(val)?;
                let value = if raw {
                    value
                } else {
                    value.checked_mul(8).ok_or_else(|| {
                        CliError::from(format!("invalid rtt value: {val}"))
                    })?
                };
                metrics.push(RouteMetric::Rtt(value));
            }
            "rttvar" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"rttvar\" requires a value")
                })?;
                let (value, raw) = parse_time_rtt(val)?;
                let value = if raw {
                    value
                } else {
                    value.checked_mul(4).ok_or_else(|| {
                        CliError::from(format!("invalid rttvar value: {val}"))
                    })?
                };
                metrics.push(RouteMetric::RttVar(value));
            }
            "reordering" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"reordering\" requires a value")
                })?;
                metrics.push(RouteMetric::Reordering(parse_u32_any_base(val)?));
            }
            "window" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"window\" requires a value")
                })?;
                metrics.push(RouteMetric::Window(parse_u32_any_base(val)?));
            }
            "cwnd" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"cwnd\" requires a value")
                })?;
                metrics.push(RouteMetric::Cwnd(parse_u32_any_base(val)?));
            }
            "initcwnd" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"initcwnd\" requires a value")
                })?;
                metrics.push(RouteMetric::InitCwnd(parse_u32_any_base(val)?));
            }
            "initrwnd" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"initrwnd\" requires a value")
                })?;
                metrics.push(RouteMetric::InitRwnd(parse_u32_any_base(val)?));
            }
            "ssthresh" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"ssthresh\" requires a value")
                })?;
                metrics.push(RouteMetric::SsThresh(parse_u32_any_base(val)?));
            }
            "hoplimit" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"hoplimit\" requires a value")
                })?;
                let value = parse_u32_any_base(val)?;
                if value > 255 {
                    return Err(CliError::from(format!(
                        "invalid hoplimit value: {val}"
                    )));
                }
                metrics.push(RouteMetric::Hoplimit(value));
            }
            "rto_min" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"rto_min\" requires a value")
                })?;
                let (value, _) = parse_time_rtt(val)?;
                metrics.push(RouteMetric::RtoMin(value));
            }
            "features" => {
                let mut features = 0u32;
                let mut count = 0u32;
                while let Some(feature) = iter.peek() {
                    let bit = match feature.as_str() {
                        "ecn" => 1,
                        "tcp_usec_ts" => 16,
                        _ => break,
                    };
                    features |= bit;
                    count += 1;
                    iter.next();
                }
                if count == 0 {
                    return Err(CliError::from(
                        "\"features\" requires at least one feature",
                    ));
                }
                metrics.push(RouteMetric::Features(features));
            }
            "quickack" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"quickack\" requires a value")
                })?;
                let value = parse_u32_any_base(val)?;
                if value > 1 {
                    return Err(CliError::from(
                        "\"quickack\" value should be 0 or 1",
                    ));
                }
                metrics.push(RouteMetric::QuickAck(value));
            }
            "congctl" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"congctl\" requires a value")
                })?;
                // netlink-packet-route's `CcAlgo` variant currently models
                // RTAX_CC_ALGO as u32; emit the string payload via `Other`
                // until that crate is fixed.
                metrics.push(RouteMetric::Other(DefaultNla::new(
                    16,
                    val.as_bytes().to_vec(),
                )));
            }
            "fastopen_no_cookie" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"fastopen_no_cookie\" requires a value")
                })?;
                let value = parse_u32_any_base(val)?;
                if value > 1 {
                    return Err(CliError::from(
                        "\"fastopen_no_cookie\" value should be 0 or 1",
                    ));
                }
                metrics.push(RouteMetric::FastopenNoCookie(value));
            }
            "realms" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"realms\" requires a value")
                })?;
                realm = Some(parse_realm(val)?);
            }
            "as" => {
                return Err(CliError::from(format!("invalid argument: {arg}")));
            }
            _ => {
                if !positional_prefix_seen {
                    if let Ok(rt) = parse_route_type(arg) {
                        kind = Some(rt);
                    } else {
                        let (addr, plen) = parse_prefix(arg)?;
                        dst = Some(addr);
                        dst_len = plen;
                        positional_prefix_seen = true;
                        if family.is_none() {
                            family = addr_to_family(&addr);
                        }
                    }
                } else {
                    return Err(CliError::from(format!(
                        "unexpected argument: {arg}"
                    )));
                }
            }
        }
    }

    if family.is_none() {
        family = Some(AddressFamily::Inet);
    }

    Ok(RouteAddConfig {
        dst,
        dst_len,
        src,
        src_len,
        via,
        dev,
        table,
        protocol,
        scope,
        kind,
        metric,
        prefsrc,
        onlink,
        expires,
        mark,
        uid,
        preference,
        tos,
        ttl_propagate,
        nhid,
        ip_proto,
        sport,
        dport,
        flowlabel,
        pervasive,
        nexthops,
        encap,
        family,
        metrics,
        realm,
    })
}

/// Parse one `nexthop` clause until the next route-level option or nexthop.
fn parse_route_nexthop<'a, I>(
    iter: &mut std::iter::Peekable<I>,
    current_family: Option<AddressFamily>,
) -> Result<(RouteNextHopConfig, Option<AddressFamily>), CliError>
where
    I: Iterator<Item = &'a String>,
{
    let mut config = RouteNextHopConfig::default();
    let mut family = current_family;

    while let Some(arg) = iter.peek() {
        if is_route_level_option(arg) || *arg == "nexthop" {
            break;
        }
        let arg = iter.next().expect("peeked nexthop option");
        match arg.as_str() {
            "via" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("nexthop \"via\" requires an address")
                })?;
                let (addr, via_family) = parse_via_address(val, family, iter)?;
                config.via = Some(addr);
                family = via_family.or(family).or(addr_to_family(&addr));
            }
            "dev" => {
                config.dev = Some(
                    iter.next()
                        .ok_or_else(|| {
                            CliError::from("nexthop \"dev\" requires a value")
                        })?
                        .clone(),
                );
            }
            "weight" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("nexthop \"weight\" requires a value")
                })?;
                let value = parse_u32_any_base(val)?;
                if !(1..=256).contains(&value) {
                    return Err(CliError::from(format!(
                        "nexthop weight must be between 1 and 256: {val}"
                    )));
                }
                config.weight = Some((value - 1) as u8);
            }
            "onlink" => config.flags.insert(RouteNextHopFlags::Onlink),
            "pervasive" => {
                config.flags.insert(RouteNextHopFlags::Pervasive);
            }
            "nhflags" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("nexthop \"nhflags\" requires a value")
                })?;
                config.flags |= parse_nexthop_flags(val)?;
            }
            other => {
                return Err(CliError::from(format!(
                    "unexpected nexthop option: {other}"
                )));
            }
        }
    }

    if config.via.is_none() && config.dev.is_none() {
        return Err(CliError::from(
            "nexthop requires at least a via address or dev",
        ));
    }
    Ok((config, family))
}

fn is_route_level_option(arg: &str) -> bool {
    matches!(
        arg,
        "src"
            | "from"
            | "to"
            | "table"
            | "proto"
            | "protocol"
            | "scope"
            | "type"
            | "tos"
            | "dsfield"
            | "metric"
            | "priority"
            | "preference"
            | "ttl-propagate"
            | "nhid"
            | "ipproto"
            | "sport"
            | "dport"
            | "flowlabel"
            | "expires"
            | "mark"
            | "uid"
            | "pref"
            | "mtu"
            | "advmss"
            | "rtt"
            | "rttvar"
            | "reordering"
            | "window"
            | "cwnd"
            | "initcwnd"
            | "initrwnd"
            | "ssthresh"
            | "hoplimit"
            | "rto_min"
            | "features"
            | "quickack"
            | "congctl"
            | "fastopen_no_cookie"
            | "realms"
            | "encap"
    )
}

/// Parse the common, typed subset of `ip route ... encap`.
fn parse_route_encap<'a, I>(
    iter: &mut std::iter::Peekable<I>,
    kind: &str,
) -> Result<RouteEncapConfig, CliError>
where
    I: Iterator<Item = &'a String>,
{
    match kind {
        "mpls" => {
            let labels = iter.next().ok_or_else(|| {
                CliError::from("\"encap mpls\" requires a label stack")
            })?;
            let labels = parse_mpls_labels(labels)?;
            let ttl = if iter.peek().is_some_and(|value| *value == "ttl") {
                iter.next();
                Some(parse_u8_any_base(
                    iter.next().ok_or_else(|| {
                        CliError::from("\"encap mpls ttl\" requires a value")
                    })?,
                    "MPLS TTL",
                )?)
            } else {
                None
            };
            Ok(RouteEncapConfig::Mpls { labels, ttl })
        }
        "seg6" => {
            let mut mode = Seg6Mode::Encap;
            let mut segments = None;
            while let Some(value) = iter.peek() {
                match value.as_str() {
                    "mode" => {
                        iter.next();
                        let value = iter.next().ok_or_else(|| {
                            CliError::from(
                                "\"encap seg6 mode\" requires inline or encap",
                            )
                        })?;
                        mode = match value.as_str() {
                            "inline" => Seg6Mode::Inline,
                            "encap" => Seg6Mode::Encap,
                            value => {
                                return Err(CliError::from(format!(
                                    "invalid seg6 mode: {value}"
                                )));
                            }
                        };
                    }
                    "segs" | "segments" => {
                        iter.next();
                        let value = iter.next().ok_or_else(|| {
                            CliError::from(
                                "\"encap seg6 segs\" requires IPv6 segments",
                            )
                        })?;
                        segments = Some(parse_ipv6_segments(value)?);
                    }
                    _ => break,
                }
            }
            let segments = segments.ok_or_else(|| {
                CliError::from("\"encap seg6\" requires a segs list")
            })?;
            Ok(RouteEncapConfig::Seg6 { mode, segments })
        }
        "ip6" => {
            let mut id = None;
            let mut destination = None;
            let mut source = None;
            let mut hoplimit = None;
            let mut traffic_class = None;
            let mut flags = 0u16;
            while let Some(value) = iter.peek() {
                match value.as_str() {
                    "id" => {
                        iter.next();
                        id = Some(parse_u64_any_base(
                            iter.next().ok_or_else(|| {
                                CliError::from(
                                    "\"encap ip6 id\" requires a value",
                                )
                            })?,
                        )?);
                    }
                    "dst" | "destination" => {
                        iter.next();
                        destination = Some(parse_ipv6_encap_address(
                            iter.next().ok_or_else(|| {
                                CliError::from(
                                    "\"encap ip6 dst\" requires an address",
                                )
                            })?,
                            "destination",
                        )?);
                    }
                    "src" | "source" => {
                        iter.next();
                        source = Some(parse_ipv6_encap_address(
                            iter.next().ok_or_else(|| {
                                CliError::from(
                                    "\"encap ip6 src\" requires an address",
                                )
                            })?,
                            "source",
                        )?);
                    }
                    "hoplimit" | "hlim" => {
                        iter.next();
                        hoplimit = Some(parse_u8_any_base(
                            iter.next().ok_or_else(|| {
                                CliError::from(
                                    "\"encap ip6 hoplimit\" requires a value",
                                )
                            })?,
                            "IPv6 hoplimit",
                        )?);
                    }
                    "tc" => {
                        iter.next();
                        traffic_class = Some(parse_u8_any_base(
                            iter.next().ok_or_else(|| {
                                CliError::from(
                                    "\"encap ip6 tc\" requires a value",
                                )
                            })?,
                            "IPv6 traffic class",
                        )?);
                    }
                    "key" => {
                        iter.next();
                        flags |= 1 << 2;
                    }
                    "csum" => {
                        iter.next();
                        flags |= 1;
                    }
                    "seq" => {
                        iter.next();
                        flags |= 1 << 3;
                    }
                    _ => break,
                }
            }
            if destination.is_none() && source.is_none() && id.is_none() {
                return Err(CliError::from(
                    "\"encap ip6\" requires id, dst, or src",
                ));
            }
            Ok(RouteEncapConfig::Ip6 {
                id,
                destination,
                source,
                hoplimit,
                traffic_class,
                flags,
            })
        }
        other => Err(CliError::from(format!(
            "route encapsulation '{other}' is not supported yet; supported types are mpls, seg6, and ip6"
        ))),
    }
}

fn parse_mpls_labels(value: &str) -> Result<Vec<MplsLabel>, CliError> {
    let parts = value.split(['/', ',']).collect::<Vec<_>>();
    if parts.is_empty() || parts.iter().any(|part| part.is_empty()) {
        return Err(CliError::from(format!(
            "invalid MPLS label stack: {value}"
        )));
    }
    parts
        .iter()
        .enumerate()
        .map(|(index, part)| {
            let fields = part.split(':').collect::<Vec<_>>();
            let label = parse_u32_any_base(fields[0])?;
            if label > 0xF_FFFF {
                return Err(CliError::from(format!(
                    "MPLS label is out of range: {label}"
                )));
            }
            let traffic_class = fields
                .get(1)
                .map(|value| parse_u8_any_base(value, "MPLS traffic class"))
                .transpose()?
                .unwrap_or(0);
            if traffic_class > 7 {
                return Err(CliError::from(format!(
                    "MPLS traffic class is out of range: {traffic_class}"
                )));
            }
            let bottom_of_stack =
                fields.get(2).map_or(index + 1 == parts.len(), |value| {
                    matches!(*value, "1" | "yes" | "true" | "S" | "s")
                });
            let ttl = fields
                .get(3)
                .map(|value| parse_u8_any_base(value, "MPLS TTL"))
                .transpose()?
                .unwrap_or(0);
            Ok(MplsLabel {
                label,
                traffic_class,
                bottom_of_stack,
                ttl,
            })
        })
        .collect()
}

fn parse_ipv6_segments(value: &str) -> Result<Vec<Ipv6Addr>, CliError> {
    value
        .split(',')
        .map(|segment| {
            segment.parse::<Ipv6Addr>().map_err(|_| {
                CliError::from(format!("invalid IPv6 segment: {segment}"))
            })
        })
        .collect()
}

fn parse_ipv6_encap_address(
    value: &str,
    name: &str,
) -> Result<Ipv6Addr, CliError> {
    value.parse::<Ipv6Addr>().map_err(|_| {
        CliError::from(format!("invalid IPv6 {name} address: {value}"))
    })
}

fn parse_u8_any_base(value: &str, name: &str) -> Result<u8, CliError> {
    let number = parse_u32_any_base(value)?;
    u8::try_from(number)
        .map_err(|_| CliError::from(format!("invalid {name}: {value}")))
}

fn parse_u64_any_base(value: &str) -> Result<u64, CliError> {
    let (radix, digits) = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (16, hex)
    } else if value.len() > 1 && value.starts_with('0') {
        (8, &value[1..])
    } else {
        (10, value)
    };
    u64::from_str_radix(digits, radix)
        .map_err(|_| CliError::from(format!("invalid number: {value}")))
}

fn parse_ttl_propagation(
    value: &str,
) -> Result<RouteMplsTtlPropagation, CliError> {
    match value {
        "enabled" | "enable" | "on" | "1" => {
            Ok(RouteMplsTtlPropagation::Enabled)
        }
        "disabled" | "disable" | "off" | "0" => {
            Ok(RouteMplsTtlPropagation::Disabled)
        }
        "default" => Ok(RouteMplsTtlPropagation::Default),
        _ => Err(CliError::from(format!(
            "invalid ttl-propagate value: {value}"
        ))),
    }
}

fn parse_nexthop_flags(value: &str) -> Result<RouteNextHopFlags, CliError> {
    let mut flags = RouteNextHopFlags::empty();
    for flag in value.split([',', '/']) {
        let bit = match flag {
            "dead" => RouteNextHopFlags::Dead,
            "pervasive" => RouteNextHopFlags::Pervasive,
            "onlink" => RouteNextHopFlags::Onlink,
            "offload" => RouteNextHopFlags::Offload,
            "linkdown" => RouteNextHopFlags::Linkdown,
            "unresolved" => RouteNextHopFlags::Unresolved,
            "trap" => RouteNextHopFlags::Trap,
            _ => {
                return Err(CliError::from(format!(
                    "invalid nexthop flag: {flag}"
                )));
            }
        };
        flags.insert(bit);
    }
    Ok(flags)
}

fn parse_ip_protocol(value: &str) -> Result<u8, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "sctp" => Ok(132),
        "icmp" => Ok(1),
        "icmpv6" => Ok(58),
        _ => value.parse::<u8>().map_err(|_| {
            CliError::from(format!("invalid ipproto value: {value}"))
        }),
    }
}

fn parse_u16_any_base(value: &str, name: &str) -> Result<u16, CliError> {
    let parsed = parse_u32_any_base(value)?;
    u16::try_from(parsed)
        .map_err(|_| CliError::from(format!("invalid {name} value: {value}")))
}

fn parse_u32_any_base(s: &str) -> Result<u32, CliError> {
    let (radix, digits) = if let Some(hex) =
        s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
    {
        (16, hex)
    } else if s.len() > 1 && s.starts_with('0') {
        (8, &s[1..])
    } else {
        (10, s)
    };
    u32::from_str_radix(digits, radix)
        .map_err(|_| CliError::from(format!("invalid number: {s}")))
}

fn parse_time_rtt(s: &str) -> Result<(u32, bool), CliError> {
    let lower = s.to_ascii_lowercase();
    let (num, multiplier, has_suffix) =
        if let Some(num) = lower.strip_suffix("msecs") {
            (num, 1.0, true)
        } else if let Some(num) = lower.strip_suffix("msec") {
            (num, 1.0, true)
        } else if let Some(num) = lower.strip_suffix("ms") {
            (num, 1.0, true)
        } else if let Some(num) = lower.strip_suffix("secs") {
            (num, 1000.0, true)
        } else if let Some(num) = lower.strip_suffix("sec") {
            (num, 1000.0, true)
        } else if let Some(num) = lower.strip_suffix("s") {
            (num, 1000.0, true)
        } else {
            (lower.as_str(), 1.0, false)
        };

    if num.is_empty() {
        return Err(CliError::from(format!("invalid time value: {s}")));
    }

    let value = if num.contains('.') {
        let t: f64 = num
            .parse()
            .map_err(|_| CliError::from(format!("invalid time value: {s}")))?;
        if t < 0.0 || !t.is_finite() {
            return Err(CliError::from(format!("invalid time value: {s}")));
        }
        t * multiplier
    } else {
        parse_u32_any_base(num)? as f64 * multiplier
    };

    if value > u32::MAX as f64 {
        return Err(CliError::from(format!("invalid time value: {s}")));
    }
    Ok((value.ceil() as u32, !has_suffix))
}

/// Parse a route lifetime into the kernel's integer-second representation.
///
/// `ip route` accepts a bare number of seconds as well as common suffixes.
/// Fractional values are rounded up so a non-zero lifetime is not silently
/// turned into an immediately expired route.
fn parse_time_seconds(s: &str) -> Result<u32, CliError> {
    let lower = s.to_ascii_lowercase();
    let (num, multiplier) = if let Some(num) = lower.strip_suffix("msecs") {
        (num, 0.001)
    } else if let Some(num) = lower.strip_suffix("msec") {
        (num, 0.001)
    } else if let Some(num) = lower.strip_suffix("ms") {
        (num, 0.001)
    } else if let Some(num) = lower.strip_suffix("minutes") {
        (num, 60.0)
    } else if let Some(num) = lower.strip_suffix("minute") {
        (num, 60.0)
    } else if let Some(num) = lower.strip_suffix("mins") {
        (num, 60.0)
    } else if let Some(num) = lower.strip_suffix("min") {
        (num, 60.0)
    } else if let Some(num) = lower.strip_suffix("hours") {
        (num, 3600.0)
    } else if let Some(num) = lower.strip_suffix("hour") {
        (num, 3600.0)
    } else if let Some(num) = lower.strip_suffix('h') {
        (num, 3600.0)
    } else if let Some(num) = lower.strip_suffix("days") {
        (num, 86_400.0)
    } else if let Some(num) = lower.strip_suffix("day") {
        (num, 86_400.0)
    } else if let Some(num) = lower.strip_suffix('d') {
        (num, 86_400.0)
    } else if let Some(num) = lower.strip_suffix("secs") {
        (num, 1.0)
    } else if let Some(num) = lower.strip_suffix("sec") {
        (num, 1.0)
    } else if let Some(num) = lower.strip_suffix('s') {
        (num, 1.0)
    } else {
        (lower.as_str(), 1.0)
    };

    if num.is_empty() {
        return Err(CliError::from(format!("invalid expires value: {s}")));
    }
    let value = if num.contains('.') {
        num.parse::<f64>().map_err(|_| {
            CliError::from(format!("invalid expires value: {s}"))
        })? * multiplier
    } else {
        parse_u32_any_base(num)? as f64 * multiplier
    };
    if value.is_sign_negative() || !value.is_finite() || value > u32::MAX as f64
    {
        return Err(CliError::from(format!("invalid expires value: {s}")));
    }
    Ok(value.ceil() as u32)
}

fn parse_realm(s: &str) -> Result<RouteRealm, CliError> {
    if let Some((from, to)) = s.split_once('/') {
        Ok(RouteRealm {
            source: parse_realm_component(from)?,
            destination: parse_realm_component(to)?,
        })
    } else {
        let value = parse_u32_any_base(s)?;
        Ok(RouteRealm {
            source: (value >> 16) as u16,
            destination: value as u16,
        })
    }
}

fn parse_realm_component(s: &str) -> Result<u16, CliError> {
    let value = parse_u32_any_base(s)?;
    if value > u16::MAX as u32 {
        return Err(CliError::from(format!("invalid realm value: {s}")));
    }
    Ok(value as u16)
}

fn addr_to_family(addr: &IpAddr) -> Option<AddressFamily> {
    match addr {
        IpAddr::V4(_) => Some(AddressFamily::Inet),
        IpAddr::V6(_) => Some(AddressFamily::Inet6),
    }
}

fn parse_via_address<'a>(
    s: &str,
    current_family: Option<AddressFamily>,
    iter: &mut std::iter::Peekable<impl Iterator<Item = &'a String>>,
) -> Result<(IpAddr, Option<AddressFamily>), CliError> {
    let result = match s {
        "inet" => {
            let addr = iter.next().ok_or_else(|| {
                CliError::from("\"via inet\" requires an address")
            })?;
            let v4: Ipv4Addr = addr.parse().map_err(|_| {
                CliError::from(format!("invalid IPv4 via address: {addr}"))
            })?;
            (IpAddr::V4(v4), Some(AddressFamily::Inet))
        }
        "inet6" => {
            let addr = iter.next().ok_or_else(|| {
                CliError::from("\"via inet6\" requires an address")
            })?;
            let v6: Ipv6Addr = addr.parse().map_err(|_| {
                CliError::from(format!("invalid IPv6 via address: {addr}"))
            })?;
            (IpAddr::V6(v6), Some(AddressFamily::Inet6))
        }
        _ => {
            let addr: IpAddr = s.parse().map_err(|_| {
                CliError::from(format!("invalid via address: {s}"))
            })?;
            let fam = addr_to_family(&addr);
            if let Some(cf) = current_family
                && fam != Some(cf)
            {
                // Address family differs from route family -
                // will use RTA_VIA instead of RTA_GATEWAY
            }
            (addr, fam)
        }
    };
    Ok(result)
}

fn parse_prefix(s: &str) -> Result<(IpAddr, u8), CliError> {
    if let Some((addr_str, plen_str)) = s.split_once('/') {
        let addr: IpAddr = addr_str.parse().map_err(|_| {
            CliError::from(format!("invalid address: {addr_str}"))
        })?;
        let plen = plen_str.parse::<u8>().map_err(|_| {
            CliError::from(format!("invalid prefix length: {plen_str}"))
        })?;
        Ok((addr, plen))
    } else {
        let addr: IpAddr = s
            .parse()
            .map_err(|_| CliError::from(format!("invalid address: {s}")))?;
        let plen = if addr.is_ipv4() { 32 } else { 128 };
        Ok((addr, plen))
    }
}

fn parse_table_id(s: &str) -> Result<u32, CliError> {
    match s {
        "local" => Ok(255),
        "main" => Ok(254),
        "default" => Ok(253),
        "all" => Ok(0),
        v => v
            .parse::<u32>()
            .map_err(|_| CliError::from(format!("invalid table ID: {v}"))),
    }
}

fn parse_route_protocol(s: &str) -> Result<RouteProtocol, CliError> {
    match s {
        "unspec" => Ok(RouteProtocol::Unspec),
        "redirect" => Ok(RouteProtocol::IcmpRedirect),
        "kernel" => Ok(RouteProtocol::Kernel),
        "boot" => Ok(RouteProtocol::Boot),
        "static" => Ok(RouteProtocol::Static),
        "gated" => Ok(RouteProtocol::Gated),
        "ra" => Ok(RouteProtocol::Ra),
        "mrt" => Ok(RouteProtocol::Mrt),
        "zebra" => Ok(RouteProtocol::Zebra),
        "bird" => Ok(RouteProtocol::Bird),
        "dnrouted" => Ok(RouteProtocol::DnRouted),
        "xorp" => Ok(RouteProtocol::Xorp),
        "ntk" => Ok(RouteProtocol::Ntk),
        "dhcp" => Ok(RouteProtocol::Dhcp),
        "mrouted" => Ok(RouteProtocol::Mrouted),
        "keepalived" => Ok(RouteProtocol::KeepAlived),
        "babel" => Ok(RouteProtocol::Babel),
        "bgp" => Ok(RouteProtocol::Bgp),
        "isis" => Ok(RouteProtocol::Isis),
        "ospf" => Ok(RouteProtocol::Ospf),
        "rip" => Ok(RouteProtocol::Rip),
        "eigrp" => Ok(RouteProtocol::Eigrp),
        v => {
            let num = v.parse::<u8>().map_err(|_| {
                CliError::from(format!("invalid protocol: {v}"))
            })?;
            Ok(RouteProtocol::from(num))
        }
    }
}

fn parse_route_scope(s: &str) -> Result<RouteScope, CliError> {
    match s {
        "global" | "universe" => Ok(RouteScope::Universe),
        "site" => Ok(RouteScope::Site),
        "link" => Ok(RouteScope::Link),
        "host" => Ok(RouteScope::Host),
        "nowhere" => Ok(RouteScope::NoWhere),
        v => {
            let num = v
                .parse::<u8>()
                .map_err(|_| CliError::from(format!("invalid scope: {v}")))?;
            Ok(RouteScope::from(num))
        }
    }
}

fn parse_route_type(s: &str) -> Result<RouteType, CliError> {
    match s {
        "unspec" => Ok(RouteType::Unspec),
        "unicast" => Ok(RouteType::Unicast),
        "local" => Ok(RouteType::Local),
        "broadcast" => Ok(RouteType::Broadcast),
        "anycast" => Ok(RouteType::Anycast),
        "multicast" => Ok(RouteType::Multicast),
        "blackhole" => Ok(RouteType::BlackHole),
        "unreachable" => Ok(RouteType::Unreachable),
        "prohibit" => Ok(RouteType::Prohibit),
        "throw" => Ok(RouteType::Throw),
        "nat" => Ok(RouteType::Nat),
        "xresolve" => Ok(RouteType::ExternalResolve),
        v => {
            let num = v.parse::<u8>().map_err(|_| {
                CliError::from(format!("invalid route type: {v}"))
            })?;
            Ok(RouteType::from(num))
        }
    }
}

fn parse_mark_value(s: &str) -> Result<u32, CliError> {
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
    {
        u32::from_str_radix(hex_str, 16)
            .map_err(|_| CliError::from(format!("invalid mark value: {s}")))
    } else {
        s.parse::<u32>()
            .map_err(|_| CliError::from(format!("invalid mark value: {s}")))
    }
}

pub(crate) async fn resolve_ifindex(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<u32, CliError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links.try_next().await?.ok_or_else(|| {
        CliError::from(format!("Device \"{name}\" does not exist"))
    })?;
    Ok(link.header.index)
}

#[cfg(test)]
mod tests {
    use rtnetlink::packet_route::route::RouteAttribute;

    use super::*;

    fn opts(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_parse_route_metric_options() {
        let config = parse_route_config(
            &opts(&[
                "10.0.0.0/8",
                "via",
                "192.0.2.1",
                "mtu",
                "1500",
                "advmss",
                "1400",
                "rtt",
                "100ms",
                "rttvar",
                "100ms",
                "reordering",
                "10",
                "window",
                "100",
                "cwnd",
                "10",
                "initcwnd",
                "10",
                "initrwnd",
                "10",
                "ssthresh",
                "100",
                "hoplimit",
                "64",
                "rto_min",
                "200ms",
                "features",
                "ecn",
                "tcp_usec_ts",
                "quickack",
                "1",
                "congctl",
                "cubic",
                "fastopen_no_cookie",
                "1",
                "realms",
                "10/20",
            ]),
            None,
        )
        .unwrap();

        assert_eq!(
            config.metrics,
            vec![
                RouteMetric::Mtu(1500),
                RouteMetric::Advmss(1400),
                RouteMetric::Rtt(800),
                RouteMetric::RttVar(400),
                RouteMetric::Reordering(10),
                RouteMetric::Window(100),
                RouteMetric::Cwnd(10),
                RouteMetric::InitCwnd(10),
                RouteMetric::InitRwnd(10),
                RouteMetric::SsThresh(100),
                RouteMetric::Hoplimit(64),
                RouteMetric::RtoMin(200),
                RouteMetric::Features(17),
                RouteMetric::QuickAck(1),
                RouteMetric::Other(DefaultNla::new(16, b"cubic".to_vec(),)),
                RouteMetric::FastopenNoCookie(1),
            ]
        );
        assert_eq!(
            config.realm,
            Some(RouteRealm {
                source: 10,
                destination: 20,
            })
        );
    }

    #[test]
    fn test_parse_route_time_metrics_raw() {
        let config = parse_route_config(
            &opts(&[
                "10.0.0.0/8",
                "rtt",
                "100",
                "rttvar",
                "50",
                "rto_min",
                "200",
            ]),
            None,
        )
        .unwrap();

        assert_eq!(
            config.metrics,
            vec![
                RouteMetric::Rtt(100),
                RouteMetric::RttVar(50),
                RouteMetric::RtoMin(200),
            ]
        );
    }

    #[test]
    fn test_parse_route_expiration_suffixes() {
        assert_eq!(parse_time_seconds("300").unwrap(), 300);
        assert_eq!(parse_time_seconds("300s").unwrap(), 300);
        assert_eq!(parse_time_seconds("1.5s").unwrap(), 2);
        assert_eq!(parse_time_seconds("2min").unwrap(), 120);
        assert_eq!(parse_time_seconds("500ms").unwrap(), 1);
    }

    #[test]
    fn test_parse_route_multipath_and_flow_selectors() {
        let config = parse_route_config(
            &opts(&[
                "203.0.113.0/24",
                "tos",
                "0x10",
                "ipproto",
                "tcp",
                "sport",
                "0x1234",
                "dport",
                "443",
                "flowlabel",
                "0xabc",
                "pervasive",
                "nexthop",
                "via",
                "192.0.2.1",
                "dev",
                "eth0",
                "weight",
                "1",
                "onlink",
                "nexthop",
                "dev",
                "eth1",
                "weight",
                "2",
                "nhflags",
                "pervasive",
            ]),
            None,
        )
        .unwrap();

        assert_eq!(config.tos, Some(0x10));
        assert_eq!(config.ip_proto, Some(6));
        assert_eq!(config.sport, Some(0x1234));
        assert_eq!(config.dport, Some(443));
        assert_eq!(config.flowlabel, Some(0xabc));
        assert!(config.pervasive);
        assert_eq!(config.nexthops.len(), 2);
        assert_eq!(config.nexthops[0].weight, Some(0));
        assert!(config.nexthops[0].flags.contains(RouteNextHopFlags::Onlink));
        assert_eq!(config.nexthops[1].weight, Some(1));
        assert!(
            config.nexthops[1]
                .flags
                .contains(RouteNextHopFlags::Pervasive)
        );

        let message =
            super::super::modify::build_route_message(&config).unwrap();
        assert!(
            message.header.flags.contains(
                rtnetlink::packet_route::route::RouteFlags::Pervasive
            )
        );
        assert!(message.attributes.iter().any(|attribute| matches!(
            attribute,
            RouteAttribute::MultiPath(next_hops) if next_hops.len() == 2
        )));
    }

    #[test]
    fn test_parse_route_encapsulation_forms() {
        let config = parse_route_config(
            &opts(&[
                "10.0.0.0/8",
                "encap",
                "mpls",
                "100:2:0:64/200",
                "ttl",
                "32",
                "dev",
                "eth0",
            ]),
            None,
        )
        .unwrap();
        let Some(RouteEncapConfig::Mpls { labels, ttl }) = config.encap else {
            panic!("expected MPLS encapsulation");
        };
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].label, 100);
        assert!(!labels[0].bottom_of_stack);
        assert!(labels[1].bottom_of_stack);
        assert_eq!(ttl, Some(32));

        let config = parse_route_config(
            &opts(&[
                "2001:db8::/64",
                "encap",
                "seg6",
                "mode",
                "inline",
                "segs",
                "2001:db8::1,2001:db8::2",
            ]),
            None,
        )
        .unwrap();
        assert!(matches!(
            config.encap.as_ref(),
            Some(RouteEncapConfig::Seg6 {
                mode: Seg6Mode::Inline,
                segments
            }) if segments.len() == 2
        ));
        let message =
            super::super::modify::build_route_message(&config).unwrap();
        assert!(message.attributes.iter().any(|attribute| matches!(
            attribute,
            RouteAttribute::EncapType(
                rtnetlink::packet_route::route::RouteLwEnCapType::Seg6
            )
        )));
    }

    #[test]
    fn test_parse_route_as_rejected() {
        let result = parse_route_config(
            &opts(&["10.0.0.0/8", "as", "to", "192.0.2.1"]),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_route_metric_message() {
        let config = parse_route_config(
            &opts(&["10.0.0.0/8", "mtu", "1500", "realms", "1/2"]),
            None,
        )
        .unwrap();
        let msg = super::super::modify::build_route_message(&config).unwrap();

        assert!(
            msg.attributes.contains(&RouteAttribute::Metrics(vec![
                RouteMetric::Mtu(1500)
            ]))
        );
        assert!(msg.attributes.contains(&RouteAttribute::Realm(RouteRealm {
            source: 1,
            destination: 2,
        })));
    }
}
