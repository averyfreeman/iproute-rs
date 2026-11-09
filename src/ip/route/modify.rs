// SPDX-License-Identifier: MIT

//! Construction and acknowledged submission of route-netlink mutations.

use std::net::IpAddr;

use futures_util::stream::StreamExt;
use rtnetlink::{
    packet_core::{
        NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE,
        NLM_F_REQUEST, NetlinkMessage,
    },
    packet_route::{
        AddressFamily, RouteNetlinkMessage,
        route::{
            RouteAddress, RouteAttribute, RouteIp6Tunnel, RouteLwEnCapType,
            RouteLwTunnelEncap, RouteMessage, RouteMplsIpTunnel, RouteNextHop,
            RoutePreference, RouteProtocol, RouteScope, RouteSeg6IpTunnel,
            RouteType, RouteVia, Seg6Header,
        },
    },
};

use super::add::{
    RouteAddConfig, RouteEncapConfig, parse_route_config, resolve_ifindex,
};
use crate::CliError;

enum RouteModifyOp {
    Add,
    Append,
    Change,
    Prepend,
    Replace,
}

async fn send_route_request(
    mut handle: rtnetlink::Handle,
    msg: RouteMessage,
    op: RouteModifyOp,
) -> Result<(), CliError> {
    let mut nl_msg = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
    nl_msg.header.flags = match op {
        RouteModifyOp::Add => {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE
        }
        RouteModifyOp::Append => {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_APPEND | NLM_F_CREATE
        }
        RouteModifyOp::Prepend => NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        RouteModifyOp::Change => NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE,
        RouteModifyOp::Replace => {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE | NLM_F_CREATE
        }
    };

    let mut response = handle
        .request(nl_msg)
        .map_err(|e| CliError::from(format!("{e}")))?;
    while let Some(msg) = response.next().await {
        if let rtnetlink::packet_core::NetlinkPayload::Error(err) = msg.payload
        {
            return Err(CliError::from(format!(
                "Received a netlink error message {err}"
            )));
        }
    }
    Ok(())
}

async fn handle_modify(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
    op: RouteModifyOp,
) -> Result<(), CliError> {
    let config = parse_route_config(opts, preferred_family)?;
    let mut msg = build_route_message(&config)?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    if let Some(ref dev) = config.dev {
        let index = resolve_ifindex(&handle, dev).await?;
        msg.attributes.push(RouteAttribute::Oif(index));
    }

    if !config.nexthops.is_empty()
        && let Some(RouteAttribute::MultiPath(nexthops)) = msg
            .attributes
            .iter_mut()
            .find(|attribute| matches!(attribute, RouteAttribute::MultiPath(_)))
    {
        for (nexthop, config_nexthop) in
            nexthops.iter_mut().zip(&config.nexthops)
        {
            if let Some(ref dev) = config_nexthop.dev {
                nexthop.interface_index = resolve_ifindex(&handle, dev).await?;
            }
        }
    }

    let need_onlink = config.onlink
        || (msg.header.scope == RouteScope::Link && config.via.is_some());
    if need_onlink {
        msg.header.flags |= rtnetlink::packet_route::route::RouteFlags::Onlink;
    }

    send_route_request(handle, msg, op).await
}

/// Build the nested multipath records before interface names are resolved.
///
/// `build_route_message` is intentionally synchronous so it can be unit
/// tested and reused by save/restore tooling. The asynchronous modify path
/// fills in each `interface_index` after it has queried the kernel for the
/// requested device name.
fn build_route_nexthops(config: &RouteAddConfig) -> Vec<RouteNextHop> {
    let family = config.family;
    config
        .nexthops
        .iter()
        .map(|config_nexthop| {
            let mut nexthop = RouteNextHop::default();
            nexthop.flags = config_nexthop.flags;
            nexthop.hops = config_nexthop.weight.unwrap_or(0);
            if let Some(addr) = config_nexthop.via {
                let use_via = matches!(
                    (family, addr),
                    (Some(AddressFamily::Inet), IpAddr::V6(_))
                        | (Some(AddressFamily::Inet6), IpAddr::V4(_))
                );
                let attribute = if use_via {
                    match addr {
                        IpAddr::V4(value) => {
                            RouteAttribute::Via(RouteVia::Inet(value))
                        }
                        IpAddr::V6(value) => {
                            RouteAttribute::Via(RouteVia::Inet6(value))
                        }
                    }
                } else {
                    match addr {
                        IpAddr::V4(value) => {
                            RouteAttribute::Gateway(RouteAddress::Inet(value))
                        }
                        IpAddr::V6(value) => {
                            RouteAttribute::Gateway(RouteAddress::Inet6(value))
                        }
                    }
                };
                nexthop.attributes.push(attribute);
            }
            nexthop
        })
        .collect()
}

pub(crate) fn build_route_message(
    config: &RouteAddConfig,
) -> Result<RouteMessage, CliError> {
    let mut msg = RouteMessage::default();

    let family = config.family.unwrap_or(AddressFamily::Inet);
    msg.header.address_family = family;

    msg.header.protocol = RouteProtocol::Boot;
    msg.header.scope = RouteScope::Universe;
    msg.header.kind = RouteType::Unicast;
    msg.header.table = 254;

    if let Some(proto) = config.protocol {
        msg.header.protocol = proto;
    }
    if let Some(scope) = config.scope {
        msg.header.scope = scope;
    }
    if let Some(kind) = config.kind {
        msg.header.kind = kind;
    }
    if let Some(table) = config.table {
        if table > 255 {
            msg.attributes.push(RouteAttribute::Table(table));
        } else {
            msg.header.table = table as u8;
        }
    }

    if let Some(tos) = config.tos {
        msg.header.tos = tos;
    }

    if let Some(ref addr) = config.dst {
        msg.header.destination_prefix_length = config.dst_len;
        let rta = match addr {
            IpAddr::V4(a) => {
                RouteAttribute::Destination(RouteAddress::Inet(*a))
            }
            IpAddr::V6(a) => {
                RouteAttribute::Destination(RouteAddress::Inet6(*a))
            }
        };
        msg.attributes.push(rta);
    }

    if let Some(ref addr) = config.src {
        msg.header.source_prefix_length = config.src_len;
        let rta = match addr {
            IpAddr::V4(a) => RouteAttribute::Source(RouteAddress::Inet(*a)),
            IpAddr::V6(a) => RouteAttribute::Source(RouteAddress::Inet6(*a)),
        };
        msg.attributes.push(rta);
    }

    if let Some(ref addr) = config.via {
        let use_via = matches!(
            (family, addr),
            (AddressFamily::Inet, IpAddr::V6(_))
                | (AddressFamily::Inet6, IpAddr::V4(_))
        );
        let rta = if use_via {
            match addr {
                IpAddr::V4(a) => RouteAttribute::Via(RouteVia::Inet(*a)),
                IpAddr::V6(a) => RouteAttribute::Via(RouteVia::Inet6(*a)),
            }
        } else {
            match addr {
                IpAddr::V4(a) => {
                    RouteAttribute::Gateway(RouteAddress::Inet(*a))
                }
                IpAddr::V6(a) => {
                    RouteAttribute::Gateway(RouteAddress::Inet6(*a))
                }
            }
        };
        msg.attributes.push(rta);
    }

    if let Some(ref addr) = config.prefsrc {
        let rta = match addr {
            IpAddr::V4(a) => RouteAttribute::PrefSource(RouteAddress::Inet(*a)),
            IpAddr::V6(a) => {
                RouteAttribute::PrefSource(RouteAddress::Inet6(*a))
            }
        };
        msg.attributes.push(rta);
    }

    if let Some(m) = config.metric {
        msg.attributes.push(RouteAttribute::Priority(m));
    }

    if !config.metrics.is_empty() {
        msg.attributes
            .push(RouteAttribute::Metrics(config.metrics.clone()));
    }

    if let Some(realm) = config.realm {
        msg.attributes.push(RouteAttribute::Realm(realm));
    }

    if let Some(e) = config.expires {
        msg.attributes.push(RouteAttribute::Expires(e));
    }

    #[cfg(not(target_os = "android"))]
    if let Some(m) = config.mark {
        msg.attributes.push(RouteAttribute::Mark(m));
    }

    if let Some(u) = config.uid {
        msg.attributes.push(RouteAttribute::Uid(u));
    }

    if let Some(p) = config.preference {
        msg.attributes
            .push(RouteAttribute::Preference(RoutePreference::from(p)));
    }

    if let Some(nhid) = config.nhid {
        msg.attributes.push(RouteAttribute::NhId(nhid));
    }
    if let Some(ip_proto) = config.ip_proto {
        msg.attributes.push(RouteAttribute::IpProto(ip_proto));
    }
    if let Some(sport) = config.sport {
        msg.attributes.push(RouteAttribute::Sport(sport));
    }
    if let Some(dport) = config.dport {
        msg.attributes.push(RouteAttribute::Dport(dport));
    }
    if let Some(flowlabel) = config.flowlabel {
        msg.attributes.push(RouteAttribute::Flowlabel(flowlabel));
    }
    if let Some(ttl_propagate) = config.ttl_propagate {
        msg.attributes
            .push(RouteAttribute::TtlPropagate(ttl_propagate));
    }
    if let Some(encap) = &config.encap {
        let (encap_type, attributes) = match encap {
            RouteEncapConfig::Mpls { labels, ttl } => {
                let mut attributes = vec![RouteLwTunnelEncap::Mpls(
                    RouteMplsIpTunnel::Destination(labels.clone()),
                )];
                if let Some(ttl) = ttl {
                    attributes.push(RouteLwTunnelEncap::Mpls(
                        RouteMplsIpTunnel::Ttl(*ttl),
                    ));
                }
                (RouteLwEnCapType::Mpls, attributes)
            }
            RouteEncapConfig::Seg6 { mode, segments } => {
                let mut header = Seg6Header::default();
                header.mode = *mode;
                header.segments = segments.clone();
                (
                    RouteLwEnCapType::Seg6,
                    vec![RouteLwTunnelEncap::Seg6(RouteSeg6IpTunnel::Seg6(
                        header,
                    ))],
                )
            }
            RouteEncapConfig::Ip6 {
                id,
                destination,
                source,
                hoplimit,
                traffic_class,
                flags,
            } => {
                let mut attributes = Vec::new();
                if let Some(value) = id {
                    attributes.push(RouteLwTunnelEncap::Ip6(
                        RouteIp6Tunnel::Id(*value),
                    ));
                }
                if let Some(value) = destination {
                    attributes.push(RouteLwTunnelEncap::Ip6(
                        RouteIp6Tunnel::Destination(*value),
                    ));
                }
                if let Some(value) = source {
                    attributes.push(RouteLwTunnelEncap::Ip6(
                        RouteIp6Tunnel::Source(*value),
                    ));
                }
                if let Some(value) = hoplimit {
                    attributes.push(RouteLwTunnelEncap::Ip6(
                        RouteIp6Tunnel::Hoplimit(*value),
                    ));
                }
                if let Some(value) = traffic_class {
                    attributes.push(RouteLwTunnelEncap::Ip6(
                        RouteIp6Tunnel::Tc(*value),
                    ));
                }
                if *flags != 0 {
                    attributes.push(RouteLwTunnelEncap::Ip6(
                        RouteIp6Tunnel::Other(
                            rtnetlink::packet_core::DefaultNla::new(
                                6,
                                flags.to_be_bytes().to_vec(),
                            ),
                        ),
                    ));
                }
                (RouteLwEnCapType::Ip6, attributes)
            }
        };
        msg.attributes.push(RouteAttribute::EncapType(encap_type));
        msg.attributes.push(RouteAttribute::Encap(attributes));
    }
    if !config.nexthops.is_empty() {
        msg.attributes
            .push(RouteAttribute::MultiPath(build_route_nexthops(config)));
    }
    if config.pervasive {
        msg.header
            .flags
            .insert(rtnetlink::packet_route::route::RouteFlags::Pervasive);
    }

    let kind = msg.header.kind;
    let scope_set = config.scope.is_some();
    if (kind == RouteType::Local || kind == RouteType::Nat) && !scope_set {
        msg.header.scope = RouteScope::Host;
    } else if (kind == RouteType::Broadcast
        || kind == RouteType::Multicast
        || kind == RouteType::Anycast
        || (kind == RouteType::Unicast || kind == RouteType::Unspec)
            && config.via.is_none()
            && config.dev.is_none()
            && config.preference.is_none())
        && !scope_set
    {
        msg.header.scope = RouteScope::Link;
    }

    if (kind == RouteType::Local
        || kind == RouteType::Broadcast
        || kind == RouteType::Nat
        || kind == RouteType::Anycast)
        && config.table.is_none()
    {
        msg.header.table = 255;
    }

    Ok(msg)
}

pub(crate) async fn handle_modify_add(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Add).await
}

pub(crate) async fn handle_modify_append(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Append).await
}

pub(crate) async fn handle_modify_change(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Change).await
}

pub(crate) async fn handle_modify_prepend(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Prepend).await
}

pub(crate) async fn handle_modify_replace(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Replace).await
}
