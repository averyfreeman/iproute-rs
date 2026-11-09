// SPDX-License-Identifier: MIT

//! Mutation support for `ip neighbour`.
//!
//! The kernel's neighbour API is intentionally small: a destination, an
//! interface index, a link-layer address, a NUD state, and a set of flags.
//! This module translates the familiar `ip neigh add|replace|delete` syntax
//! into those typed netlink fields without invoking an external command.

use std::net::IpAddr;

use iproute_rs::{CliError, parse_mac_str};
use rtnetlink::packet_route::{
    AddressFamily,
    neighbour::{
        NeighbourAddress, NeighbourAttribute, NeighbourExtFlags,
        NeighbourFlags, NeighbourMessage, NeighbourState,
    },
    route::RouteType,
};

use super::show::resolve_link_index;

#[derive(Debug)]
struct NeighbourSpec {
    destination: IpAddr,
    device: String,
    lladdr: Option<Vec<u8>>,
    state: NeighbourState,
    flags: NeighbourFlags,
    ext_flags: NeighbourExtFlags,
}

impl NeighbourSpec {
    fn parse(options: &[String], deleting: bool) -> Result<Self, CliError> {
        let mut options = options.iter().map(String::as_str).peekable();
        let first = options.next().ok_or("missing neighbour destination")?;
        let mut flags = NeighbourFlags::empty();
        if first == "proxy" {
            flags |= NeighbourFlags::Proxy;
        }

        let destination_text = if first == "proxy" {
            options.next().ok_or("missing destination after `proxy`")?
        } else {
            first
        };
        let destination = destination_text.parse::<IpAddr>().map_err(|_| {
            format!("invalid neighbour destination `{destination_text}`")
        })?;

        let mut device = None;
        let mut lladdr = None;
        let mut state = if deleting {
            NeighbourState::None
        } else {
            NeighbourState::Permanent
        };
        let mut ext_flags = NeighbourExtFlags::empty();

        while let Some(option) = options.next() {
            match option {
                "dev" | "oif" => {
                    device = Some(
                        options
                            .next()
                            .ok_or("missing device after `dev`")?
                            .to_owned(),
                    );
                }
                "lladdr" => {
                    let value = options
                        .next()
                        .ok_or("missing address after `lladdr`")?;
                    lladdr = Some(parse_mac_str(value)?);
                }
                "nud" => {
                    let value =
                        options.next().ok_or("missing state after `nud`")?;
                    state =
                        value.parse::<NeighbourState>().map_err(|error| {
                            format!("invalid neighbour state: {error}")
                        })?;
                }
                "router" => flags |= NeighbourFlags::Router,
                "use" => flags |= NeighbourFlags::Use,
                "extern_learn" | "extern-learn" => {
                    flags |= NeighbourFlags::ExtLearned;
                }
                "offload" => flags |= NeighbourFlags::Offloaded,
                "sticky" => flags |= NeighbourFlags::Sticky,
                "managed" => ext_flags |= NeighbourExtFlags::Managed,
                "locked" => ext_flags |= NeighbourExtFlags::Locked,
                other => {
                    return Err(
                        format!("unknown neighbour option `{other}`").into()
                    );
                }
            }
        }

        let device = device.ok_or("neighbour command requires `dev DEVICE`")?;
        Ok(Self {
            destination,
            device,
            lladdr,
            state,
            flags,
            ext_flags,
        })
    }

    fn family(&self) -> AddressFamily {
        match self.destination {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        }
    }

    fn destination_attribute(&self) -> NeighbourAttribute {
        NeighbourAttribute::Destination(match self.destination {
            IpAddr::V4(address) => NeighbourAddress::Inet(address),
            IpAddr::V6(address) => NeighbourAddress::Inet6(address),
        })
    }
}

/// Add or replace a neighbour entry.
pub(crate) async fn handle_add(
    options: &[String],
    replace: bool,
) -> Result<(), CliError> {
    let spec = NeighbourSpec::parse(options, false)?;
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    let index = resolve_link_index(&handle, &spec.device).await?;

    let mut request = handle.neighbours().add(index, spec.destination);
    request = request
        .state(spec.state)
        .flags(spec.flags)
        .kind(RouteType::Unspec);
    if replace {
        request = request.replace();
    }
    let message = request.message_mut();
    if let Some(lladdr) = spec.lladdr {
        message
            .attributes
            .push(NeighbourAttribute::LinkLayerAddress(lladdr));
    }
    if !spec.ext_flags.is_empty() {
        message
            .attributes
            .push(NeighbourAttribute::ExtFlags(spec.ext_flags));
    }
    if spec.flags.contains(NeighbourFlags::Proxy) {
        message.header.state = NeighbourState::None;
    }
    request.execute().await?;
    Ok(())
}

/// Delete a neighbour entry.
pub(crate) async fn handle_delete(options: &[String]) -> Result<(), CliError> {
    let spec = NeighbourSpec::parse(options, true)?;
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    let index = resolve_link_index(&handle, &spec.device).await?;

    let mut message = NeighbourMessage::default();
    message.header.family = spec.family();
    message.header.ifindex = index;
    message.header.flags = spec.flags;
    message.header.kind = RouteType::Unspec;
    message.attributes.push(spec.destination_attribute());
    if let Some(lladdr) = spec.lladdr {
        message
            .attributes
            .push(NeighbourAttribute::LinkLayerAddress(lladdr));
    }
    handle.neighbours().del(message).execute().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_static_neighbor() {
        let spec = NeighbourSpec::parse(
            &[
                "192.0.2.1".into(),
                "lladdr".into(),
                "02:00:00:00:00:01".into(),
                "dev".into(),
                "eth0".into(),
                "nud".into(),
                "permanent".into(),
            ],
            false,
        )
        .expect("valid neighbour options");
        assert_eq!(spec.destination, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(spec.device, "eth0");
        assert_eq!(spec.lladdr, Some(vec![2, 0, 0, 0, 0, 1]));
        assert_eq!(spec.state, NeighbourState::Permanent);
    }

    #[test]
    fn parses_proxy_neighbor() {
        let spec = NeighbourSpec::parse(
            &[
                "proxy".into(),
                "2001:db8::1".into(),
                "dev".into(),
                "eth0".into(),
            ],
            false,
        )
        .expect("valid proxy options");
        assert!(spec.flags.contains(NeighbourFlags::Proxy));
        assert_eq!(spec.family(), AddressFamily::Inet6);
    }
}
