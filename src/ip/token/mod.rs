// SPDX-License-Identifier: MIT

//! IPv6 tokenized-interface-identifier support for `ip token`.
//!
//! Tokens are carried in the IPv6 address-family attributes of a link
//! message.  The implementation intentionally uses the link handle rather
//! than a second protocol so that list/get and set/delete share the same
//! interface-name and capability behavior as `ip link`.

use std::net::Ipv6Addr;

use futures_util::stream::TryStreamExt;
use iproute_rs::{CanDisplay, CanOutput, CliError};
use rtnetlink::packet_route::link::{
    AfSpecInet6, AfSpecUnspec, LinkAttribute, LinkFlags, LinkHeader,
    LinkMessage,
};
use serde::Serialize;

/// Top-level `ip token` command.
pub(crate) struct TokenCommand;

impl TokenCommand {
    /// Canonical command name used by clap and the dispatcher.
    pub(crate) const CMD: &'static str = "token";

    /// Build the token command grammar.
    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("IPv6 tokenized interface identifiers")
            .subcommand_required(false)
            .disable_help_subcommand(true)
            .subcommand(
                clap::Command::new("list")
                    .about("list interface tokens")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("set")
                    .about("set an interface token")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("delete")
                    .about("delete an interface token")
                    .alias("del")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("get")
                    .about("get an interface token")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(clap::Command::new("help").about("show token help"))
    }

    /// Execute a token operation.
    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<TokenOutput, CliError> {
        let (operation, child) =
            matches.subcommand().unwrap_or(("list", matches));
        match operation {
            "help" => Ok(TokenOutput::Help(TOKEN_HELP.to_owned())),
            "list" | "get" | "set" | "delete" | "del" => {
                let options = child
                    .get_many::<String>("options")
                    .unwrap_or_default()
                    .cloned()
                    .collect::<Vec<_>>();
                match operation {
                    "list" | "get" => list_tokens(&options).await,
                    "set" => set_token(&options).await,
                    "delete" | "del" => delete_token(&options).await,
                    _ => unreachable!(),
                }
            }
            other => Err(format!("unknown ip token operation: {other}").into()),
        }
    }
}

/// Output returned by `ip token`.
pub(crate) enum TokenOutput {
    /// Token records, one for each selected interface.
    Records(Vec<TokenInfo>),
    /// Human-readable command help.
    Help(String),
}

impl Serialize for TokenOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Records(values) => values.serialize(serializer),
            Self::Help(value) => value.serialize(serializer),
        }
    }
}

impl CanDisplay for TokenOutput {
    fn gen_string(&self) -> String {
        match self {
            Self::Records(values) => values.gen_string(),
            Self::Help(value) => value.clone(),
        }
    }
}

impl CanOutput for TokenOutput {}

/// One tokenized IPv6 interface identifier.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct TokenInfo {
    /// IPv6 token value.
    pub(crate) token: Ipv6Addr,
    /// Interface name.
    pub(crate) ifname: String,
}

impl std::fmt::Display for TokenInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "token {} dev {}", self.token, self.ifname)
    }
}

impl CanDisplay for TokenInfo {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for TokenInfo {}

fn parse_device(args: &[String]) -> Result<Option<String>, CliError> {
    let mut device = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "dev" => {
                let value = iter.next().ok_or_else(|| {
                    CliError::from("token: dev requires a value")
                })?;
                device = Some(value.clone());
            }
            "help" => return Ok(None),
            unknown => {
                return Err(
                    format!("token: unknown argument `{unknown}`").into()
                );
            }
        }
    }
    Ok(device)
}

fn parse_set_args(args: &[String]) -> Result<(Ipv6Addr, String), CliError> {
    let mut token = None;
    let mut device = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "dev" => {
                let value = iter.next().ok_or_else(|| {
                    CliError::from("token: dev requires a value")
                })?;
                device = Some(value.clone());
            }
            value if token.is_none() => {
                token = Some(value.parse::<Ipv6Addr>().map_err(|error| {
                    CliError::from(format!(
                        "invalid IPv6 token `{value}`: {error}"
                    ))
                })?);
            }
            unknown => {
                return Err(
                    format!("token: unknown argument `{unknown}`").into()
                );
            }
        }
    }
    let token =
        token.ok_or_else(|| CliError::from("token set requires TOKEN"))?;
    let device =
        device.ok_or_else(|| CliError::from("token set requires dev DEV"))?;
    Ok((token, device))
}

async fn list_tokens(args: &[String]) -> Result<TokenOutput, CliError> {
    let device = parse_device(args)?;
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut links = if let Some(device) = device {
        handle.link().get().match_name(device).execute()
    } else {
        handle.link().get().execute()
    };
    let mut records = Vec::new();
    while let Some(link) = links.try_next().await? {
        let Some(ifname) = link.attributes.iter().find_map(|attribute| {
            if let LinkAttribute::IfName(name) = attribute {
                Some(name.clone())
            } else {
                None
            }
        }) else {
            continue;
        };
        let token = link.attributes.iter().find_map(|attribute| {
            let LinkAttribute::AfSpecUnspec(specs) = attribute else {
                return None;
            };
            specs.iter().find_map(|spec| {
                let AfSpecUnspec::Inet6(values) = spec else {
                    return None;
                };
                values.iter().find_map(|value| {
                    if let AfSpecInet6::Token(token) = value {
                        Some(*token)
                    } else {
                        None
                    }
                })
            })
        });
        // iproute2 lists the token for broadcast-capable interfaces.  The
        // kernel commonly reports the default token as `::`; it is still a
        // meaningful record for this command and should not be discarded.
        if link.header.flags.contains(LinkFlags::Broadcast)
            && let Some(token) = token
        {
            records.push(TokenInfo { token, ifname });
        }
    }
    Ok(TokenOutput::Records(records))
}

async fn set_token(args: &[String]) -> Result<TokenOutput, CliError> {
    let (token, device) = parse_set_args(args)?;
    change_token(&device, token).await
}

async fn delete_token(args: &[String]) -> Result<TokenOutput, CliError> {
    let device = parse_device(args)?
        .ok_or_else(|| CliError::from("token delete requires dev DEV"))?;
    change_token(&device, Ipv6Addr::UNSPECIFIED).await
}

async fn change_token(
    device: &str,
    token: Ipv6Addr,
) -> Result<TokenOutput, CliError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    let mut links = handle.link().get().match_name(device.to_owned()).execute();
    let link = links.try_next().await?.ok_or_else(|| {
        CliError::from(format!("Device `{device}` does not exist"))
    })?;
    let mut message = LinkMessage::default();
    message.header = LinkHeader {
        index: link.header.index,
        ..LinkHeader::default()
    };
    message.attributes.push(LinkAttribute::AfSpecUnspec(vec![
        AfSpecUnspec::Inet6(vec![AfSpecInet6::Token(token)]),
    ]));
    handle.link().change(message).execute().await?;
    Ok(TokenOutput::Records(Vec::new()))
}

const TOKEN_HELP: &str = "Usage: ip token [ list | set TOKEN dev DEV | del dev DEV | get dev DEV ]\n";
