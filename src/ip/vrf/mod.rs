// SPDX-License-Identifier: MIT

//! VRF inventory for `ip vrf show`.
//!
//! A VRF device is represented by an ordinary link message with `vrf` link
//! info and an `IFLA_VRF_TABLE` attribute.  Show/list therefore needs no new
//! netlink protocol.  Process association is read from cgroup v2 metadata,
//! matching the mechanism used by iproute2.  Executing a command in a VRF is
//! a separate cgroup-BPF operation and remains explicitly unsupported here.

use std::{
    collections::BTreeSet,
    fs,
    os::linux::fs::MetadataExt,
    path::{Path, PathBuf},
};

use futures_util::stream::TryStreamExt;
use iproute_rs::{CanDisplay, CanOutput, CliError};
use rtnetlink::packet_route::link::{
    InfoData, InfoKind, InfoVrf, LinkAttribute, LinkInfo,
};
use serde::Serialize;

/// Top-level `ip vrf` command.
pub(crate) struct VrfCommand;

impl VrfCommand {
    /// Canonical command name used by clap and the dispatcher.
    pub(crate) const CMD: &'static str = "vrf";

    /// Build the supported VRF grammar.
    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("virtual routing and forwarding devices")
            .subcommand_required(false)
            .disable_help_subcommand(true)
            .subcommand(
                clap::Command::new("show")
                    .about("show VRF devices")
                    .alias("list")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("identify")
                    .about("identify the VRF for a process")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("pids")
                    .about("list processes in a VRF")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("exec")
                    .about("execute a command in a VRF")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .num_args(2..)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(clap::Command::new("help").about("show VRF help"))
    }

    /// Execute a VRF operation.
    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<VrfOutput, CliError> {
        let (operation, child) =
            matches.subcommand().unwrap_or(("show", matches));
        match operation {
            "show" | "list" => {
                let options = child
                    .get_many::<String>("options")
                    .unwrap_or_default()
                    .cloned()
                    .collect::<Vec<_>>();
                show_vrfs(&options).await
            }
            "help" => Ok(VrfOutput::Help(VRF_HELP.to_owned())),
            "identify" => {
                let options = child
                    .get_many::<String>("options")
                    .unwrap_or_default()
                    .cloned()
                    .collect::<Vec<_>>();
                if options.len() > 1 {
                    return Err("vrf identify accepts at most one PID".into());
                }
                let pid = options.first().map(String::as_str).unwrap_or("self");
                Ok(VrfOutput::Lines(identify_vrf(pid)?))
            }
            "pids" => {
                let options = child
                    .get_many::<String>("options")
                    .unwrap_or_default()
                    .cloned()
                    .collect::<Vec<_>>();
                let name = match options.as_slice() {
                    [name] => name,
                    [] => return Err("vrf pids requires a VRF name".into()),
                    _ => return Err("vrf pids accepts one VRF name".into()),
                };
                let VrfOutput::Records(records) =
                    show_vrfs(std::slice::from_ref(name)).await?
                else {
                    unreachable!("show_vrfs always returns records");
                };
                if records.is_empty() {
                    return Err(format!("invalid VRF name: {name}").into());
                }
                Ok(VrfOutput::Lines(pids_for_vrf(name)?))
            }
            "exec" => Err(CliError::from(
                "ip vrf exec is not implemented: it requires privileged cgroup-BPF setup; use ip vrf exec from iproute2",
            )),
            other => Err(format!("unknown ip vrf operation: {other}").into()),
        }
    }
}

/// Output returned by `ip vrf`.
pub(crate) enum VrfOutput {
    /// VRF link records.
    Records(Vec<VrfInfo>),
    /// Lines returned by process-association queries.
    Lines(Vec<String>),
    /// Human-readable command help.
    Help(String),
}

impl Serialize for VrfOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Records(values) => values.serialize(serializer),
            Self::Lines(values) => values.serialize(serializer),
            Self::Help(value) => value.serialize(serializer),
        }
    }
}

impl CanDisplay for VrfOutput {
    fn gen_string(&self) -> String {
        match self {
            Self::Records(values) => {
                let mut output = String::from("Name              Table\n");
                output.push_str("-----------------------\n");
                for value in values {
                    output.push_str(&value.to_string());
                    output.push('\n');
                }
                output.trim_end_matches('\n').to_owned()
            }
            Self::Lines(values) => values.join("\n"),
            Self::Help(value) => value.clone(),
        }
    }
}

impl CanOutput for VrfOutput {}

/// One VRF device and its route-table ID.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct VrfInfo {
    /// VRF link name.
    pub(crate) ifname: String,
    /// Route table selected by the VRF device.
    pub(crate) table: u32,
}

impl std::fmt::Display for VrfInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:<18} {}", self.ifname, self.table)
    }
}

impl CanDisplay for VrfInfo {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for VrfInfo {}

async fn show_vrfs(args: &[String]) -> Result<VrfOutput, CliError> {
    let requested_name = match args {
        [] => None,
        [name] => Some(name.as_str()),
        _ => return Err("vrf show accepts at most one VRF name".into()),
    };
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    let mut links = handle.link().get().execute();
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
        if requested_name.is_some_and(|name| name != ifname) {
            continue;
        }
        let Some(table) = link.attributes.iter().find_map(|attribute| {
            let LinkAttribute::LinkInfo(infos) = attribute else {
                return None;
            };
            vrf_table_id(infos)
        }) else {
            continue;
        };
        records.push(VrfInfo { ifname, table });
    }
    Ok(VrfOutput::Records(records))
}

/// Extract the route-table ID from a decoded VRF link-info attribute list.
pub(crate) fn vrf_table_id(infos: &[LinkInfo]) -> Option<u32> {
    let is_vrf = infos
        .iter()
        .any(|info| matches!(info, LinkInfo::Kind(InfoKind::Vrf)));
    if !is_vrf {
        return None;
    }
    infos.iter().find_map(|info| {
        let LinkInfo::Data(InfoData::Vrf(values)) = info else {
            return None;
        };
        values.iter().find_map(|value| {
            if let InfoVrf::TableId(table) = value {
                Some(*table)
            } else {
                None
            }
        })
    })
}

/// Resolve the VRF cgroup association of a process.
///
/// iproute2 stores the association in a controller-less cgroup v2 path below
/// `/vrf/NAME`.  An empty result is the normal answer for a process in the
/// default VRF.
fn identify_vrf(pid: &str) -> Result<Vec<String>, CliError> {
    let proc_pid = if pid == "self" {
        "self".to_owned()
    } else {
        let _: u32 = pid
            .parse()
            .map_err(|_| CliError::from(format!("invalid PID: {pid}")))?;
        pid.to_owned()
    };
    let contents = fs::read_to_string(format!("/proc/{proc_pid}/cgroup"))
        .map_err(|error| {
            CliError::from(format!("cannot read process cgroup: {error}"))
        })?;
    let name = contents.lines().find_map(|line| {
        let (_, path) = line.split_once("::")?;
        let name = path.split_once("/vrf/")?.1;
        let name = name.split('/').next().unwrap_or_default();
        (!name.is_empty()).then_some(name.to_owned())
    });
    Ok(name.into_iter().collect())
}

/// Find cgroup v2 mount points visible in the current mount namespace.
fn cgroup2_mounts() -> Vec<PathBuf> {
    let mut mounts = Vec::new();
    if let Ok(contents) = fs::read_to_string("/proc/self/mountinfo") {
        for line in contents.lines() {
            let Some((before, after)) = line.split_once(" - ") else {
                continue;
            };
            if after.split_whitespace().next() != Some("cgroup2") {
                continue;
            }
            if let Some(mountpoint) = before.split_whitespace().nth(4) {
                let path = PathBuf::from(
                    mountpoint
                        .replace("\\040", " ")
                        .replace("\\011", "\t")
                        .replace("\\134", "\\"),
                );
                if !mounts.contains(&path) {
                    mounts.push(path);
                }
            }
        }
    }
    if mounts.is_empty() && Path::new("/sys/fs/cgroup").is_dir() {
        mounts.push(PathBuf::from("/sys/fs/cgroup"));
    }
    mounts
}

/// Check whether a process is in the caller's network namespace.
fn in_current_netns(pid: u32) -> bool {
    let Ok(current) = fs::metadata("/proc/self/ns/net") else {
        return false;
    };
    let Ok(process) = fs::metadata(format!("/proc/{pid}/ns/net")) else {
        return false;
    };
    current.st_dev() == process.st_dev() && current.st_ino() == process.st_ino()
}

fn command_name(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|value| value.trim().to_owned())
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "<terminated?>".to_owned())
}

fn read_cgroup_pids(path: &Path, pids: &mut BTreeSet<u32>) {
    let Ok(contents) = fs::read_to_string(path) else {
        return;
    };
    for line in contents.lines() {
        let Ok(pid) = line.trim().parse::<u32>() else {
            continue;
        };
        if in_current_netns(pid) {
            pids.insert(pid);
        }
    }
}

fn walk_cgroup_tree(root: &Path, vrf_name: &str, pids: &mut BTreeSet<u32>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if entry.file_name() == "vrf" {
            read_cgroup_pids(&path.join(vrf_name).join("cgroup.procs"), pids);
        }
        walk_cgroup_tree(&path, vrf_name, pids);
    }
}

/// Return formatted PID/command records for a VRF in the current netns.
fn pids_for_vrf(vrf_name: &str) -> Result<Vec<String>, CliError> {
    let mounts = cgroup2_mounts();
    if mounts.is_empty() {
        return Err("ip vrf pids requires a visible cgroup v2 mount".into());
    }
    let mut pids = BTreeSet::new();
    for mount in mounts {
        walk_cgroup_tree(&mount, vrf_name, &mut pids);
    }
    Ok(pids
        .into_iter()
        .map(|pid| format!("{pid:>5}  {}", command_name(pid)))
        .collect())
}

const VRF_HELP: &str = "Usage: ip vrf show [ NAME ]\n       ip vrf exec NAME COMMAND [ARGS...]\n       ip vrf identify [PID]\n       ip vrf pids NAME\n";
