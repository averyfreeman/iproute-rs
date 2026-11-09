// SPDX-License-Identifier: MIT

//! Named network-namespace management for `ip netns`.
//!
//! Namespace creation/removal delegates to `rtnetlink::NetworkNamespace`,
//! while list/identify/pids are read-only inode comparisons against
//! `/proc/<pid>/ns/net`.  `exec` enters the namespace in the short-lived
//! command process and inherits its standard streams, so the caller's shell
//! remains in its original namespace.

use std::{
    fs::{self, File},
    os::linux::fs::MetadataExt,
    path::Path,
    process::Command,
};

use iproute_rs::CliError;
use nix::{sched::CloneFlags, sched::setns};
use rtnetlink::NetworkNamespace;

const NETNS_DIR: &str = "/run/netns";

/// Top-level `ip netns` command.
pub(crate) struct NetnsCommand;

/// Enter a namespace selected by the global `ip -n/--netns` option.
///
/// The selector accepts a named namespace, a PID, or an explicit namespace
/// file, matching the useful forms of iproute2's global option.
pub(crate) fn enter_named_namespace(selector: &str) -> Result<(), CliError> {
    // `self` is already the current namespace.  Avoid a redundant setns(2)
    // call, which requires CAP_SYS_ADMIN even when the target is identical.
    if selector == "self" {
        return Ok(());
    }
    let path = if selector.parse::<u32>().is_ok() {
        Path::new("/proc").join(selector).join("ns/net")
    } else if selector.contains('/') {
        Path::new(selector).to_owned()
    } else {
        Path::new(NETNS_DIR).join(selector)
    };
    enter_namespace_path(&path, selector)
}

impl NetnsCommand {
    /// Canonical command name used by clap and the dispatcher.
    pub(crate) const CMD: &'static str = "netns";

    /// Build supported named-namespace operations.
    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("manage named network namespaces")
            .subcommand_required(false)
            .disable_help_subcommand(true)
            .subcommand(clap::Command::new("list").alias("ls"))
            .subcommand(
                clap::Command::new("add").arg(
                    clap::Arg::new("name")
                        .required(true)
                        .action(clap::ArgAction::Set),
                ),
            )
            .subcommand(
                clap::Command::new("delete").alias("del").arg(
                    clap::Arg::new("name")
                        .required(true)
                        .action(clap::ArgAction::Set),
                ),
            )
            .subcommand(
                clap::Command::new("identify")
                    .arg(clap::Arg::new("pid").action(clap::ArgAction::Set)),
            )
            .subcommand(
                clap::Command::new("pids").arg(
                    clap::Arg::new("name")
                        .required(true)
                        .action(clap::ArgAction::Set),
                ),
            )
            .subcommand(
                clap::Command::new("exec")
                    .about("execute a command in a namespace")
                    .arg(
                        clap::Arg::new("options")
                            .required(true)
                            .num_args(2..)
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(clap::Command::new("help"))
    }

    /// Execute the selected namespace operation.
    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<Vec<String>, CliError> {
        let (operation, child) =
            matches.subcommand().unwrap_or(("list", matches));
        match operation {
            "list" => list_names(),
            "add" => {
                let name = child
                    .get_one::<String>("name")
                    .ok_or_else(|| CliError::from("netns add requires a name"))?;
                NetworkNamespace::add(name).await?;
                Ok(vec![])
            }
            "delete" => {
                let name = child
                    .get_one::<String>("name")
                    .ok_or_else(|| CliError::from("netns delete requires a name"))?;
                NetworkNamespace::del(name).await?;
                Ok(vec![])
            }
            "identify" => {
                let pid = child
                    .get_one::<String>("pid")
                    .map(String::as_str)
                    .unwrap_or("self");
                identify_pid(pid)
            }
            "pids" => {
                let name = child
                    .get_one::<String>("name")
                    .ok_or_else(|| CliError::from("netns pids requires a name"))?;
                pids_for(name)
            }
            "help" => Ok(vec![
                "Usage: ip netns { list | add NAME | delete NAME | identify [PID] | pids NAME | exec NAME COMMAND [ARGS...] }"
                    .to_owned(),
            ]),
            "exec" => {
                let options = child
                    .get_many::<String>("options")
                    .ok_or_else(|| {
                        CliError::from(
                            "netns exec requires NAME and COMMAND",
                        )
                    })
                    .map(|values| values.cloned().collect::<Vec<_>>())?;
                exec_in_namespace(&options)
            }
            other => Err(format!("unknown ip netns operation: {other}").into()),
        }
    }
}

fn list_names() -> Result<Vec<String>, CliError> {
    let Ok(entries) = fs::read_dir(NETNS_DIR) else {
        return Ok(vec![]);
    };
    let mut names = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    names.sort_unstable();
    Ok(names)
}

fn namespace_key(path: impl AsRef<Path>) -> Result<(u64, u64), CliError> {
    let metadata = fs::metadata(path.as_ref()).map_err(|error| {
        CliError::from(format!(
            "cannot inspect {}: {error}",
            path.as_ref().display()
        ))
    })?;
    Ok((metadata.st_dev(), metadata.st_ino()))
}

fn identify_pid(pid: &str) -> Result<Vec<String>, CliError> {
    let proc_path = if pid == "self" {
        "/proc/self/ns/net".to_owned()
    } else {
        let _: u32 = pid
            .parse()
            .map_err(|_| CliError::from(format!("invalid PID: {pid}")))?;
        format!("/proc/{pid}/ns/net")
    };
    let key = namespace_key(proc_path)?;
    Ok(list_names()?
        .into_iter()
        .filter(|name| {
            namespace_key(Path::new(NETNS_DIR).join(name)).ok() == Some(key)
        })
        .collect())
}

fn pids_for(name: &str) -> Result<Vec<String>, CliError> {
    let key = namespace_key(Path::new(NETNS_DIR).join(name))?;
    let Ok(entries) = fs::read_dir("/proc") else {
        return Ok(vec![]);
    };
    let mut pids = entries
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().into_string().ok()?;
            if !pid.as_bytes().iter().all(u8::is_ascii_digit) {
                return None;
            }
            let proc_ns = entry.path().join("ns/net");
            (namespace_key(proc_ns).ok() == Some(key)).then_some(pid)
        })
        .collect::<Vec<_>>();
    pids.sort_by_key(|pid| pid.parse::<u64>().unwrap_or(u64::MAX));
    Ok(pids)
}

/// Enter a named network namespace and run a child command with inherited
/// standard streams.  The parent process exits after the child, so changing
/// its namespace does not affect the caller's shell.
fn exec_in_namespace(options: &[String]) -> Result<Vec<String>, CliError> {
    let (name, command_line) = options.split_first().ok_or_else(|| {
        CliError::from("netns exec requires NAME and COMMAND")
    })?;
    let (command, args) = command_line.split_first().ok_or_else(|| {
        CliError::from("netns exec requires NAME and COMMAND")
    })?;
    enter_named_namespace(name)?;

    let status =
        Command::new(command).args(args).status().map_err(|error| {
            CliError::from(format!(
                "cannot execute {command} in network namespace {name}: {error}"
            ))
        })?;
    if !status.success() {
        return Err(CliError::from(format!(
            "command {command} exited with status {status}"
        )));
    }
    Ok(vec![])
}

fn enter_namespace_path(path: &Path, selector: &str) -> Result<(), CliError> {
    let namespace = File::open(path).map_err(|error| {
        CliError::from(format!(
            "cannot open network namespace {}: {error}",
            path.display()
        ))
    })?;
    setns(&namespace, CloneFlags::CLONE_NEWNET).map_err(|error| {
        CliError::from(format!(
            "cannot enter network namespace {selector}: {error}"
        ))
    })
}
