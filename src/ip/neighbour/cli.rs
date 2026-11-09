// SPDX-License-Identifier: MIT

use iproute_rs::CliError;

use super::{
    modify::{handle_add, handle_delete},
    show::{CliNeighbourInfo, handle_flush, handle_show},
};

pub(crate) struct NeighbourCommand;

impl NeighbourCommand {
    pub(crate) const CMD: &'static str = "neighbour";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("arp/ndp table management")
            .alias("neigh")
            .alias("neig")
            .alias("nei")
            .alias("ne")
            .alias("n")
            .subcommand_required(false)
            .subcommand(
                clap::Command::new("show")
                    .about("list neighbour entries")
                    .alias("list")
                    .alias("lst")
                    .alias("ls")
                    .alias("li")
                    .alias("l")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("add")
                    .about("add a neighbour entry")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("replace")
                    .about("replace a neighbour entry")
                    .alias("change")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("delete")
                    .about("delete a neighbour entry")
                    .alias("del")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("flush")
                    .about("flush neighbour entries")
                    .alias("f")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<Vec<CliNeighbourInfo>, CliError> {
        if let Some(matches) = matches.subcommand_matches("show") {
            let opts = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(String::as_str);
            handle_show(opts, matches.get_flag("STATISTICS")).await
        } else if let Some(matches) = matches.subcommand_matches("add") {
            let opts = collect_options(matches);
            handle_add(&opts, false).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("replace") {
            let opts = collect_options(matches);
            handle_add(&opts, true).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("delete") {
            let opts = collect_options(matches);
            handle_delete(&opts).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("flush") {
            let opts = collect_options(matches);
            handle_flush(
                opts.iter().map(String::as_str),
                matches.get_flag("STATISTICS"),
            )
            .await?;
            Ok(vec![])
        } else {
            handle_show([].into_iter(), matches.get_flag("STATISTICS")).await
        }
    }
}

fn collect_options(matches: &clap::ArgMatches) -> Vec<String> {
    matches
        .get_many::<String>("options")
        .unwrap_or_default()
        .cloned()
        .collect()
}
