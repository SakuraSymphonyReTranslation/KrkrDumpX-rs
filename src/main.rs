mod bootstrap;
mod bres;
mod classify;
mod cli;
mod derive;
mod descramble;
mod drip;
mod exe_finder;
mod filter;
mod grammar;
mod hash;
mod hxv4;
mod pbd;
mod pe;
mod pipeline;
mod psb;
mod salt;
mod tjs2;
mod unhash;
mod xp3;

use clap::Parser;
use cli::{Cli, Command};

fn main() {
    let cli = Cli::parse();
    let res = match cli.command {
        Command::Run(args) => pipeline::cmd_run(args),
        Command::Keys(args) => pipeline::cmd_keys(args),
        Command::Analyze(args) => pipeline::cmd_analyze(args),
        Command::Extract(args) => pipeline::cmd_extract(args),
        Command::Unhash(args) => pipeline::cmd_unhash(args),
        Command::Hash(args) => pipeline::cmd_hash(args),
    };

    if let Err(err) = res {
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}
