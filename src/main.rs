extern crate clap;
extern crate crypto;
extern crate getopts;
extern crate walkdir;

mod checksum;
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};

fn parse_args() -> ArgMatches<'static> {
    return App::new("aerate")
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .subcommand(SubCommand::with_name("resume"))
        .subcommand(SubCommand::with_name("update"))
        .subcommand(SubCommand::with_name("check"))
        .setting(AppSettings::SubcommandRequired)
        .get_matches();
}

fn main() {
    let args = parse_args();
    if args.is_present("update") || args.is_present("resume") {
        checksum::create::gen_hashes(".", "allfiles_checksums.txt", args.is_present("resume"))
            .expect("gen_hashes failed");
    } else if args.is_present("check") {
        checksum::check::check_hashes(".", &String::from("allfiles_checksums.txt"))
            .expect("check_hashes failed");
    }
}
