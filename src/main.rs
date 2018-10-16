extern crate clap;
extern crate crypto;
extern crate getopts;
extern crate walkdir;

use self::crypto::digest::Digest;
use self::crypto::sha1::Sha1;
use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use walkdir::WalkDir;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use std::fs;
use std::path::Path;

/* Sample output of this program
f550855......940a8cc310a427	362	config	./.git/config
9635f1b......d809ef07efa2f4	73	description	./.git/description
acbaef2......456fbbe8c84724	23	HEAD	./.git/HEAD
9f2aa63......ed0833b479479c	177	README.sample	./.git/hooks/README.sample
*/
struct FileMetaData {
    fname: String,
    hash: String,
    sz: u64,
}

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
// -------------------------------------------------------------
// load_checksum_file() opens and parses a checksum manifest file
// with specific format shows in the example at the top of this
// file. `ignore_errors` parameter decides whether incomplete lines
// at the bottom of the checksum file are ignored. If a previous
// run was interrupted, incomplete lines are to be expected.
// -------------------------------------------------------------
fn load_checksum_file(
    checksum_file: &String,
    ignore_errors: bool,
) -> io::Result<HashMap<std::path::PathBuf, FileMetaData>> {
    let mut file_checksums = HashMap::new();

    match File::open(Path::new(checksum_file)) {
        Err(err) => return Err(err),
        Ok(ifp) => {
            let ifb = BufReader::new(ifp);

            for line in ifb.lines() {
                match line {
                    Ok(line) => {
                        let v: Vec<&str> = line.split("\t").collect();
                        if v.len() == 4 {
                            let mut sz1: u64;
                            match v[1].parse::<u64>() {
                                Ok(n) => sz1 = n,
                                Err(e) => {
                                    if ignore_errors {
                                        break;
                                    } else {
                                        return Err(Error::new(ErrorKind::Interrupted, e));
                                    }
                                }
                            }
                            // String::from is required to keep contents
                            // of v[3] alive after loop or probably even
                            // past current-line-to-next-line switch
                            file_checksums.insert(
                                PathBuf::from(v[3]),
                                FileMetaData {
                                    fname: String::from(v[2]),
                                    hash: String::from(v[0]),
                                    sz: sz1, // parsed from v[1]
                                },
                            );
                        } else {
                            if ignore_errors {
                                break;
                            } else {
                                return Err(Error::new(
                                    ErrorKind::Interrupted,
                                    "Incomplete line in checksum file",
                                ));
                            }
                        }
                    }
                    Err(err) => {
                        return Err(err);
                    }
                }
            }
        }
    }
    return Ok(file_checksums);
}
/* Sample contents of file
f550855......940a8cc310a427	362	config	./.git/config
9635f1b......d809ef07efa2f4	73	description	./.git/description
acbaef2......456fbbe8c84724	23	HEAD	./.git/HEAD
9f2aa63......ed0833b479479c	177	README.sample	./.git/hooks/README.sample
*/
fn gen_hashes(dir: &str, checksum_file: &str, resume: bool) -> io::Result<()> {
    let mut buffer: Vec<u8> = vec![0; 1024 * 1024];
    let mut count = 0;
    let tn = format!("{}.tmp", checksum_file);

    let mut hasher = Sha1::new();
    let mut already_done = HashMap::new();

    let mut opts = OpenOptions::new();
    opts.write(true);
    opts.create(true); // we overwrite/create even if we are 'resume'-ing
    if resume {
        match load_checksum_file(&tn, true) {
            Err(err) => {
                println!("Error trying to load previous file: {}", err);
            }
            Ok(done_files) => {
                already_done = done_files;
                fs::rename(&tn, format!("{}.backup", &tn))?
            }
        }
    } else {
        opts.create(true);
    }
    let ofp = opts.open(Path::new(&tn))?;
    let mut ofb = BufWriter::new(ofp);

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let fname: &str;
            match entry.file_name().to_str() {
                Some(_fn) => match _fn {
                    "allfiles_checksums.txt" => continue,
                    "allfiles_checksums.txt.tmp" => continue,
                    _ => fname = _fn,
                },
                None => return Err(Error::new(ErrorKind::Other, "Invalid filename!")),
            }
            let md = fs::metadata(entry.path())?;
            let sz = md.len();
            {
                count += 1;
                match already_done.get(entry.path()) {
                    Some(row) => writeln!(
                        ofb,
                        "{}\t{}\t{}\t{}",
                        row.hash,
                        row.sz,
                        row.fname,
                        entry.path().display()
                    )?,
                    None => {
                        let mut ifp = File::open(entry.path())?;
                        let mut ifb = BufReader::new(ifp);
                        hasher.reset();
                        loop {
                            let res = ifb.read(&mut buffer);
                            match res {
                                Ok(n) => {
                                    if n > 0 {
                                        hasher.input(&buffer[0..n])
                                    } else {
                                        break;
                                    }
                                }
                                Err(err) => panic!(err),
                            }
                        }
                        let h = hasher.result_str();
                        writeln!(ofb, "{}\t{}\t{}\t{}", h, sz, fname, entry.path().display(),)?
                    }
                }
                if count == 1 || count % 100 == 0 {
                    println!(
                        "Checksumed {} files. Last {}",
                        count,
                        entry.path().display()
                    )
                }
            }
        }
    }
    ofb.flush()?;
    drop(ofb);

    fs::rename(&tn, &checksum_file)?;

    println!("Checksumed {} files. Result in {}", count, &checksum_file);
    Ok(())
}

/* Sample contents of file
f550855......940a8cc310a427	362	config	./.git/config
9635f1b......d809ef07efa2f4	73	description	./.git/description
acbaef2......456fbbe8c84724	23	HEAD	./.git/HEAD
9f2aa63......ed0833b479479c	177	README.sample	./.git/hooks/README.sample
*/
fn check_hashes(dir: &str, checksum_file: &String) -> io::Result<()> {
    let mut buffer: Vec<u8> = vec![0; 1024 * 1024];
    let mut count = 0;

    let mut hasher = Sha1::new();
    let already_done: HashMap<std::path::PathBuf, FileMetaData>;
    let mut checked: HashMap<std::path::PathBuf, bool> = HashMap::new();

    match load_checksum_file(checksum_file, false) {
        Err(err) => {
            return Err(err);
        }
        Ok(chks) => {
            already_done = chks;
        }
    }

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let md = fs::metadata(entry.path())?;
            let sz = md.len();
            {
                count += 1;
                let fname: &str;
                match entry.file_name().to_str() {
                    Some(_fn) => match _fn {
                        "allfiles_checksums.txt" => continue,
                        "allfiles_checksums.txt.tmp" => continue,
                        _ => fname = _fn,
                    },
                    None => return Err(Error::new(ErrorKind::Other, "Invalid filename!")),
                }
                let mut ifp = File::open(entry.path())?;
                let mut ifb = BufReader::new(ifp);
                hasher.reset();
                loop {
                    let res = ifb.read(&mut buffer);
                    match res {
                        Ok(n) => {
                            if n > 0 {
                                hasher.input(&buffer[0..n])
                            } else {
                                break;
                            }
                        }
                        Err(err) => panic!(err),
                    }
                }
                let h = hasher.result_str();
                match already_done.get(entry.path()) {
                    Some(md) => {
                        if md.hash != h && md.sz != sz {
                            println!("File checksum mismatch for {}", entry.path().display());
                        }
                        checked.insert(entry.path().to_path_buf(), true);
                    }
                    None => {
                        println!("Untracked/New file found: {}", entry.path().display());
                    }
                }
            }
            if count == 1 || count % 100 == 0 {
                println!("Checked {} files. Last {}", count, entry.path().display())
            }
        }
    }

    for (pb, md) in already_done.iter() {
        if !checked.contains_key(pb) {
            println!("Missing file {} with checksum {}", pb.display(), md.hash);
        }
    }

    println!("Checked {} files", count);
    Ok(())
}

fn main() {
    let args = parse_args();
    if args.is_present("update") || args.is_present("resume") {
        gen_hashes(".", "allfiles_checksums.txt", args.is_present("resume"))
            .expect("gen_hashes failed");
    } else if args.is_present("check") {
        check_hashes(".", &String::from("allfiles_checksums.txt")).expect("check_hashes failed");
    }
}
