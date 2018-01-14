extern crate args;
extern crate crypto;
extern crate getopts;
extern crate walkdir;

use walkdir::WalkDir;
use std::io::prelude::*;
use std::fs::File;
use std::io;
use std::io::{Error, ErrorKind};
use std::io::BufReader;
use std::io::BufWriter;
use self::crypto::digest::Digest;
use self::crypto::sha1::Sha1;
use std::env;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::process;
use std::path::PathBuf;

use std::fs;
use std::path::Path;
use args::{Args, ArgsError};

const PROGRAM_DESC: &'static str =
    "Calculates checksums for all files under (recursively) a given directory";

/* Sample output of this program
f550855......940a8cc310a427	362	config	./.git/config
9635f1b......d809ef07efa2f4	73	description	./.git/description
acbaef2......456fbbe8c84724	23	HEAD	./.git/HEAD
9f2aa63......ed0833b479479c	177	README.sample	./.git/hooks/README.sample
*/
struct FileMetaData {
    fname: String,
    hash: String,
    path: String,
    sz: u64,
}

fn parse_args() -> Result<(Args), ArgsError> {
    let raw_args: Vec<String> = env::args().collect();
    let mut args = Args::new(&raw_args[0], PROGRAM_DESC);

    args.flag("h", "help", "Print the usage menu");

    args.flag(
        "r",
        "resume",
        "Resume (updating checksum file) from where we left off",
    );

    args.flag(
        "c",
        "check",
        "Check current files against the checksum-file",
    );

    try!(args.parse(raw_args));

    let help = try!(args.value_of("help"));
    if help {
        println!("{}", args.full_usage());
        return Err(ArgsError::new("", "")); // I have to create an ArgsError
    }

    Ok(args)
}

fn load_checksum_file(
    checksum_file: &str,
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
                            let mut sz1 = 0;
                            match v[1].parse::<u64>() {
                                Ok(n) => sz1 = n,
                                Err(e) => {
                                    return Err(Error::new(ErrorKind::Interrupted, e));
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
                                    path: String::from(v[3]),
                                },
                            );
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
    if resume {
        match load_checksum_file(&tn) {
            Err(err) => {
                println!("Error trying to load previous file: {}", err);
                opts.create(true);
            }
            Ok(done_files) => {
                already_done = done_files;
                opts.append(true);
            }
        }
    } else {
        opts.create(true);
    }
    let ofp = try!(opts.open(Path::new(&tn)));
    let mut ofb = BufWriter::new(ofp);

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let fname: &str;
            match entry.file_name().to_str() {
                Some(_fn) => fname = _fn,
                None => return Err(Error::new(ErrorKind::Other, "Invalid filename!")),
            }
            let md = try!(fs::metadata(entry.path()));
            let sz = md.len();
            {
                count += 1;
                if !already_done.contains_key(entry.path()) {
                    let mut ifp = try!(File::open(entry.path()));
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
                    writeln!(ofb, "{}\t{}\t{}\t{}", h, sz, fname, entry.path().display(),);
                }
                if count == 1 || count % 100 == 0 {
                    println!("Checked {} files. Last {}", count, entry.path().display())
                }
            }
        }
    }
    println!("Checked {} files", count);
    Ok(())
}

/* Sample contents of file
f550855......940a8cc310a427	362	config	./.git/config
9635f1b......d809ef07efa2f4	73	description	./.git/description
acbaef2......456fbbe8c84724	23	HEAD	./.git/HEAD
9f2aa63......ed0833b479479c	177	README.sample	./.git/hooks/README.sample
*/
fn check_hashes(dir: &str, checksum_file: &str) -> io::Result<()> {
    let mut buffer: Vec<u8> = vec![0; 1024 * 1024];
    let mut count = 0;

    let mut hasher = Sha1::new();
    let already_done: HashMap<std::path::PathBuf, FileMetaData>;
    let mut checked: HashMap<std::path::PathBuf, bool> = HashMap::new();

    match load_checksum_file(checksum_file) {
        Err(err) => {
            return Err(err);
        }
        Ok(chks) => {
            already_done = chks;
        }
    }

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let md = try!(fs::metadata(entry.path()));
            let sz = md.len();
            {
                count += 1;
                let mut ifp = try!(File::open(entry.path()));
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
    match parse_args() {
        Ok(args) => match args.value_of::<bool>("check") {
            Ok(x) => {
                if x {
                    check_hashes(".", "allfiles_checksums.txt").expect("check_hashes failed");
                } else {
                    gen_hashes(
                        ".",
                        "allfiles_checksums.txt",
                        args.value_of("resume").unwrap(),
                    ).expect("gen_hashes failed");
                }
            }
            Err(err) => {
                println!("{}", err);
                process::exit(0);
            }
        },
        Err(err) => {
            println!("{}", err);
            process::exit(0);
        }
    }
}
