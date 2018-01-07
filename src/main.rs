extern crate args;
extern crate crypto;
extern crate getopts;
extern crate walkdir;

use walkdir::WalkDir;
use std::io::prelude::*;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use self::crypto::digest::Digest;
use self::crypto::sha1::Sha1;
use std::env;
use std::collections::HashMap;
use std::fs::OpenOptions;

use std::fs;
use std::path::Path;
use args::{Args, ArgsError};

const PROGRAM_DESC: &'static str = "aerate checksums all files under a given directory";
const PROGRAM_NAME: &'static str = "aerate";

fn parse_args() -> Result<(Args), ArgsError> {
    let mut args = Args::new(PROGRAM_NAME, PROGRAM_DESC);

    args.flag("h", "help", "Print the usage menu");

    args.flag(
        "r",
        "resume",
        "Resume (updating checksum file) from where we left off",
    );

    let raw_args: Vec<String> = env::args().collect();
    try!(args.parse(raw_args));

    let help = try!(args.value_of("help"));
    if help {
        args.full_usage();
        return Ok((args));
    }

    Ok((args))
}

fn load_checksum_file(checksum_file: &str) -> HashMap<String, bool> {
    let mut already_done = HashMap::new();

    match File::open(Path::new(checksum_file)) {
        Err(_) => println!("WARNING: No existing checksum file found"),
        Ok(ifp) => {
            let ifb = BufReader::new(ifp);

            for line in ifb.lines() {
                match line {
                    Ok(line) => {
                        let v: Vec<&str> = line.split("\t").collect();
                        if v.len() == 4 {
                            // String::from is required to keep contents
                            // of v[3] alive after loop or probably even
                            // past current-line-to-next-line switch
                            already_done.insert(String::from(v[3]), true);
                        }
                    }
                    Err(err) => {
                        println!("{}", err);
                    }
                }
            }
        }
    }
    return already_done;
}
/* Sample contents of file
f550855......940a8cc310a427	362	config	./.git/config
9635f1b......d809ef07efa2f4	73	description	./.git/description
acbaef2......456fbbe8c84724	23	HEAD	./.git/HEAD
9f2aa63......ed0833b479479c	177	README.sample	./.git/hooks/README.sample
*/
fn gen_hashes(dir: &str, checksum_file: &str, resume: bool) {
    let mut buffer: Vec<u8> = vec![0; 1024 * 1024];
    let mut count = 0;
    let tn = format!("{}.tmp", checksum_file);

    let mut hasher = Sha1::new();
    let mut already_done = HashMap::new();

    let mut opts = OpenOptions::new();
    opts.write(true);
    if resume {
        opts.append(true);
        already_done = load_checksum_file(&tn);
    } else {
        opts.create(true);
    }
    let ofp = opts.open(Path::new(&tn)).unwrap();
    let mut ofb = BufWriter::new(ofp);

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let full_path_name = entry.path().to_str().unwrap();
            let fname = entry.file_name().to_str().unwrap();
            let md = fs::metadata(entry.path()).unwrap();
            let sz = md.len();
            {
                count += 1;
                if !already_done.contains_key(full_path_name) {
                    let mut ifp = File::open(entry.path()).unwrap();
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
    println!("Checked {} files", count)
}

fn main() {
    let args = parse_args().unwrap();
    gen_hashes(
        ".",
        "allfiles_checksums.txt",
        args.value_of("resume").unwrap(),
    )
}
