extern crate crypto;

use self::crypto::digest::Digest;
use self::crypto::sha1::Sha1;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use walkdir::WalkDir;

use std::fs;

use checksum::common;

/* Sample contents of file
f550855......940a8cc310a427	362	config	./.git/config
9635f1b......d809ef07efa2f4	73	description	./.git/description
acbaef2......456fbbe8c84724	23	HEAD	./.git/HEAD
9f2aa63......ed0833b479479c	177	README.sample	./.git/hooks/README.sample
*/
pub fn check_hashes(dir: &str, checksum_file: &String) -> io::Result<()> {
    let mut buffer: Vec<u8> = vec![0; 1024 * 1024];
    let mut count = 0;

    let mut hasher = Sha1::new();
    let already_done: HashMap<PathBuf, common::FileMetaData>;
    let mut checked: HashMap<PathBuf, bool> = HashMap::new();

    match common::load_checksum_file(checksum_file, false) {
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
                match entry.file_name().to_str() {
                    Some(_fn) => match _fn {
                        "allfiles_checksums.txt" => continue,
                        "allfiles_checksums.txt.tmp" => continue,
                        _ => (),
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
