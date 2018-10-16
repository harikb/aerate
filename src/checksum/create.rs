extern crate crypto;

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
use walkdir::WalkDir;

use std::fs;
use std::path::Path;

use checksum::common;

/* Sample contents of file
f550855......940a8cc310a427	362	config	./.git/config
9635f1b......d809ef07efa2f4	73	description	./.git/description
acbaef2......456fbbe8c84724	23	HEAD	./.git/HEAD
9f2aa63......ed0833b479479c	177	README.sample	./.git/hooks/README.sample
*/
pub fn gen_hashes(dir: &str, checksum_file: &str, resume: bool) -> io::Result<()> {
    let mut buffer: Vec<u8> = vec![0; 1024 * 1024];
    let mut count = 0;
    let tn = format!("{}.tmp", checksum_file);

    let mut hasher = Sha1::new();
    let mut already_done = HashMap::new();

    let mut opts = OpenOptions::new();
    opts.write(true);
    opts.create(true); // we overwrite/create even if we are 'resume'-ing
    if resume {
        match common::load_checksum_file(&tn, true) {
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
