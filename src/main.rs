extern crate crypto;
extern crate walkdir;

use walkdir::WalkDir;
use std::io::prelude::*;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use self::crypto::digest::Digest;
use self::crypto::sha1::Sha1;

use std::fs;
use std::path::Path;

fn gen_hashes(dir: &str, checksum_file: &str) {
    let mut buffer: Vec<u8> = vec![0; 1024 * 1024];

    let tn = format!("{}.tmp", checksum_file);
    let ofp = File::create(Path::new(&tn)).unwrap();
    let mut ofb = BufWriter::new(ofp);
    let mut hasher = Sha1::new();

    for entry in WalkDir::new(dir) {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            let md = fs::metadata(entry.path()).unwrap();
            let sz = md.len();
            let fname = entry.file_name().to_str().unwrap();
            {
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
        }
    }
}

fn main() {
    gen_hashes(".", "allfiles_checksums.txt")
}
