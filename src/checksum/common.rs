use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

use std::path::Path;

pub struct FileMetaData {
    pub fname: String,
    pub hash: String,
    pub sz: u64,
}

// -------------------------------------------------------------
// load_checksum_file() opens and parses a checksum manifest file
// with specific format shows in the example at the top of this
// file. `ignore_errors` parameter decides whether incomplete lines
// at the bottom of the checksum file are ignored. If a previous
// run was interrupted, incomplete lines are to be expected.
// -------------------------------------------------------------
pub fn load_checksum_file(
    checksum_file: &String,
    ignore_errors: bool,
) -> io::Result<HashMap<PathBuf, FileMetaData>> {
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
