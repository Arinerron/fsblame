//! Ring buffer items as a stale BPF object or a kernel-side bug could hand them over: any
//! bytes. Decoding returns a record or `Malformed` and never panics, whatever lengths and
//! flags the header claims, and so do the accessors of the payload it borrows.
#![no_main]

use fsblame::record::{self, Record};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|item: &[u8]| {
    match record::decode(item) {
        Ok(Record::Exec(exec)) => {
            let _ = exec.env_entries();
            let _ = exec.cwd(&mut Vec::new());
            let _ = record::c_str(&exec.rec.comm);
        }
        Ok(Record::Fs(fs)) => {
            let _ = record::c_str(&fs.rec.comm);
            let _ = record::trim_nul(fs.path2);
        }
        Ok(Record::Fork(_) | Record::Exit(_)) | Err(_) => {}
    }
});
