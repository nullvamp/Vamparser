use crate::time;
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

#[derive(Debug)]
struct Entry {
    path: String,
    modified: Option<String>,
    data_size: u32,
    entry_size: u32,
    position: u32,
    hash: String,
}
fn u16le(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2).context("truncated u16")?.try_into()?,
    ))
}
fn u32le(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4).context("truncated u32")?.try_into()?,
    ))
}
fn u64le(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8).context("truncated u64")?.try_into()?,
    ))
}
fn utf16(b: &[u8]) -> String {
    String::from_utf16_lossy(
        &b.as_chunks::<2>()
            .0
            .iter()
            .map(|x| u16::from_le_bytes([x[0], x[1]]))
            .collect::<Vec<_>>(),
    )
}
fn parse(b: &[u8]) -> Result<Vec<Entry>> {
    if b.windows(4).any(|x| x == b"10ts") {
        parse_modern(b)
    } else if b
        .get(..200.min(b.len()))
        .is_some_and(|x| x.windows(4).any(|w| w == [0x30, 0, 0, 0]))
    {
        parse_win7(b)
    } else {
        bail!("unrecognized ShimCache format")
    }
}
fn parse_modern(b: &[u8]) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    let mut at = b
        .windows(4)
        .position(|x| x == b"10ts")
        .context("no Windows 10/11 cache entries")?;
    if at + 16 > b.len() {
        bail!("truncated ShimCache entry header")
    };
    while at + 16 <= b.len() {
        if &b[at..at + 4] != b"10ts" {
            if let Some(next) = b[at + 1..].windows(4).position(|x| x == b"10ts") {
                at += next + 1;
                continue;
            }
            break;
        }
        let position = u32::try_from(at).context("entry position overflow")?;
        let entry_size = u32le(b, at + 8)?;
        let path_len = u16le(b, at + 12)? as usize;
        let p0 = at + 14;
        let p1 = p0.checked_add(path_len).context("path overflow")?;
        let path = utf16(b.get(p0..p1).context("truncated path")?);
        let modified = time::forensic(time::filetime(u64le(b, p1)?));
        let data_size = u16le(b, p1 + 8)? as u32;
        let end = p1 + 10 + data_size as usize;
        if end > b.len() {
            bail!("truncated ShimCache entry")
        };
        let hash = format!("{:x}", Sha256::digest(&b[at..end]));
        out.push(Entry {
            path,
            modified,
            data_size,
            entry_size,
            position,
            hash,
        });
        at = end;
    }
    Ok(out)
}
fn parse_win7(b: &[u8]) -> Result<Vec<Entry>> {
    let count = u32le(b, 4)? as usize;
    let mut out = Vec::new();
    let mut at = 8usize;
    for _ in 0..count {
        let header = b.get(at..at + 40).context("truncated Windows 7 entry")?;
        let entry_size = u32le(header, 0)?;
        let path_len = u32le(header, 8)? as usize;
        let path_off = u32le(header, 12)? as usize;
        let modified = time::forensic(time::filetime(u64le(header, 16)?));
        let data_size = u32le(header, 32)?;
        let path = utf16(
            b.get(path_off..path_off.saturating_add(path_len))
                .context("invalid Windows 7 path offset")?,
        );
        let hash = format!("{:x}", Sha256::digest(header));
        out.push(Entry {
            path,
            modified,
            data_size,
            entry_size,
            position: at as u32,
            hash,
        });
        at += 40;
    }
    Ok(out)
}
fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS shimcache_entries(id INTEGER PRIMARY KEY AUTOINCREMENT,filename TEXT NOT NULL,path TEXT NOT NULL,last_modified TEXT,last_modified_readable TEXT,data_size INTEGER DEFAULT 0,entry_size INTEGER DEFAULT 0,cache_entry_position INTEGER DEFAULT 0,entry_hash TEXT UNIQUE,parsed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,UNIQUE(path,last_modified));")?;
    Ok(())
}
pub fn run(input: &Path, output: &Path) -> Result<usize> {
    run_bytes(&fs::read(input)?, output)
}
pub fn run_bytes(b: &[u8], output: &Path) -> Result<usize> {
    let entries = parse(b)?;
    let mut db = Connection::open(output)?;
    schema(&db)?;
    let tx = db.transaction()?;
    let mut n = 0;
    for e in entries {
        let filename = Path::new(&e.path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        n+=tx.execute("INSERT OR IGNORE INTO shimcache_entries(filename,path,last_modified,last_modified_readable,data_size,entry_size,cache_entry_position,entry_hash) VALUES(?1,?2,?3,?3,?4,?5,?6,?7)",params![filename,e.path,e.modified,e.data_size,e.entry_size,e.position,e.hash])?;
    }
    tx.commit()?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_empty_and_truncated_data() {
        assert!(parse(&[]).is_err());
        assert!(parse(b"10ts").is_err());
    }
}
