use crate::time;
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

#[derive(Debug, Serialize)]
struct Volume {
    device_path: String,
    serial: String,
    created: Option<String>,
}

#[derive(Debug)]
struct Record {
    source: String,
    executable: String,
    hash: String,
    run_count: u32,
    run_times: Vec<String>,
    volumes: Vec<Volume>,
    resources: Vec<String>,
    directories: Vec<String>,
    created: Option<String>,
    modified: Option<String>,
    accessed: Option<String>,
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
    let words: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|x| u16::from_le_bytes([x[0], x[1]]))
        .take_while(|x| *x != 0)
        .collect();
    String::from_utf16_lossy(&words)
}
fn utf16_all(b: &[u8]) -> String {
    String::from_utf16_lossy(
        &b.as_chunks::<2>()
            .0
            .iter()
            .map(|x| u16::from_le_bytes([x[0], x[1]]))
            .collect::<Vec<_>>(),
    )
}
fn range(b: &[u8], off: u32, len: u32) -> Result<&[u8]> {
    let start = off as usize;
    let end = start.checked_add(len as usize).context("offset overflow")?;
    b.get(start..end).context("offset outside file")
}

fn parse(path: &Path) -> Result<Record> {
    let source = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let b = if source.starts_with(b"MAM") {
        let expected = u32le(&source, 4)? as usize;
        if expected > 256 * 1024 * 1024 {
            bail!("declared Prefetch size is unreasonable");
        }
        xpress_huffman::decompress(source.get(8..).context("truncated MAM header")?, expected)
            .map_err(|e| anyhow::anyhow!("XPRESS-Huffman decompression failed: {e}"))?
    } else {
        source
    };
    if b.len() < 84 {
        bail!("{} is too short for a Prefetch file", path.display());
    }
    if &b[4..8] != b"SCCA" {
        bail!("{} has no SCCA signature", path.display());
    }
    let version = u32le(&b, 0)?;
    if !matches!(version, 17 | 23 | 26 | 30 | 31) {
        bail!("unsupported Prefetch version {version}");
    }
    let executable = utf16(&b[16..76]);
    let hash = format!("{:08X}", u32le(&b, 76)?);
    let info = 84usize;
    let names_off = u32le(&b, info + 16)?;
    let names_len = u32le(&b, info + 20)?;
    let names = range(&b, names_off, names_len)?;
    let resources = utf16_all(names)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let volumes_off = u32le(&b, info + 24)?;
    let volume_count = u32le(&b, info + 28)?;
    let volume_size = u32le(&b, info + 32)?;
    let volume_blob = range(&b, volumes_off, volume_size).unwrap_or_default();
    let entry_size = if version == 17 {
        40
    } else if matches!(version, 23 | 26) {
        104
    } else {
        96
    };
    let mut volumes = Vec::new();
    let mut directories = Vec::new();
    for i in 0..volume_count as usize {
        let base = i.checked_mul(entry_size).context("volume index overflow")?;
        let Some(entry) = volume_blob.get(base..base + entry_size) else {
            break;
        };
        let dev_off = u32le(entry, 0)?;
        let dev_chars = u32le(entry, 4)?;
        let dev =
            utf16(range(volume_blob, dev_off, dev_chars.saturating_mul(2)).unwrap_or_default());
        let serial = format!("{:X}", u32le(entry, 16)?);
        let created = time::forensic(time::filetime(u64le(entry, 8)?));
        volumes.push(Volume {
            device_path: dev,
            serial,
            created,
        });
        let dir_off = u32le(entry, 28)? as usize;
        let dir_count = u32le(entry, 32)? as usize;
        let mut cursor = dir_off;
        for _ in 0..dir_count {
            let Some(size_bytes) = volume_blob.get(cursor..cursor + 2) else {
                break;
            };
            let chars = u16::from_le_bytes(size_bytes.try_into()?) as usize;
            cursor += 2;
            let bytes = chars.checked_mul(2).context("directory size overflow")?;
            let Some(value) = volume_blob.get(cursor..cursor + bytes) else {
                break;
            };
            directories.push(utf16(value));
            cursor = cursor.saturating_add(bytes + 2);
        }
    }
    let (run_at, run_slots, count_at) = match version {
        17 => (info + 36, 1, info + 60),
        23 => (info + 44, 1, info + 68),
        26 => (info + 44, 8, info + 116),
        _ => (info + 44, 8, info + 124),
    };
    let mut run_times = Vec::new();
    for i in 0..run_slots {
        if let Some(dt) = time::forensic(time::filetime(u64le(&b, run_at + i * 8)?)) {
            run_times.push(dt)
        }
    }
    let run_count = u32le(&b, count_at)?;
    let meta = fs::metadata(path)?;
    let stamp = |x: std::io::Result<std::time::SystemTime>| {
        x.ok()
            .map(chrono::DateTime::<chrono::Utc>::from)
            .and_then(|v| time::forensic(Some(v)))
    };
    Ok(Record {
        source: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        executable,
        hash,
        run_count,
        run_times,
        volumes,
        directories,
        resources,
        created: stamp(meta.created()),
        modified: stamp(meta.modified()),
        accessed: stamp(meta.accessed()),
    })
}

fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS prefetch_data(filename TEXT,executable_name TEXT,hash TEXT,run_count INTEGER,last_executed TIMESTAMP,run_times JSON,volumes JSON,directories JSON,resources JSON,created_on TIMESTAMP,modified_on TIMESTAMP,accessed_on TIMESTAMP,PRIMARY KEY(filename,hash));")?;
    Ok(())
}

pub fn run(input: &Path, output: &Path) -> Result<usize> {
    let mut paths: Vec<PathBuf> = if input.is_dir() {
        WalkDir::new(input)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_type().is_file()
                    && e.path()
                        .extension()
                        .is_some_and(|x| x.eq_ignore_ascii_case("pf"))
            })
            .map(|e| e.into_path())
            .collect()
    } else {
        vec![input.to_owned()]
    };
    paths.sort();
    let mut db = Connection::open(output)?;
    schema(&db)?;
    let tx = db.transaction()?;
    let mut n = 0;
    for p in paths {
        let r = match parse(&p) {
            Ok(record) => record,
            Err(error) => {
                eprintln!("Skipped {}: {error:#}", p.display());
                continue;
            }
        };
        let last = r.run_times.first().cloned();
        tx.execute("INSERT INTO prefetch_data VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT(filename,hash) DO UPDATE SET run_count=excluded.run_count,last_executed=excluded.last_executed,run_times=excluded.run_times,volumes=excluded.volumes,directories=excluded.directories,resources=excluded.resources,created_on=excluded.created_on,modified_on=excluded.modified_on,accessed_on=excluded.accessed_on",params![r.source,r.executable,r.hash,r.run_count,last,serde_json::to_string(&r.run_times)?,serde_json::to_string(&r.volumes)?,serde_json::to_string(&r.directories)?,serde_json::to_string(&r.resources)?,r.created,r.modified,r.accessed])?;
        n += 1;
    }
    tx.commit()?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn rejects_short_and_bad_signature() {
        let root = std::env::temp_dir().join(format!("vamparser-prefetch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let short = root.join("short.pf");
        fs::write(&short, [0u8; 20]).unwrap();
        assert!(parse(&short).is_err());
        let bad = root.join("bad.pf");
        let mut bytes = vec![0u8; 100];
        bytes[0..4].copy_from_slice(&30u32.to_le_bytes());
        fs::write(&bad, bytes).unwrap();
        assert!(parse(&bad).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
