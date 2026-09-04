use crate::time;
use anyhow::Result;
use rusqlite::{params, Connection};
use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

fn u16le(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn u32le(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn u64le(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}
fn i64le(b: &[u8], o: usize) -> Option<i64> {
    Some(i64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
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
fn stamp(v: u64) -> Option<String> {
    time::forensic(time::filetime(v))
}

fn apply_fixup(record: &mut [u8]) -> bool {
    let Some(off) = u16le(record, 4).map(usize::from) else {
        return false;
    };
    let Some(count) = u16le(record, 6).map(usize::from) else {
        return false;
    };
    if count < 2 {
        return false;
    }
    let Some(usn) = record.get(off..off + 2).map(|x| [x[0], x[1]]) else {
        return false;
    };
    let sector_size = record.len() / (count - 1);
    if !matches!(sector_size, 512 | 1024 | 2048 | 4096) {
        return false;
    }
    for i in 1..count {
        let end = i * sector_size;
        if end < 2 || end > record.len() || record[end - 2..end] != usn {
            return false;
        }
        let Some(repl) = record
            .get(off + i * 2..off + i * 2 + 2)
            .map(|x| [x[0], x[1]])
        else {
            return false;
        };
        record[end - 2..end].copy_from_slice(&repl)
    }
    true
}

struct MftRow {
    number: u64,
    sequence: u16,
    flags: u16,
    name: String,
    parent: u64,
    parent_sequence: u16,
    namespace: u8,
    size: u64,
    allocated: u64,
    created: Option<String>,
    modified: Option<String>,
    accessed: Option<String>,
    changed: Option<String>,
    attrs: u32,
    has_ads: bool,
    ads: u32,
}

fn parse_mft_record(raw: &[u8], fallback: u64) -> Option<MftRow> {
    let mut b = raw.to_vec();
    if b.get(..4)? != b"FILE" || !apply_fixup(&mut b) {
        return None;
    }
    let attrs_off = u16le(&b, 20)? as usize;
    let flags = u16le(&b, 22)?;
    let number = u32le(&b, 44)
        .map(u64::from)
        .filter(|x| *x != 0)
        .unwrap_or(fallback);
    let sequence = u16le(&b, 16)?;
    let mut row = MftRow {
        number,
        sequence,
        flags,
        name: String::new(),
        parent: 0,
        parent_sequence: 0,
        namespace: 0,
        size: 0,
        allocated: 0,
        created: None,
        modified: None,
        accessed: None,
        changed: None,
        attrs: 0,
        has_ads: false,
        ads: 0,
    };
    let mut at = attrs_off;
    let mut best_name = -1i8;
    while at + 16 <= b.len() {
        let kind = u32le(&b, at)?;
        if kind == 0xffff_ffff {
            break;
        }
        let len = u32le(&b, at + 4)? as usize;
        if len < 16 || at.checked_add(len)? > b.len() {
            break;
        }
        let nonresident = *b.get(at + 8)? != 0;
        let name_len = *b.get(at + 9)? as usize;
        let value = if !nonresident {
            let n = u32le(&b, at + 16)? as usize;
            let o = u16le(&b, at + 20)? as usize;
            b.get(at + o..at + o + n)
        } else {
            None
        };
        match (kind, value) {
            (0x10, Some(v)) if v.len() >= 36 => {
                row.created = stamp(u64le(v, 0)?);
                row.modified = stamp(u64le(v, 8)?);
                row.changed = stamp(u64le(v, 16)?);
                row.accessed = stamp(u64le(v, 24)?);
                row.attrs = u32le(v, 32)?
            }
            (0x30, Some(v)) if v.len() >= 66 => {
                let ns = *v.get(65)?;
                let priority = match ns {
                    1 | 3 => 2,
                    0 => 1,
                    _ => 0,
                };
                if priority > best_name {
                    let chars = *v.get(64)? as usize;
                    let n = v.get(66..66 + chars * 2)?;
                    row.name = utf16(n);
                    let pref = u64le(v, 0)?;
                    row.parent = pref & 0x0000_ffff_ffff_ffff;
                    row.parent_sequence = (pref >> 48) as u16;
                    row.namespace = ns;
                    row.created = stamp(u64le(v, 8)?);
                    row.modified = stamp(u64le(v, 16)?);
                    row.changed = stamp(u64le(v, 24)?);
                    row.accessed = stamp(u64le(v, 32)?);
                    row.allocated = u64le(v, 40)?;
                    row.size = u64le(v, 48)?;
                    best_name = priority
                }
            }
            (0x80, _) => {
                if name_len > 0 {
                    row.has_ads = true;
                    row.ads += 1
                }
                if !nonresident {
                    row.size = row.size.max(value.map(|v| v.len() as u64).unwrap_or(0))
                } else if let Some(real) = u64le(&b, at + 48) {
                    row.size = row.size.max(real);
                    row.allocated = row.allocated.max(u64le(&b, at + 40).unwrap_or(0))
                }
            }
            _ => {}
        }
        at += len;
    }
    Some(row)
}

fn mft_schema(c: &Connection) -> Result<()> {
    c.execute_batch("PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS mft_records(record_number INTEGER,file_name TEXT,volume_letter TEXT,extension TEXT,file_size INTEGER,in_use INTEGER,is_directory INTEGER,flags INTEGER,mft_sequence_number INTEGER,has_ads INTEGER DEFAULT 0,ads_count INTEGER DEFAULT 0,created_time TIMESTAMP,modified_time TIMESTAMP,accessed_time TIMESTAMP,mft_modified_time TIMESTAMP,file_attributes INTEGER,PRIMARY KEY(record_number,volume_letter));CREATE TABLE IF NOT EXISTS mft_standard_info(record_number INTEGER,file_name TEXT,volume_letter TEXT,created TIMESTAMP,modified TIMESTAMP,accessed TIMESTAMP,mft_modified TIMESTAMP,flags INTEGER,max_versions INTEGER,version_number INTEGER,class_id INTEGER,owner_id INTEGER,security_id INTEGER,quota_charged INTEGER,usn INTEGER);CREATE TABLE IF NOT EXISTS mft_file_names(record_number INTEGER,file_name TEXT,volume_letter TEXT,parent_record INTEGER,parent_sequence INTEGER,namespace INTEGER,created TIMESTAMP,modified TIMESTAMP,accessed TIMESTAMP,mft_modified TIMESTAMP,allocated_size INTEGER,real_size INTEGER,flags INTEGER);CREATE TABLE IF NOT EXISTS mft_data_attributes(record_number INTEGER,file_name TEXT,volume_letter TEXT,attribute_name TEXT,resident INTEGER,size INTEGER,data_type TEXT DEFAULT 'Default');CREATE INDEX IF NOT EXISTS idx_mft_records_filename ON mft_records(file_name);CREATE INDEX IF NOT EXISTS idx_mft_records_extension ON mft_records(extension);CREATE INDEX IF NOT EXISTS idx_mft_filenames_parent ON mft_file_names(parent_record);")?;
    Ok(())
}
pub fn parse_mft(input: &Path, output: &Path, volume: &str) -> Result<usize> {
    let file = File::open(input)?;
    let size = file.metadata()?.len();
    let record_size = if size % 1024 == 0 { 1024 } else { 4096 };
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut buf = vec![0u8; record_size];
    let mut db = Connection::open(output)?;
    mft_schema(&db)?;
    let tx = db.transaction()?;
    let mut index = 0u64;
    let mut count = 0;
    loop {
        match reader.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        if let Some(r) = parse_mft_record(&buf, index) {
            let ext = Path::new(&r.name)
                .extension()
                .map(|x| x.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            tx.execute("INSERT OR REPLACE INTO mft_records VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",params![r.number,r.name,volume,ext,r.size,(r.flags&1!=0)as u8,(r.flags&2!=0)as u8,r.flags,r.sequence,r.has_ads as u8,r.ads,r.created,r.modified,r.accessed,r.changed,r.attrs])?;
            tx.execute(
                "INSERT INTO mft_file_names VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    r.number,
                    r.name,
                    volume,
                    r.parent,
                    r.parent_sequence,
                    r.namespace,
                    r.created,
                    r.modified,
                    r.accessed,
                    r.changed,
                    r.allocated,
                    r.size,
                    r.attrs
                ],
            )?;
            count += 1
        }
        index += 1
    }
    tx.execute("INSERT INTO mft_standard_info(record_number,file_name,volume_letter,created,modified,accessed,mft_modified,flags) SELECT record_number,file_name,volume_letter,created_time,modified_time,accessed_time,mft_modified_time,file_attributes FROM mft_records WHERE volume_letter=?1",params![volume])?;
    tx.execute("INSERT INTO mft_data_attributes(record_number,file_name,volume_letter,attribute_name,resident,size,data_type) SELECT record_number,file_name,volume_letter,'',NULL,file_size,'Default' FROM mft_records WHERE volume_letter=?1",params![volume])?;
    tx.commit()?;
    Ok(count)
}

fn reason_text(v: u32) -> String {
    const F: &[(u32, &str)] = &[
        (1, "DATA_OVERWRITE"),
        (2, "DATA_EXTEND"),
        (4, "DATA_TRUNCATION"),
        (0x10, "NAMED_DATA_OVERWRITE"),
        (0x20, "NAMED_DATA_EXTEND"),
        (0x40, "NAMED_DATA_TRUNCATION"),
        (0x100, "FILE_CREATE"),
        (0x200, "FILE_DELETE"),
        (0x400, "EA_CHANGE"),
        (0x800, "SECURITY_CHANGE"),
        (0x1000, "RENAME_OLD_NAME"),
        (0x2000, "RENAME_NEW_NAME"),
        (0x4000, "INDEXABLE_CHANGE"),
        (0x8000, "BASIC_INFO_CHANGE"),
        (0x10000, "HARD_LINK_CHANGE"),
        (0x20000, "COMPRESSION_CHANGE"),
        (0x40000, "ENCRYPTION_CHANGE"),
        (0x80000, "OBJECT_ID_CHANGE"),
        (0x100000, "REPARSE_POINT_CHANGE"),
        (0x200000, "STREAM_CHANGE"),
        (0x80000000, "CLOSE"),
    ];
    let s = F
        .iter()
        .filter(|(f, _)| v & f != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(" | ");
    if s.is_empty() {
        format!("0x{v:08X}")
    } else {
        s
    }
}
fn attrs_text(v: u32) -> String {
    let mut x = Vec::new();
    for (f, n) in [
        (1, "READONLY"),
        (2, "HIDDEN"),
        (4, "SYSTEM"),
        (0x10, "DIRECTORY"),
        (0x20, "ARCHIVE"),
        (0x400, "REPARSE_POINT"),
        (0x1000, "OFFLINE"),
    ] {
        if v & f != 0 {
            x.push(n)
        }
    }
    x.join(" | ")
}
fn usn_schema(c: &Connection) -> Result<()> {
    c.execute_batch("PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS journal_events(volume_letter TEXT,filename TEXT,usn INTEGER,major_version INTEGER,frn TEXT,parent_frn TEXT,timestamp TEXT,reason TEXT,source_info TEXT,security_id INTEGER,file_attributes TEXT,record_length INTEGER,parsed_at TEXT,PRIMARY KEY(volume_letter,usn));")?;
    Ok(())
}

struct UsnRow {
    len: usize,
    major: u16,
    frn: u64,
    parent: u64,
    usn: i64,
    timestamp: Option<String>,
    reason: u32,
    source: u32,
    security: u32,
    attrs: u32,
    name: String,
}
fn parse_usn_record(record: &[u8]) -> Option<UsnRow> {
    let len = u32le(record, 0)? as usize;
    let major = u16le(record, 4)?;
    if !(60..=65536).contains(&len) || record.len() < len || !matches!(major, 2..=4) {
        return None;
    }
    let nlen = u16le(record, 56)? as usize;
    let noff = u16le(record, 58)? as usize;
    let end = noff.checked_add(nlen)?;
    if end > len || !nlen.is_multiple_of(2) {
        return None;
    }
    Some(UsnRow {
        len,
        major,
        frn: u64le(record, 8)?,
        parent: u64le(record, 16)?,
        usn: i64le(record, 24)?,
        timestamp: stamp(u64le(record, 32)?),
        reason: u32le(record, 40)?,
        source: u32le(record, 44)?,
        security: u32le(record, 48)?,
        attrs: u32le(record, 52)?,
        name: utf16(record.get(noff..end)?),
    })
}

pub fn parse_usn(input: &Path, output: &Path, volume: &str) -> Result<usize> {
    let mut reader = BufReader::with_capacity(1024 * 1024, File::open(input)?);
    let mut pending = Vec::with_capacity(1024 * 1024 + 65536);
    let mut chunk = vec![0u8; 1024 * 1024];
    let mut db = Connection::open(output)?;
    usn_schema(&db)?;
    let tx = db.transaction()?;
    let mut count = 0;
    loop {
        let read = reader.read(&mut chunk)?;
        if read > 0 {
            pending.extend_from_slice(&chunk[..read])
        }
        let mut at = 0usize;
        while pending.len().saturating_sub(at) >= 60 {
            let len = u32le(&pending, at).unwrap_or(0) as usize;
            let major = u16le(&pending, at + 4).unwrap_or(0);
            if (60..=65536).contains(&len) && matches!(major, 2..=4) {
                if pending.len() - at < len {
                    break;
                }
                if let Some(row) = parse_usn_record(&pending[at..at + len]) {
                    tx.execute("INSERT OR IGNORE INTO journal_events VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",params![volume,row.name,row.usn,row.major,format!("{}-{}",row.frn&0x0000_ffff_ffff_ffff,row.frn>>48),format!("{}-{}",row.parent&0x0000_ffff_ffff_ffff,row.parent>>48),row.timestamp,reason_text(row.reason),format!("0x{:08X}",row.source),row.security,attrs_text(row.attrs),row.len,time::now()])?;
                    count += 1;
                    at += len;
                    continue;
                }
            }
            at += 8
        }
        if at > 0 {
            pending.drain(..at);
        }
        if read == 0 {
            break;
        }
    }
    tx.commit()?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    fn v2(name: &str, usn: i64) -> Vec<u8> {
        let wide = name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let len = (60 + wide.len() + 7) & !7;
        let mut b = vec![0u8; len];
        b[0..4].copy_from_slice(&(len as u32).to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes());
        b[8..16].copy_from_slice(&42u64.to_le_bytes());
        b[16..24].copy_from_slice(&5u64.to_le_bytes());
        b[24..32].copy_from_slice(&usn.to_le_bytes());
        b[40..44].copy_from_slice(&0x100u32.to_le_bytes());
        b[52..56].copy_from_slice(&0x20u32.to_le_bytes());
        b[56..58].copy_from_slice(&(wide.len() as u16).to_le_bytes());
        b[58..60].copy_from_slice(&60u16.to_le_bytes());
        b[60..60 + wide.len()].copy_from_slice(&wide);
        b
    }
    #[test]
    fn parses_v2_and_rejects_truncation() {
        let record = v2("created.txt", 123);
        assert_eq!(parse_usn_record(&record).unwrap().name, "created.txt");
        assert!(parse_usn_record(&record[..40]).is_none());
    }
    #[test]
    fn streams_multiple_records() {
        let root = std::env::temp_dir().join(format!("vamparser-usn-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let input = root.join("$J");
        let output = root.join("usn.db");
        let mut data = v2("one.txt", 1);
        data.extend(v2("two.txt", 2));
        fs::write(&input, data).unwrap();
        assert_eq!(parse_usn(&input, &output, "C:").unwrap(), 2);
        let db = Connection::open(output).unwrap();
        let count: i64 = db
            .query_row("SELECT count(*) FROM journal_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
        drop(db);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn malformed_mft_produces_no_rows() {
        let root = std::env::temp_dir().join(format!("vamparser-mft-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let input = root.join("$MFT");
        fs::write(&input, vec![0u8; 1024]).unwrap();
        let output = root.join("mft.db");
        assert_eq!(parse_mft(&input, &output, "C:").unwrap(), 0);
        let db = Connection::open(output).unwrap();
        let count: i64 = db
            .query_row("SELECT count(*) FROM mft_records", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        drop(db);
        fs::remove_dir_all(root).unwrap();
    }
}
