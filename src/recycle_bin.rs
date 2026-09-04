use crate::time;
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use std::{
    fs,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

#[derive(Debug)]
struct Entry {
    original_path: String,
    deletion: Option<String>,
    size: u64,
    i_path: PathBuf,
    r_path: PathBuf,
    sid: String,
    signature: String,
    status: String,
}
fn u64le(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .context("truncated $I field")?
            .try_into()?,
    ))
}
fn utf16(b: &[u8]) -> String {
    String::from_utf16_lossy(
        &b.as_chunks::<2>()
            .0
            .iter()
            .map(|x| u16::from_le_bytes([x[0], x[1]]))
            .take_while(|x| *x != 0)
            .collect::<Vec<_>>(),
    )
}
fn signature(path: &Path) -> String {
    let Ok(b) = fs::read(path) else {
        return "Missing content".into();
    };
    let h = &b[..b.len().min(16)];
    if h.starts_with(b"MZ") {
        "Windows executable"
    } else if h.starts_with(b"%PDF-") {
        "PDF document"
    } else if h.starts_with(&[0x50, 0x4b, 3, 4]) {
        "ZIP container"
    } else if h.starts_with(&[0xff, 0xd8, 0xff]) {
        "JPEG image"
    } else if h.starts_with(&[0x89, b'P', b'N', b'G']) {
        "PNG image"
    } else {
        "Unknown"
    }
    .into()
}
fn parse(path: &Path) -> Result<Entry> {
    let b = fs::read(path)?;
    if b.len() < 24 {
        bail!("short $I file")
    };
    let version = u64le(&b, 0)?;
    let size = u64le(&b, 8)?;
    let deletion = time::forensic(time::filetime(u64le(&b, 16)?));
    let start = if version >= 2 {
        let chars = u32::from_le_bytes(
            b.get(24..28)
                .context("missing v2 path length")?
                .try_into()?,
        ) as usize;
        let end = 28usize.checked_add(chars * 2).context("path overflow")?;
        utf16(b.get(28..end).context("truncated v2 path")?)
    } else {
        utf16(b.get(24..).unwrap_or_default())
    };
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let suffix = name.strip_prefix("$I").context("not an $I file")?;
    let r_path = path.with_file_name(format!("$R{suffix}"));
    let sid = path
        .parent()
        .and_then(Path::file_name)
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let status = match fs::metadata(&r_path) {
        Ok(m) if m.len() == size => "Recoverable (size matches)",
        Ok(_) => "Partial or changed",
        Err(_) => "Content unavailable",
    }
    .into();
    Ok(Entry {
        original_path: start,
        deletion,
        size,
        i_path: path.to_owned(),
        signature: signature(&r_path),
        r_path,
        sid,
        status,
    })
}
fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS recycle_bin_entries(original_filename TEXT,original_path TEXT,deletion_time TEXT,formatted_file_size TEXT,user_sid TEXT,recycle_bin_path TEXT,r_file_path TEXT,random_i_filename TEXT,random_r_filename TEXT,file_signature TEXT,recovery_status TEXT,parsed_at TEXT);")?;
    Ok(())
}
pub fn run(input: &Path, output: &Path) -> Result<usize> {
    let mut files: Vec<_> = WalkDir::new(input)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file() && e.file_name().to_string_lossy().starts_with("$I"))
        .map(|e| e.into_path())
        .collect();
    files.sort();
    let mut db = Connection::open(output)?;
    schema(&db)?;
    let tx = db.transaction()?;
    let mut n = 0;
    for p in files {
        let e = parse(&p).with_context(|| format!("parse {}", p.display()))?;
        let filename = Path::new(&e.original_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let formatted = if e.size < 1024 {
            format!("{} B", e.size)
        } else if e.size < 1_048_576 {
            format!("{:.2} KB", e.size as f64 / 1024.)
        } else {
            format!("{:.2} MB", e.size as f64 / 1_048_576.)
        };
        tx.execute(
            "INSERT INTO recycle_bin_entries VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                filename,
                e.original_path,
                e.deletion,
                formatted,
                e.sid,
                e.i_path
                    .parent()
                    .unwrap_or(Path::new(""))
                    .display()
                    .to_string(),
                e.r_path.display().to_string(),
                e.i_path.file_name().unwrap_or_default().to_string_lossy(),
                e.r_path.file_name().unwrap_or_default().to_string_lossy(),
                e.signature,
                e.status,
                time::now()
            ],
        )?;
        n += 1
    }
    tx.commit()?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_v2_metadata_and_correlates_content() {
        let root = std::env::temp_dir().join(format!("dfir-recycle-{}", std::process::id()));
        let sid = root.join("S-1-5-21-test");
        fs::create_dir_all(&sid).unwrap();
        let i = sid.join("$IABC");
        let r = sid.join("$RABC");
        let original = r"C:\Users\Test\deleted.pdf";
        let wide: Vec<u8> = original
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut bytes = Vec::new();
        bytes.extend(2u64.to_le_bytes());
        bytes.extend(5u64.to_le_bytes());
        bytes.extend(132_537_600_000_000_000u64.to_le_bytes());
        bytes.extend(((wide.len() / 2) as u32).to_le_bytes());
        bytes.extend(wide);
        fs::write(&i, bytes).unwrap();
        fs::write(&r, b"%PDF").unwrap();
        let entry = parse(&i).unwrap();
        assert_eq!(entry.original_path, original);
        assert_eq!(entry.size, 5);
        assert!(entry.status.contains("changed"));
        fs::remove_dir_all(root).unwrap();
    }
}
