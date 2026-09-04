use anyhow::Result;
use libesedb::{EseDb, Value};
use rusqlite::{params, Connection};
use serde_json::{Map, Value as JsonValue};
use std::{collections::HashMap, path::Path, time::Instant};

fn schema(c: &Connection) -> Result<()> {
    c.execute_batch(r#"PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS srum_records(TableName TEXT,RecordIndex INTEGER,RecordJSON TEXT,PRIMARY KEY(TableName,RecordIndex));
CREATE INDEX IF NOT EXISTS idx_srum_table ON srum_records(TableName);
CREATE TABLE IF NOT EXISTS srum_metadata(id INTEGER PRIMARY KEY AUTOINCREMENT,parsed_at TEXT NOT NULL,srudb_path TEXT,total_records_parsed INTEGER,parsing_duration_seconds REAL,windows_version TEXT,notes TEXT);
CREATE VIEW IF NOT EXISTS srum_application_usage AS SELECT RecordIndex id,json_extract(RecordJSON,'$.TimeStamp') timestamp,json_extract(RecordJSON,'$.AppId') app_id,json_extract(RecordJSON,'$.AppName') app_name,json_extract(RecordJSON,'$.UserId') user_id,json_extract(RecordJSON,'$.UserSid') user_sid,json_extract(RecordJSON,'$.ForegroundCycleTime') foreground_cycle_time,json_extract(RecordJSON,'$.BackgroundCycleTime') background_cycle_time,json_extract(RecordJSON,'$.FaceTime') face_time,json_extract(RecordJSON,'$.ForegroundBytesRead') foreground_bytes_read,json_extract(RecordJSON,'$.ForegroundBytesWritten') foreground_bytes_written,json_extract(RecordJSON,'$.BackgroundBytesRead') background_bytes_read,json_extract(RecordJSON,'$.BackgroundBytesWritten') background_bytes_written FROM srum_records WHERE TableName='{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}';
CREATE VIEW IF NOT EXISTS srum_network_data_usage AS SELECT RecordIndex id,json_extract(RecordJSON,'$.TimeStamp') timestamp,json_extract(RecordJSON,'$.AppId') app_id,json_extract(RecordJSON,'$.AppName') app_name,json_extract(RecordJSON,'$.UserId') user_id,json_extract(RecordJSON,'$.UserSid') user_sid,json_extract(RecordJSON,'$.InterfaceLuid') interface_luid,json_extract(RecordJSON,'$.L2ProfileId') l2_profile_id,json_extract(RecordJSON,'$.BytesSent') bytes_sent,json_extract(RecordJSON,'$.BytesRecvd') bytes_received FROM srum_records WHERE TableName='{973F5D5C-1D90-4944-BE8E-24B94231A174}';
CREATE VIEW IF NOT EXISTS srum_network_connectivity AS SELECT RecordIndex id,json_extract(RecordJSON,'$.TimeStamp') timestamp,json_extract(RecordJSON,'$.AppName') app_name,json_extract(RecordJSON,'$.UserSid') user_sid,json_extract(RecordJSON,'$.InterfaceLuid') interface_luid,json_extract(RecordJSON,'$.ConnectedTime') connected_time,json_extract(RecordJSON,'$.ConnectStartTime') connect_start_time FROM srum_records WHERE TableName='{DD6636C4-8929-4683-974E-22C046A43763}';
CREATE VIEW IF NOT EXISTS srum_energy_usage AS SELECT RecordIndex id,json_extract(RecordJSON,'$.TimeStamp') timestamp,json_extract(RecordJSON,'$.AppName') app_name,json_extract(RecordJSON,'$.UserSid') user_sid,RecordJSON FROM srum_records WHERE TableName='{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}';"#)?;
    Ok(())
}

fn value_string(v: Value) -> String {
    if let Some(t) = v.to_oletime() {
        let d: chrono::DateTime<chrono::Utc> = t.into();
        return d.to_rfc3339();
    }
    v.to_string()
}
fn decode_utf16(bytes: &[u8]) -> String {
    String::from_utf16_lossy(
        &bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect::<Vec<_>>(),
    )
    .trim_end_matches('\0')
    .to_string()
}
fn decode_sid(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let count = bytes[1] as usize;
    if bytes.len() < 8 + count * 4 {
        return None;
    }
    let authority = bytes[2..8].iter().fold(0u64, |n, b| (n << 8) | *b as u64);
    let mut sid = format!("S-{}-{authority}", bytes[0]);
    for i in 0..count {
        let p = 8 + i * 4;
        sid.push_str(&format!(
            "-{}",
            u32::from_le_bytes(bytes[p..p + 4].try_into().ok()?)
        ));
    }
    Some(sid)
}
fn id_map(ese: &EseDb) -> Result<(HashMap<u32, String>, HashMap<u32, String>)> {
    let (mut apps, mut users) = (HashMap::new(), HashMap::new());
    for tr in ese.iter_tables()? {
        let Ok(t) = tr else { continue };
        if t.name().unwrap_or_default() != "SruDbIdMapTable" {
            continue;
        }
        let cols: Vec<String> = t
            .iter_columns()?
            .filter_map(|c| c.ok()?.name().ok())
            .collect();
        for rr in t.iter_records()? {
            let Ok(r) = rr else { continue };
            let vals: Vec<Value> = r.iter_values()?.filter_map(Result::ok).collect();
            let get = |n: &str| cols.iter().position(|c| c == n).and_then(|i| vals.get(i));
            let Some(index) = get("IdIndex").and_then(Value::to_u32) else {
                continue;
            };
            let kind = get("IdType").and_then(Value::to_u32).unwrap_or(u32::MAX);
            let Some(blob) = get("IdBlob").and_then(Value::as_bytes) else {
                continue;
            };
            if kind == 0 {
                apps.insert(index, decode_utf16(blob));
            } else if kind == 3 {
                if let Some(s) = decode_sid(blob) {
                    users.insert(index, s);
                }
            }
        }
    }
    Ok((apps, users))
}
pub fn run(input: &Path, output: &Path) -> Result<usize> {
    let start = Instant::now();
    let ese = EseDb::open(input)?;
    let (apps, users) = id_map(&ese)?;
    let mut db = Connection::open(output)?;
    schema(&db)?;
    let tx = db.transaction()?;
    let mut total = 0usize;
    for tr in ese.iter_tables()? {
        let Ok(t) = tr else { continue };
        let name = t.name().unwrap_or_else(|_| "Unknown".into());
        let cols: Vec<String> = t
            .iter_columns()?
            .map(|c| c.and_then(|x| x.name()))
            .map(|x| x.unwrap_or_else(|_| "Unknown".into()))
            .collect();
        for (index, rr) in t.iter_records()?.enumerate() {
            let Ok(r) = rr else { continue };
            let mut object = Map::new();
            for (i, vr) in r.iter_values()?.enumerate() {
                let value = vr.map(value_string).unwrap_or_default();
                object.insert(
                    cols.get(i).cloned().unwrap_or_else(|| format!("Column{i}")),
                    JsonValue::String(value),
                );
            }
            if let Some(id) = object
                .get("AppId")
                .and_then(JsonValue::as_str)
                .and_then(|s| s.parse().ok())
            {
                if let Some(v) = apps.get(&id) {
                    object.insert("AppName".into(), JsonValue::String(v.clone()));
                }
            }
            if let Some(id) = object
                .get("UserId")
                .and_then(JsonValue::as_str)
                .and_then(|s| s.parse().ok())
            {
                if let Some(v) = users.get(&id) {
                    object.insert("UserSid".into(), JsonValue::String(v.clone()));
                }
            }
            tx.execute(
                "INSERT OR REPLACE INTO srum_records VALUES(?1,?2,?3)",
                params![name, index, JsonValue::Object(object).to_string()],
            )?;
            total += 1
        }
    }
    tx.execute("INSERT INTO srum_metadata(parsed_at,srudb_path,total_records_parsed,parsing_duration_seconds,notes)VALUES(?1,?2,?3,?4,?5)",params![crate::time::now(),input.display().to_string(),total,start.elapsed().as_secs_f64(),format!("All ESE tables preserved; resolved {} application and {} user identifiers",apps.len(),users.len())])?;
    tx.commit()?;
    Ok(total)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn sid() {
        assert_eq!(
            decode_sid(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]).as_deref(),
            Some("S-1-5-18")
        );
    }
    #[test]
    fn utf16() {
        assert_eq!(decode_utf16(&[65, 0, 66, 0, 0, 0]), "AB");
    }
    #[test]
    fn rejects_non_ese_input() {
        let root = std::env::temp_dir().join(format!("vamparser-srum-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let input = root.join("SRUDB.dat");
        fs::write(&input, b"not an ESE database").unwrap();
        assert!(run(&input, &root.join("srum.db")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
