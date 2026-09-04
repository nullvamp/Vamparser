use anyhow::Result;
use evtx::EvtxParser;
use rusqlite::{params, Connection};
use serde_json::Value;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn files(p: &Path) -> Vec<PathBuf> {
    if p.is_file() {
        vec![p.to_owned()]
    } else {
        let mut v: Vec<_> = WalkDir::new(p)
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| {
                x.file_type().is_file()
                    && x.path()
                        .extension()
                        .is_some_and(|e| e.eq_ignore_ascii_case("evtx"))
            })
            .map(|x| x.into_path())
            .collect();
        v.sort();
        v
    }
}
fn text(v: Option<&Value>) -> Option<String> {
    v.map(|x| match x {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => x.to_string(),
    })
}
fn schema(c: &Connection) -> Result<()> {
    c.execute_batch("PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS evtx_events(SourceFile TEXT,RecordID INTEGER,EventID INTEGER,Provider TEXT,Channel TEXT,Computer TEXT,UserID TEXT,Level TEXT,Task TEXT,Opcode TEXT,Keywords TEXT,EventTimestampUTC TEXT,EventData TEXT,RawJSON TEXT,PRIMARY KEY(SourceFile,RecordID));CREATE INDEX IF NOT EXISTS idx_evtx_eventid ON evtx_events(EventID);CREATE INDEX IF NOT EXISTS idx_evtx_time ON evtx_events(EventTimestampUTC);")?;
    Ok(())
}
pub fn run(input: &Path, output: &Path) -> Result<usize> {
    let mut db = Connection::open(output)?;
    schema(&db)?;
    let tx = db.transaction()?;
    let mut count = 0;
    for p in files(input) {
        let mut parser = match EvtxParser::from_path(&p) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Skipped {}: {e}", p.display());
                continue;
            }
        };
        for item in parser.records_json_value() {
            let Ok(r) = item else { continue };
            let sys = r.data.pointer("/Event/System").unwrap_or(&Value::Null);
            let event_id = text(
                sys.get("EventID")
                    .and_then(|x| x.get("#text"))
                    .or_else(|| sys.get("EventID")),
            )
            .and_then(|x| x.parse::<i64>().ok());
            let provider = text(
                sys.pointer("/Provider/#attributes/Name")
                    .or_else(|| sys.pointer("/Provider/Name")),
            );
            let channel = text(sys.get("Channel"));
            let computer = text(sys.get("Computer"));
            let user = text(sys.pointer("/Security/#attributes/UserID"));
            let level = text(sys.get("Level"));
            let task = text(sys.get("Task"));
            let opcode = text(sys.get("Opcode"));
            let keywords = text(sys.get("Keywords"));
            let event_data = r
                .data
                .pointer("/Event/EventData")
                .or_else(|| r.data.pointer("/Event/UserData"))
                .map(Value::to_string);
            tx.execute("INSERT OR REPLACE INTO evtx_events VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",params![p.file_name().unwrap_or_default().to_string_lossy(),r.event_record_id,event_id,provider,channel,computer,user,level,task,opcode,keywords,r.timestamp.to_string(),event_data,r.data.to_string()])?;
            count += 1
        }
    }
    tx.commit()?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn skips_invalid_evtx_without_inventing_rows() {
        let root = std::env::temp_dir().join(format!("vamparser-evtx-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("broken.evtx"), b"not an event log").unwrap();
        let output = root.join("events.db");
        assert_eq!(run(&root, &output).unwrap(), 0);
        let db = Connection::open(output).unwrap();
        let count: i64 = db
            .query_row("SELECT count(*) FROM evtx_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        drop(db);
        fs::remove_dir_all(root).unwrap();
    }
}
