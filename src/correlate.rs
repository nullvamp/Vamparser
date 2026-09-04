use anyhow::Result;
use rusqlite::{params, Connection};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

#[derive(Clone)]
struct Node {
    name: String,
    parent: u64,
    sequence: u16,
    volume: String,
    size: u64,
    flags: u16,
}
fn path_for(id: u64, nodes: &HashMap<u64, Node>, cache: &mut HashMap<u64, String>) -> String {
    if let Some(x) = cache.get(&id) {
        return x.clone();
    }
    let mut chain = Vec::new();
    let mut current = id;
    let mut seen = HashSet::new();
    while seen.insert(current) {
        let Some(n) = nodes.get(&current) else { break };
        if !n.name.is_empty() {
            chain.push(n.name.clone())
        }
        if n.parent == current || n.parent == 5 {
            break;
        }
        current = n.parent
    }
    chain.reverse();
    let path = format!("C:\\{}", chain.join("\\"));
    cache.insert(id, path.clone());
    path
}
fn schema(c: &Connection) -> Result<()> {
    c.execute_batch("PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS mft_usn_correlated(volume_letter TEXT,mft_record_number INTEGER,fn_filename TEXT,mft_sequence_number INTEGER,mft_flags INTEGER,is_directory INTEGER,is_deleted INTEGER,file_size INTEGER,reconstructed_path TEXT,usn_event_id INTEGER,usn_timestamp TEXT,usn_reason TEXT,usn_source_info TEXT,usn_file_attributes TEXT,usn_filename TEXT,usn_frn TEXT,usn_parent_frn TEXT,usn_security_id INTEGER,has_mft_record INTEGER,has_usn_event INTEGER,correlation_confidence TEXT,created_at TEXT,UNIQUE(volume_letter,mft_record_number,mft_sequence_number,usn_event_id));CREATE INDEX IF NOT EXISTS idx_corr_path ON mft_usn_correlated(reconstructed_path);")?;
    Ok(())
}
pub fn run(mft_path: &Path, usn_path: &Path, output: &Path) -> Result<usize> {
    let mft = Connection::open(mft_path)?;
    let mut nodes = HashMap::new();
    let mut stmt=mft.prepare("SELECT r.record_number,r.file_name,f.parent_record,r.mft_sequence_number,r.volume_letter,r.file_size,r.flags FROM mft_records r LEFT JOIN mft_file_names f ON f.record_number=r.record_number AND f.volume_letter=r.volume_letter")?;
    for row in stmt.query_map([], |r| {
        Ok((
            r.get::<_, u64>(0)?,
            Node {
                name: r.get(1)?,
                parent: r.get(2).unwrap_or(5),
                sequence: r.get(3)?,
                volume: r.get(4)?,
                size: r.get(5)?,
                flags: r.get(6)?,
            },
        ))
    })? {
        let (id, node) = row?;
        nodes.entry(id).or_insert(node);
    }
    let usn = Connection::open(usn_path)?;
    let mut query=usn.prepare("SELECT filename,usn,timestamp,reason,source_info,security_id,file_attributes,frn,parent_frn FROM journal_events ORDER BY usn")?;
    let mut out = Connection::open(output)?;
    schema(&out)?;
    let tx = out.transaction()?;
    let mut cache = HashMap::new();
    let mut count = 0;
    for row in query.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, u32>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, String>(8)?,
        ))
    })? {
        let (name, event, time, reason, source, security, attrs, frn, parent) = row?;
        let id = frn
            .split('-')
            .next()
            .and_then(|x| x.parse::<u64>().ok())
            .unwrap_or(0);
        let node = nodes.get(&id);
        let reconstructed = path_for(id, &nodes, &mut cache);
        tx.execute("INSERT OR IGNORE INTO mft_usn_correlated VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,1,?20,?21)",params![node.map(|n|n.volume.as_str()).unwrap_or("C:"),id,node.map(|n|n.name.as_str()).unwrap_or(&name),node.map(|n|n.sequence).unwrap_or(0),node.map(|n|n.flags).unwrap_or(0),node.is_some_and(|n|n.flags&2!=0),node.is_some_and(|n|n.flags&1==0),node.map(|n|n.size).unwrap_or(0),reconstructed,event,time,reason,source,attrs,name,frn,parent,security,node.is_some(),if node.is_some(){"High"}else{"USN only"},crate::time::now()])?;
        count += 1
    }
    tx.commit()?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn correlates_known_record_and_marks_missing_record() {
        let root = std::env::temp_dir().join(format!("vamparser-correlate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let mft = Connection::open(root.join("mft.db")).unwrap();
        mft.execute_batch("CREATE TABLE mft_records(record_number INTEGER,file_name TEXT,mft_sequence_number INTEGER,volume_letter TEXT,file_size INTEGER,flags INTEGER);CREATE TABLE mft_file_names(record_number INTEGER,volume_letter TEXT,parent_record INTEGER);INSERT INTO mft_records VALUES(42,'known.txt',1,'C:',10,1);INSERT INTO mft_file_names VALUES(42,'C:',5);").unwrap();
        drop(mft);
        let usn = Connection::open(root.join("usn.db")).unwrap();
        usn.execute_batch("CREATE TABLE journal_events(filename TEXT,usn INTEGER,timestamp TEXT,reason TEXT,source_info TEXT,security_id INTEGER,file_attributes TEXT,frn TEXT,parent_frn TEXT);INSERT INTO journal_events VALUES('known.txt',1,NULL,'FILE_CREATE','0x0',0,'ARCHIVE','42-1','5-1');INSERT INTO journal_events VALUES('missing.txt',2,NULL,'FILE_CREATE','0x0',0,'ARCHIVE','99-1','5-1');").unwrap();
        drop(usn);
        let output = root.join("out.db");
        assert_eq!(
            run(&root.join("mft.db"), &root.join("usn.db"), &output).unwrap(),
            2
        );
        let db = Connection::open(output).unwrap();
        let high: i64 = db
            .query_row(
                "SELECT count(*) FROM mft_usn_correlated WHERE correlation_confidence='High'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let missing: i64 = db
            .query_row(
                "SELECT count(*) FROM mft_usn_correlated WHERE correlation_confidence='USN only'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!((high, missing), (1, 1));
        drop(db);
        fs::remove_dir_all(root).unwrap();
    }
}
