use crate::shimcache;
use anyhow::{bail, Result};
use regf::{hive::RegistryKey, RegistryHive};
use rusqlite::{params, Connection, Transaction};
use sha2::{Digest, Sha256};
use std::path::Path;

fn schema(c: &Connection) -> Result<()> {
    c.execute_batch("PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS registry_values(Hive TEXT,KeyPath TEXT,ValueName TEXT,ValueType TEXT,ValueData TEXT,DataSHA256 TEXT,CellState TEXT,PRIMARY KEY(Hive,KeyPath,ValueName));CREATE INDEX IF NOT EXISTS idx_registry_path ON registry_values(KeyPath);CREATE TABLE IF NOT EXISTS amcache_inventory(InventoryType TEXT,EntryID TEXT,KeyPath TEXT,ValueName TEXT,ValueType TEXT,ValueData TEXT,DataSHA256 TEXT);")?;
    Ok(())
}

fn visit(
    key: &RegistryKey<'_>,
    path: &str,
    hive: &str,
    amcache: bool,
    tx: &Transaction<'_>,
) -> Result<usize> {
    let mut count = 0;
    for value in key.values().unwrap_or_default() {
        let name = if value.is_default() {
            "(default)".into()
        } else {
            value.name()
        };
        let kind = value.data_type().name();
        let raw = value.raw_data().unwrap_or_default();
        let data = value
            .data()
            .map(|v| format!("{v:?}"))
            .unwrap_or_else(|_| raw.iter().map(|b| format!("{b:02x}")).collect());
        let hash = format!("{:x}", Sha256::digest(&raw));
        tx.execute(
            "INSERT OR REPLACE INTO registry_values VALUES(?1,?2,?3,?4,?5,?6,'Allocated')",
            params![hive, path, name, kind, data, hash],
        )?;
        if amcache {
            let lower = path.to_ascii_lowercase();
            if let Some(pos) = lower.find("inventory") {
                let inventory = path[pos..].split('\\').next().unwrap_or("Unknown");
                let entry = path.rsplit('\\').next().unwrap_or("");
                tx.execute(
                    "INSERT INTO amcache_inventory VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![inventory, entry, path, name, kind, data, hash],
                )?;
            }
        }
        count += 1;
    }
    for child in key.subkeys().unwrap_or_default() {
        let child_path = if path.is_empty() {
            child.name()
        } else {
            format!("{path}\\{}", child.name())
        };
        count += visit(&child, &child_path, hive, amcache, tx)?;
    }
    Ok(count)
}

pub fn run(input: &Path, output: &Path, amcache: bool) -> Result<usize> {
    let parsed = RegistryHive::from_file(input)?;
    let root = parsed.root_key()?;
    let mut db = Connection::open(output)?;
    schema(&db)?;
    let tx = db.transaction()?;
    let hive = input.file_name().unwrap_or_default().to_string_lossy();
    let count = visit(&root, &root.name(), &hive, amcache, &tx)?;
    tx.commit()?;
    Ok(count)
}

pub fn shimcache_hive(input: &Path, output: &Path) -> Result<usize> {
    let hive = RegistryHive::from_file(input)?;
    for set in ["ControlSet001", "ControlSet002", "CurrentControlSet"] {
        let path = format!(r"{set}\Control\Session Manager\AppCompatCache");
        if let Ok(key) = hive.open_key(&path) {
            if let Ok(value) = key.value("AppCompatCache") {
                return shimcache::run_bytes(&value.raw_data()?, output);
            }
        }
    }
    bail!("AppCompatCache value not found in SYSTEM hive")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn rejects_non_registry_input() {
        let root = std::env::temp_dir().join(format!("vamparser-registry-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let input = root.join("SYSTEM");
        fs::write(&input, b"not a registry hive").unwrap();
        assert!(run(&input, &root.join("registry.db"), false).is_err());
        assert!(shimcache_hive(&input, &root.join("shimcache.db")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
