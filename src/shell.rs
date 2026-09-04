use anyhow::Result;
use lnk_core::{
    parse_automatic_destinations, parse_custom_destinations, parse_shell_link, JumpListKind,
    ShellLink,
};
use rusqlite::{params, Connection};
use std::{
    fs,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

fn paths(input: &Path, predicate: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    if input.is_file() {
        vec![input.to_owned()]
    } else {
        let mut v: Vec<_> = WalkDir::new(input)
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| x.file_type().is_file() && predicate(x.path()))
            .map(|x| x.into_path())
            .collect();
        v.sort();
        v
    }
}
fn epoch(v: i64) -> Option<String> {
    if v == 0 {
        None
    } else {
        chrono::DateTime::from_timestamp(v, 0)
            .map(|x| x.format("%Y-%m-%d %H:%M:%S UTC").to_string())
    }
}
fn target(l: &ShellLink) -> Option<String> {
    l.link_info
        .as_ref()
        .and_then(|x| x.local_base_path.clone())
        .or_else(|| l.link_target_idlist.as_ref().and_then(|x| x.path.clone()))
        .or_else(|| l.string_data.relative_path.clone())
}
fn volume(l: &ShellLink) -> (Option<u32>, Option<String>, Option<u32>) {
    l.link_info
        .as_ref()
        .and_then(|x| x.volume_id.as_ref())
        .map(|v| {
            (
                Some(v.drive_serial_number),
                v.volume_label.clone(),
                Some(v.drive_type),
            )
        })
        .unwrap_or_default()
}
fn network(l: &ShellLink) -> Option<String> {
    l.link_info
        .as_ref()
        .and_then(|x| x.common_network_relative_link.as_ref())
        .and_then(|x| x.net_name.clone())
}
fn tracker(l: &ShellLink) -> (Option<String>, Option<String>, Option<String>) {
    l.tracker
        .as_ref()
        .map(|x| {
            (
                Some(x.machine_id.clone()),
                Some(x.droid.volume.clone()),
                Some(x.droid.object.clone()),
            )
        })
        .unwrap_or_default()
}
fn schema(c: &Connection) -> Result<()> {
    c.execute_batch("PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS LNK_Files(Source_Name TEXT,Source_Path TEXT PRIMARY KEY,Time_Access TEXT,Time_Creation TEXT,Time_Modification TEXT,Link_Flags INTEGER,File_Attributes_Flags INTEGER,FileSize INTEGER,IconIndex INTEGER,Show_Window_Command INTEGER,Hot_Key_Value INTEGER,Local_Path TEXT,Network_Share_Name TEXT,Relative_Path TEXT,Working_Directory TEXT,Command_Line_Arguments TEXT,Icon_Location TEXT,Description TEXT,Volume_Type INTEGER,Volume_Serial TEXT,Volume_Label TEXT,Tracker_NetBIOS TEXT,Droid_Volume_GUID TEXT,Droid_Object_GUID TEXT);CREATE TABLE IF NOT EXISTS Automatic_JumpLists(Source_Name TEXT,Source_Path TEXT,entry_number INTEGER,AppID TEXT,Time_Access TEXT,Access_Count INTEGER,Pin_Status TEXT,DestList_Path TEXT,Local_Path TEXT,Network_Share_Name TEXT,Volume_Serial TEXT,Volume_Label TEXT,Tracker_NetBIOS TEXT,PRIMARY KEY(Source_Path,entry_number));CREATE TABLE IF NOT EXISTS Custom_JumpLists(entry_id INTEGER PRIMARY KEY AUTOINCREMENT,Source_Name TEXT,Source_Path TEXT,AppID TEXT,Local_Path TEXT,Network_Share_Name TEXT,Volume_Serial TEXT,Volume_Label TEXT,Tracker_NetBIOS TEXT);")?;
    Ok(())
}
fn insert_link(tx: &rusqlite::Transaction<'_>, p: &Path, l: &ShellLink) -> Result<usize> {
    let (vs, vl, vt) = volume(l);
    let (machine, dv, df) = tracker(l);
    Ok(tx.execute("INSERT OR REPLACE INTO LNK_Files VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24)",params![p.file_name().unwrap_or_default().to_string_lossy(),p.display().to_string(),epoch(l.header.access_time),epoch(l.header.creation_time),epoch(l.header.write_time),l.header.link_flags,l.header.file_attributes,l.header.file_size,l.header.icon_index,l.header.show_command,l.header.hotkey,target(l),network(l),l.string_data.relative_path,l.string_data.working_dir,l.string_data.arguments,l.string_data.icon_location,l.string_data.name,vt,vs.map(|x|format!("{x:08X}")),vl,machine,dv,df])?)
}
pub fn parse_links(input: &Path, output: &Path) -> Result<usize> {
    let mut db = Connection::open(output)?;
    schema(&db)?;
    let tx = db.transaction()?;
    let mut n = 0;
    for p in paths(input, |p| {
        p.extension().is_some_and(|x| x.eq_ignore_ascii_case("lnk"))
    }) {
        if let Some(l) = parse_shell_link(&fs::read(&p)?) {
            n += insert_link(&tx, &p, &l)?
        }
    }
    tx.commit()?;
    Ok(n)
}
pub fn parse_jump_lists(input: &Path, output: &Path) -> Result<usize> {
    let mut db = Connection::open(output)?;
    schema(&db)?;
    let tx = db.transaction()?;
    let mut n = 0;
    for p in paths(input, |p| {
        p.file_name().is_some_and(|x| {
            let s = x.to_string_lossy();
            s.ends_with(".automaticDestinations-ms") || s.ends_with(".customDestinations-ms")
        })
    }) {
        let b = fs::read(&p)?;
        let name = p.file_name().unwrap_or_default().to_string_lossy();
        let list = if name.ends_with(".automaticDestinations-ms") {
            parse_automatic_destinations(&b, Some(&name))
        } else {
            parse_custom_destinations(&b, Some(&name))
        };
        let Some(list) = list else { continue };
        for e in list.entries {
            let (vs, vl, _) = volume(&e.link);
            let (machine, _, _) = tracker(&e.link);
            match list.kind {
                JumpListKind::Automatic => {
                    let Some(d) = e.destlist else { continue };
                    tx.execute("INSERT OR REPLACE INTO Automatic_JumpLists VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",params![name,p.display().to_string(),d.entry_number,list.app_id,epoch(d.last_access),d.access_count,if d.pinned{"Pinned"}else{"Not Pinned"},d.path,target(&e.link),network(&e.link),vs.map(|x|format!("{x:08X}")),vl,machine])?;
                }
                JumpListKind::Custom => {
                    tx.execute("INSERT INTO Custom_JumpLists(Source_Name,Source_Path,AppID,Local_Path,Network_Share_Name,Volume_Serial,Volume_Label,Tracker_NetBIOS)VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![name,p.display().to_string(),list.app_id,target(&e.link),network(&e.link),vs.map(|x|format!("{x:08X}")),vl,machine])?;
                }
                _ => {}
            }
            n += 1
        }
    }
    tx.commit()?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn malformed_shell_files_produce_no_rows() {
        let root = std::env::temp_dir().join(format!("vamparser-shell-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("broken.lnk"), b"broken").unwrap();
        fs::write(root.join("x.automaticDestinations-ms"), b"broken").unwrap();
        assert_eq!(parse_links(&root, &root.join("lnk.db")).unwrap(), 0);
        assert_eq!(parse_jump_lists(&root, &root.join("jump.db")).unwrap(), 0);
        fs::remove_dir_all(root).unwrap();
    }
}
