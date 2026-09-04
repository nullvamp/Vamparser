# Vamparser

Vamparser is a fast command-line parser for collected Windows forensic artifacts. It reads offline evidence and writes structured SQLite databases that can be searched directly or imported into another investigation platform.

It does not collect data from a live computer and does not require administrator rights for normal offline parsing.

## Supported artifacts

| Artifact | Command | Input |
| --- | --- | --- |
| Windows Event Logs | `evtx` | One `.evtx` file or a directory |
| Registry | `registry` | An offline Registry hive |
| Amcache | `amcache` | `Amcache.hve` |
| Shimcache | `shimcache-hive` | An offline `SYSTEM` hive |
| Raw Shimcache data | `shimcache` | Exported `AppCompatCache` bytes |
| Prefetch | `prefetch` | One `.pf` file or a directory |
| NTFS Master File Table | `mft` | An extracted `$MFT` file |
| USN Journal | `usn` | An extracted `$UsnJrnl:$J` stream |
| MFT and USN correlation | `correlate` | Databases created by the two commands above |
| SRUM | `srum` | `SRUDB.dat` |
| Recycle Bin | `recycle-bin` | A collected `$Recycle.Bin` directory |
| Windows shortcuts | `lnk` | One `.lnk` file or a directory |
| Jump Lists | `jump-lists` | Automatic or Custom Destinations files |

## Build

Install Rust, clone the repository, and run:

```powershell
rustup show
cargo build --release --locked
```

The executable is created at:

```text
target\release\vamparser.exe
```

## Examples

Parse a directory of Windows Event Logs:

```powershell
vamparser.exe evtx "D:\Evidence\Windows\System32\winevt\Logs" --output "D:\Cases\INC-001\PROCESSED\evtx.db"
```

Parse Prefetch files:

```powershell
vamparser.exe prefetch "D:\Evidence\Windows\Prefetch" --output "D:\Cases\INC-001\PROCESSED\prefetch.db"
```

Parse the MFT and USN Journal, then correlate them:

```powershell
vamparser.exe mft 'D:\Evidence\$MFT' --output mft.db --volume C:
vamparser.exe usn 'D:\Evidence\$J' --output usn.db --volume C:
vamparser.exe correlate --mft mft.db --usn usn.db --output mft-usn.db
```

Run `vamparser.exe --help` or `vamparser.exe <command> --help` for the complete command list.

## Output and evidence handling

- Source evidence is opened read-only.
- Parser results are written to SQLite.
- Database writes use transactions and parameters.
- Parsed timestamps are normalized to UTC where the artifact provides enough information.
- Damaged or unsupported data may be skipped or reported rather than guessed.

Keep output databases outside the evidence directory. Hash source evidence before analysis and retain the acquisition details with the case.

## Validation

The current parser set has been exercised against a collected Windows test corpus. Row counts and database-integrity results are recorded in [VALIDATION.md](VALIDATION.md).

Those results show what was tested; they are not a claim that every Windows version, damaged artifact, or edge case is already covered. Parser results should be checked against source evidence and a second trusted implementation when the finding is important.
