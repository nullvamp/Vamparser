# Validation report

Validated on 2026-09-02 against a read-only Windows forensic test corpus.
Every generated SQLite database returned `ok` from `PRAGMA integrity_check`.

| Artifact | Parsed rows |
| --- | ---: |
| Prefetch | 182 |
| MFT | 139,561 |
| USN Journal | 381,523 |
| MFT-USN correlation | 381,523 |
| EVTX | 20,321 |
| Registry SYSTEM values | 75,668 |
| Amcache inventory values | 28,491 |
| Shimcache | 246 |
| SRUM (all ESE tables) | 5,229 |
| LNK | 36 |
| Automatic Jump Lists | 33 |
| Custom Jump Lists | 14 |

The USN parser was revalidated after conversion to bounded streaming. It parsed the 39.5 MB `$J` source into the same 381,523 records in approximately 1.7 seconds with a measured peak working set of 9.85 MB.

The corpus contains no Recycle Bin `$I` metadata. Recycle Bin version-2 parsing
and neighboring `$R` content correlation are covered by a deterministic unit
test. The test suite contains 15 passing tests. It covers valid synthetic records,
malformed-input handling, streaming USN boundaries, and MFT/USN correlation.

## Release artifacts

| File | SHA-256 |
| --- | --- |
| `target/release/vamparser.exe` | `F3100ACEABDDF10C5CCADCCF157C2EEF2C872F044DE2D55C9062A4080345B87E` |
