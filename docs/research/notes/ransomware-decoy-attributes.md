# Ransomware vs. decoy file attributes (HIDDEN / SYSTEM) — research notes

Date: 2026-10-21. Scope: whether common Windows ransomware encryptors skip files that have
`FILE_ATTRIBUTE_HIDDEN` and/or `FILE_ATTRIBUTE_SYSTEM`, and what that means for Kestrel's canary
documents (for example `!Passwords.docx` in the roots of Documents, Desktop and Pictures).

Method: public reverse-engineering write-ups and leaked source code. Where source was available
(Babuk, Conti, the LockBit 3.0 builder config), I read it as plain text. Nothing was compiled or
executed. "No evidence" means the analyses I found don't mention an attribute check. It does not
prove that no check exists.

## TL;DR

* **No family I could verify skips files because of `FILE_ATTRIBUTE_HIDDEN` unconditionally.** The
  two leaked-source families (Conti, Babuk) select files by name, extension and folder only. They
  clear (Conti) or overwrite (Babuk) attributes before encrypting.
* **The important exception is LockBit 3.0 / Black.** It has an operator-controlled
  `skip_hidden_folders` option (Trend Micro calls it `EXCLUDE_HIDDEN_FLAG`: "If set, hidden files
  will not be encrypted"; Northwave calls it `LB3_SKIP_HIDDEN_FILES`). The leaked builder ships with
  it set to `false`. However, Kaspersky's survey of 396 samples built from that builder says the
  most common targets are "local disks and network shares, **avoiding hidden folders**". So hiding a
  decoy can blind it to a real share of LockBit 3.0 / builder-copycat deployments.
* **SYSTEM:** LockBit 2.0's traversal branches on `FILE_ATTRIBUTE_SYSTEM`. Chuong Dong's write-up
  says the extension/name filters apply to files "whose type is not FILE_ATTRIBUTE_SYSTEM". It is
  ambiguous whether files that *have* the SYSTEM attribute are then skipped. It reads most naturally
  as "only non-system files are considered", that is, skipped. No family I found specifically
  *targets* system files. Adding SYSTEM therefore only adds risk for detection. Its one benefit is
  UX: Explorer still hides "protected operating system files" when the user has turned on "show
  hidden files".
* **Things that matter more than attributes:** the decoy's name and extension, its size, its parent
  folder name, whether it is a reparse point or cloud placeholder, and whether its content is valid.
  Details are below.

## Per-family findings

| Family | Skips HIDDEN? | Skips SYSTEM? | Read-only handling | Skip logic actually documented | Evidence |
|---|---|---|---|---|---|
| **LockBit 2.0** | No evidence | **Ambiguous, possibly yes.** Name/extension checks apply to files "whose type is not FILE_ATTRIBUTE_SYSTEM". | Clears READONLY: `SetFileAttributesW(..., FILE_ATTRIBUTE_NORMAL)` | Folder names (`$recycle.bin`, `boot`, `intel`, `msocache`, `tor browser`, …), extension list, file names (`thumbs.db`, `iconcache.db`, `desktop.ini`-style). FindFirstFileExW, one thread per drive, I/O completion port workers. | [Chuong Dong — LockBit 2.0](https://www.chuongdong.com/reverse%20engineering/2022/03/19/LockbitRansomware/) |
| **LockBit 3.0 / Black** (BlackMatter-derived) | **Optional.** `skip_hidden_folders` / `EXCLUDE_HIDDEN_FLAG`. Default `false` in the leaked builder, but Kaspersky reports real builds commonly "avoiding hidden folders". It is unclear whether the code tests only directories or also files (Trend Micro says files, the builder key says folders). | No evidence | Not documented | Hashed white-lists for folders, files and extensions. The leaked default `white_folders` includes `programdata`, `public`, `all users`, `default`, `microsoft`, `windows`, `program files`. `white_files` includes `desktop.ini`, `thumbs.db`, `ntuser.dat`. | [Trend Micro 2022](https://www.trendmicro.com/en_us/research/22/g/lockbit-ransomware-group-augments-its-latest-variant--lockbit-3-.html), [Northwave config analysis](https://northwave-cybersecurity.com/threat-intel-research/lockbit-3.0-an-in-depth-analysis-of-lockbit-blacks-config), [Cynet](https://www.cynet.com/blog/cyops-threat-alert-lockbit3lockbit-black/), [Kaspersky Securelist 2023-08-25 (396 samples)](https://securelist.com/lockbit-ransomware-builder-analysis/110370/), leaked builder `config.json` mirror: [petikvx/LockBit-Black-Builder](https://github.com/petikvx/LockBit-Black-Builder) (`LockBit3Builder/config.json`: `"skip_hidden_folders": false`) |
| **LockBit 4.0** | No evidence (the write-up doesn't mention attributes) | No evidence | Not documented | Skips reparse points and directories from the name checks. Skips files smaller than 17 bytes and extensions exe/lnk/dll/cpl/sys. Breadth-first traversal; pools of 2×CPU traversal threads and 3×CPU encryption threads. | [Chuong Dong — LockBit 4.0](https://www.chuongdong.com/reverse%20engineering/2025/03/15/Lockbit4Ransomware/) |
| **Conti** (leaked source) | **No.** Source has no hidden check. | **No.** Source has no system check. | Clears only READONLY: `SetFileAttributesW(f, attrs ^ FILE_ATTRIBUTE_READONLY)` (locker.cpp). | **Skips `FILE_ATTRIBUTE_REPARSE_POINT` entries.** Directory blacklist uses *substring* `StrStrIW`: `tmp`, `winnt`, `temp`, `thumb`, `$Recycle.Bin`, `System Volume Information`, `Boot`, `Windows`, `Trend Micro`. File blacklist is also substring-based: `.exe`, `.dll`, `.lnk`, `.sys`, `.msi`, own note/log/extension. Traversal is breadth-first (TAILQ queue) from each drive root, feeding a thread pool. | Leaked source mirror [Cracked5pider/conti_locker](https://github.com/Cracked5pider/conti_locker) `locker/search.cpp`, `locker/locker.cpp`; [Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2021/11/18/conti-ransomware) |
| **Babuk** (leaked source) | **No.** | **No.** | Unconditionally sets `FILE_ATTRIBUTE_NORMAL` before encrypting, which strips HIDDEN, SYSTEM and READONLY. | Exact-name blacklist (`AppData`, `Boot`, `Windows`, `ProgramData`, `Program Files*`, `$Recycle.Bin`, `All Users`, `desktop.ini`, `thumbs.db`, `ntuser.dat`, …). Skips `.exe`, `.dll`, `.babyk`. Recursive depth-first, one thread per drive. | Leaked source mirror [Hildaboo/BabukRansomwareSourceCode](https://github.com/Hildaboo/BabukRansomwareSourceCode) `windows/Babyk/entry.cpp`; [Chuong Dong — Babuk](https://www.chuongdong.com/reverse%20engineering/2021/01/03/BabukRansomware/) |
| **Akira** (Conti-derived) | No evidence | No evidence ("skips system files" in one repo appears to mean name/path-based) | Calls GetFileAttributesW (Conti-like) | Same extension and folder lists as Conti (`winnt`, `temp`, `thumb`, `$Recycle.Bin`, `Trend Micro`, …). Restart Manager. | [Gen Digital/Avast Akira decryptor](https://www.gendigital.com/blog/insights/research/decrypted-akira-ransomware), [MITRE S1129](https://attack.mitre.org/software/S1129/), [MottaSec RE repo](https://github.com/MottaSec/akira-ransomware-reverse) |
| **Black Basta** (Conti lineage) | No evidence found | No evidence found | — | Only lineage is documented; I found no code-level file-filter analysis. | [Qualys 2024](https://blog.qualys.com/vulnerabilities-threat-research/2024/09/19/black-basta-ransomware-what-you-need-to-know) |
| **PLAY** | No | No | Not mentioned | Name/extension list (`.exe`, `.dll`, `.lnk`, `.sys`, `.msi`, `readme.txt`, `bootmgr`) and **size < 6 (bytes)**. Skips the `Windows` dir. Recursive depth-first, thread per drive and per file. | [Chuong Dong — PLAY](https://www.chuongdong.com/reverse%20engineering/2022/09/03/PLAYRansomware/) |
| **Royal** | No evidence | No evidence | — | Extension and directory exclusion via `StrStrIW`. FindFirstFileW traversal. GetLogicalDrives and NetShareEnum. | [Quick Heal](https://www.quickheal.com/blogs/deep-dive-into-royal-ransomware/), [Trend Micro](https://trendmicro.com/en_ae/research/22/l/conti-team-one-splinter-group-resurfaces-as-royal-ransomware-wit.html), [Cybereason](https://www.cybereason.com/blog/royal-ransomware-analysis) |
| **BlackCat/ALPHV** | No evidence of a hidden option in the JSON config | No evidence | — | Config `exclude_directory_names`, `exclude_file_names` (incl. `desktop.ini`), `exclude_file_extensions`, `exclude_file_path_wildcard`. | [SentinelOne](https://www.sentinelone.com/labs/blackcat-ransomware/) |
| **BlackMatter / DarkSide** | No evidence (8–9 config flags documented, none for hidden) | No evidence | — | Hashed directory/file/extension skip lists (`windows`, `application data`, `mozilla`, `desktop.ini`, `thumbs.db`, …) | [Group-IB](https://www.group-ib.com/blog/blackmatter-ransomware/), [Ciphertech](https://ciphertechsolutions.com/?p=1334) |
| **REvil/Sodinokibi** | No evidence | No evidence | — | Config `wht` → `fld`/`fls`/`ext` whitelists | [Splunk](https://www.splunk.com/en_us/blog/security/revil-ransomware-threat-research-update-and-detections), [SecurityScorecard PDF](https://securityscorecard.com/wp-content/uploads/2024/01/Research-A-Detailed-Analysis-Of-The-Last-Version-Of-REvil-Ransomware.pdf) |
| **Hive** | No evidence | No evidence | — | `-skip` regex for file names (CLI). Go concurrency. | [Trend Micro encyclopedia](https://trendmicro.com/vinfo/gb/threat-encyclopedia/malware/ransom.win32.gohive.rcy), [SentinelOne](https://www.sentinelone.com/labs/hive-attacks-analysis-of-the-human-operated-ransomware-targeting-healthcare/) |
| **Ryuk** | No evidence | No evidence | — | Extensions `dll`, `lnk`, `hrmlog`, `ini`, `exe`. Paths (`Windows`, `System32`, `$Recycle.Bin`, Chrome, Mozilla, AhnLab, …). | [VMware Carbon Black TAU](https://blogs.vmware.com/security/2020/02/vmware-carbon-black-tau-ryuk-ransomware-technical-analysis.html), [Trend Micro](https://trendmicro.com/vinfo/us/threat-encyclopedia/malware/ransom.win32.ryuk.hud) |
| **Clop** | No evidence | No evidence | — | **Skips files ≤ ~17 KB (0x4268 bytes)**. Extension exclusions. Two-thread design. | [Trend Micro](https://trendmicro.com/vinfo/au/threat-encyclopedia/malware/ransom.win32.clop.nv), [McAfee](https://mcafee.com/blogs/other-blogs/mcafee-labs/clop-ransomware/) |
| **Rhysida** | No evidence | No evidence | — | `-d` target dir. Folder/extension lists not detailed in what I read. | [Gen Digital](https://www.gendigital.com/blog/insights/research/rhysida-ransomware-technical-analysis) |
| **Phobos / 8Base** | No evidence | No evidence | — | Name-substring exclusions (`boot.ini`, `bootfont.bin`, `ntldr`, `io.sys`, own notes), `Windows` and `ProgramData\Microsoft\Windows\Caches` | [Trend Micro encyclopedia](https://trendmicro.com/vinfo/us/threat-encyclopedia/malware/ransom.win32.phobos.jshsnz), [Fortinet AVAR2020](https://filestore.fortinet.com/fortiguard/research/AVAR2020_Pay_or_Lose_Your_Critical_Data_-_Deep_Analysis_of_A_Variant_of_Phobos_Ransomware_XiaopengZhang.pdf) |
| **Qilin/Agenda** | No evidence | No evidence | — | Config `directory_black_list`, `file_black_list`, `file_pattern_black_list` | [Arete](https://areteir.com/resources/malware-spotlight-qilin-ransomware), [TEHTRIS](https://tehtris.com/en/blog/rage-against-the-powershell-qilin-in-the-name/) |
| **WannaCry** | No evidence (the write-up I wanted returned 403) | No evidence | — | Extension *allow*-list (targets ~170 doc/db/media types) and directory-name skips. Hides its *own* working dir with `attrib +h`. | [Sophos/SecureWorks](https://www.sophos.com/ja-jp/research/wcry-ransomware-analysis), [MITRE S0366](https://attack.mitre.org/software/S0366/) |
| **Medusa, Maze/Egregor, Avaddon, STOP/Djvu, RansomHub** | Not verified (no technical source found in this pass) | Not verified | — | — | — |

Supporting quotes (verbatim from the sources):

* LockBit 2.0 (Chuong Dong): "If a file whose type is not FILE_ATTRIBUTE_SYSTEM is encountered,
  LockBit compares its extension with the following extensions to avoid encrypting." … "If the
  file's attribute is FILE_ATTRIBUTE_READONLY, LockBit calls SetFileAttributesW to set it to
  FILE_ATTRIBUTE_NORMAL".
* LockBit 3.0 (Trend Micro, Table 3): `EXCLUDE_HIDDEN_FLAG` — "If set, hidden files will not be
  encrypted."
* LockBit 3.0 builder (Kaspersky, 2023-08-25, 396 samples): "The most recurrent encryption targets
  are local disks and network shares, avoiding hidden folders." Also: "Many of the detected
  parameters correspond to the default configuration of the builder." The percentage for the
  hidden option is only in an image I could not read, so how often hidden-skip is enabled is
  **unquantified**.
* Conti `search.cpp`: `if (... FindData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;`.
  The only other attribute test is `FILE_ATTRIBUTE_DIRECTORY`.
* Babuk `entry.cpp`: `SetFileAttributesW(filePath, FILE_ATTRIBUTE_NORMAL);` runs before encrypting.
  The traversal tests only `FILE_ATTRIBUTE_DIRECTORY`.

## Traversal order — does a leading `!` / `0` matter?

* `FindFirstFileW`/`FindNextFileW` order is file-system defined. On NTFS it follows the directory
  B-tree, which is "usually" alphabetical by upcased UTF-16 code unit, and is not guaranteed
  ([FindNextFile docs](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilea),
  [Raymond Chen 2014](https://devblogs.microsoft.com/oldnewthing/20140304-00/?p=1603)). `!` (0x21)
  sorts before digits (0x30–0x39) and letters, so `!Passwords.docx` is typically the first entry
  returned in its directory. `~` and `_` sort *after* uppercase letters.
* **Within a directory**, the order helps only a little. Conti, LockBit 2.0/3.0/4.0, Babuk and Royal
  push files into multi-threaded queues or pools. LockBit 4 uses 3×CPU encryption workers. So
  several files in the same folder may be encrypted concurrently, and the decoy being "first" buys
  at most a few files.
* **Across directories**, placement matters more than the name:
  * Breadth-first (Conti, LockBit 4.0): all directories at depth N are listed before depth N+1. The
    depth of `C:\Users\<u>\Documents` (and of the OneDrive KFM path `C:\Users\<u>\OneDrive\Documents`)
    therefore decides when the decoy is reached. Any user data at shallower depth (`C:\Data\...`,
    `D:\` roots, shares) goes first.
  * Depth-first (Babuk, LockBit 2.0, PLAY): at `C:\` most root folders are excluded (`Windows`,
    `Program Files*`, `ProgramData`, `$Recycle.Bin`, `System Volume Information`, `Boot`), so
    `C:\Users` is reached quickly. Inside a profile the order is alphabetical: `3D Objects`,
    `AppData` (often excluded), `Contacts`, **`Desktop`**, **`Documents`**, `Downloads`, `Favorites`,
    `Links`, `Music`, `OneDrive`, **`Pictures`**, … Desktop decoys are hit before Documents.
    Pictures comes after Downloads/Music/OneDrive, so on a profile with a big Downloads folder a
    Pictures decoy fires late.
  * Most families run one traversal thread per drive (LockBit 2.0, Babuk, PLAY) and often handle
    network shares in parallel or afterwards. A C: decoy says nothing about how quickly D: or a
    mapped share is hit. Huntress's feedback board shows the same gap for shares
    ([Huntress feedback](https://feedback.huntress.com/feature-requests/p/ransomware-canaries-ability-to-put-deploy-canaries-to-network-drives-custom-loca)).
* **Conclusion:** a leading `!` is cheap and mildly useful for single-threaded or ordered walkers.
  Coverage comes from placing decoys at several depths and in several folders, and from detecting
  on the *first* write to *any* decoy plus behavioural rules. A forum claim that RansomFree used
  low-ASCII names for the same reason was challenged in the same thread, because many families
  don't encrypt in on-disk order
  ([BleepingComputer forum](https://www.bleepingcomputer.com/forums/t/670323/ransomfree-questions-bait-files-and-mbr/)).

## Non-attribute pitfalls for decoys (all evidence-backed)

1. **Size:** Clop skips files ≤ ~17 KB, LockBit 4.0 skips files < 17 bytes, PLAY skips files
   < 6 bytes. Make decoys ≥ 64 KB. Huntress uses ~150 KB per canary
   ([Huntress changelog](https://feedback.huntress.com/changelog/ransomware-canaries-now-enabled-by-default)).
2. **Names and extensions:** Conti, Akira and Royal use *substring* matches (`StrStrIW`). A decoy
   name containing `.lnk`, `.exe`, `.dll`, `.sys` or `.msi` anywhere would be skipped. Never use the
   white-listed names `desktop.ini`, `thumbs.db`, `iconcache.db` or `ntuser.*`. Use mainstream
   targeted extensions (`.docx`, `.xlsx`, `.pdf`, `.jpg`).
3. **Folder names:** Conti and Akira skip any directory whose name *contains* `temp` (which matches
   **`Templates`**), `tmp`, `thumb`, `boot` or `windows`. Babuk skips `AppData`, `ProgramData` and
   `All Users`. LockBit 3.0 defaults skip `public`, `default`, `programdata` and `microsoft`. Don't
   put decoys only under such names, and never in a dedicated hidden decoy sub-folder: that is the
   exact case LockBit 3.0's `skip_hidden_folders` targets.
4. **Reparse points and cloud placeholders:** Conti (and therefore Akira and likely Black Basta) and
   LockBit 4.0 skip reparse points. OneDrive Files-On-Demand placeholders are reparse points. A
   decoy that OneDrive dehydrates to "online-only" becomes invisible to these families. Keep decoys
   pinned/local ("Always keep on this device") or outside OneDrive-synced paths, and check
   `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` / `RECALL_ON_OPEN`.
5. **Valid content:** some Cerber variants (2017) fingerprinted canaries by looking for image files
   that weren't real images, and then skipped the *whole directory*
   ([Dark Reading](https://www.darkreading.com/endpoint-security/cerber-fights-anti-ransomware-tools)).
   Decoys must be valid, realistic documents with plausible sizes and timestamps.
6. **Attributes get rewritten anyway:** Babuk sets NORMAL, while LockBit 2.0 and Conti clear
   READONLY. A sensor that keys on "attribute changed on decoy" (SetFileAttributes, ETW
   SetInformation) gets a pre-encryption signal from these families. Read-only decoys therefore cost
   nothing and can give an earlier tripwire.

## What other canary-based products do

* **Elastic Defend** (canary files since 7.14): "A canary file acts and looks exactly like any other
  file - it can have valid content (DOCX, PDF, etc.), hidden, or marked as a system file to avoid
  user tampering", and "canary files cannot be 'fingerprinted' and avoided by ransomware"
  ([Elastic Security Labs, 2024-02-23](https://www.elastic.co/security-labs/threat-command/ransomware-in-the-honeypot-how-we-capture-keys);
  [policy docs](https://www.elastic.co/guide/en/security/8.19/configure-endpoint-integration-policy.html)).
  The vendor says hidden *or* system is acceptable but gives no per-family data.
* **Huntress Ransomware Canaries:** "small hidden files" in user profiles (v1 `.docx`, v2 adds
  `.xlsx`/`.pdf` and the system profile). Users still found them "more often than expected", which
  prompted branded content and a support QR code
  ([Huntress 2022 update](https://huntress.com/blog/ransomware-canaries-a-2022-update)). Lesson:
  HIDDEN does not make decoys invisible to users who show hidden files. Plan for discovery with an
  explanatory body text.
* **Cybereason RansomFree** (2016–2018, discontinued): hidden decoy folders containing
  randomly-named `.doc`/`.xls`/`.jpg`/… files in several locations, re-created if deleted
  ([BleepingComputer forum](https://www.bleepingcomputer.com/forums/t/665088/ransomware-creates-hidden-folders-not-with-my-files/),
  [THN 2016](https://thehackernews.com/2016/12/free-anti-ransomware-software.html)). Hidden decoy
  *folders* are exactly what LockBit 3.0's `skip_hidden_folders` would now skip.
* **SentinelOne** (agent ≥ 21.6, per a vendor-support quote on a SonicWall community thread; not
  independently verified): canary files dropped under `C:\`, `C:\Users` and shares, on by default.
  I could not confirm their attributes.
* **Sophos Intercept X CryptoGuard:** I found no public evidence of decoys. It is documented as
  content-entropy analysis plus automatic rollback
  ([Sophos ProLock blog](https://www.sophos.com/en-us/blog/stop-prolock-ransomware-with-three-layers-of-protection-from-intercept-x)).
* **Microsoft Defender Controlled Folder Access** is not canary-based. It is an allow-list of
  trusted apps that may write to protected folders
  ([Microsoft Learn](https://learn.microsoft.com/defender-endpoint/controlled-folders)).
* **CrowdStrike Falcon:** I found no public documentation of a canary mechanism.

## Recommendation for Kestrel

**Use HIDDEN only, not HIDDEN+SYSTEM, and don't make every decoy hidden.** Confidence:
**medium**, because evidence is thin for most families.

Reasoning:

1. For the families with readable code (Conti, Babuk) and for the documented ones, neither
   attribute is used to skip files. Babuk strips both attributes before encrypting.
2. The one documented attribute skip in a current, high-volume family is LockBit 3.0's optional
   hidden skip. Kaspersky's sample survey suggests real builds often enable it. The leaked builder
   is also widely reused by copycats.
3. SYSTEM adds a further, ambiguous risk (LockBit 2.0's `FILE_ATTRIBUTE_SYSTEM` branch), plus a
   plausible heuristic for future families ("never touch OS files"). Its only gain is UX, so don't
   use it.
4. Practical layout:
   * Per protected root: at least one **non-hidden** decoy (for example a realistic
     `Budget 2025 (archive).xlsx`, or the `!`-prefixed one if the owner accepts visibility) **plus**
     hidden decoys. Optionally leave the visible one HIDDEN=false but READONLY.
   * Never put decoys in a hidden *sub-folder*.
   * Make decoys ≥ 64 KB with valid content, never cloud-dehydrated, and with no excluded substrings
     in the name or parent folder.
   * Make it a policy knob (`canary.hidden: per-decoy`) so an admin can turn visible decoys on where
     LockBit-style threat is the priority.
5. Detection logic must treat a **SetFileAttributes, rename or delete** on a decoy as a trigger,
   not only a write. Babuk, Conti and LockBit 2.0 touch attributes before writing.

Open gaps (not verified): exact semantics of LockBit 3.0's hidden flag (files vs folders; the code
path); the fraction of in-the-wild LockBit 3.0 builds with it enabled (Kaspersky's chart image); the
meaning of LockBit 2.0's SYSTEM branch; and the file filters of Medusa, Maze/Egregor, Avaddon,
STOP/Djvu and RansomHub. A sandbox test in the VM lab could settle the first point: build a
LockBit 3.0 builder sample with `skip_hidden_folders: true` and check whether a hidden *file* in a
visible folder is encrypted. That test needs the owner's sign-off because it means running a real
encryptor in an isolated VM, which CLAUDE.md rule 3 prohibits ("never run real malware"). So it is
listed here only as an open question.

## Sources

* Chuong Dong, LockBit 2.0: https://www.chuongdong.com/reverse%20engineering/2022/03/19/LockbitRansomware/
* Chuong Dong, LockBit 4.0: https://www.chuongdong.com/reverse%20engineering/2025/03/15/Lockbit4Ransomware/
* Chuong Dong, PLAY: https://www.chuongdong.com/reverse%20engineering/2022/09/03/PLAYRansomware/
* Chuong Dong, Babuk: https://www.chuongdong.com/reverse%20engineering/2021/01/03/BabukRansomware/
* Trend Micro, LockBit 3.0: https://www.trendmicro.com/en_us/research/22/g/lockbit-ransomware-group-augments-its-latest-variant--lockbit-3-.html
* Northwave, LockBit 3.0 config: https://northwave-cybersecurity.com/threat-intel-research/lockbit-3.0-an-in-depth-analysis-of-lockbit-blacks-config
* Cynet, LockBit 3 builder: https://www.cynet.com/blog/cyops-threat-alert-lockbit3lockbit-black/
* Kaspersky Securelist, LockBit builder analysis (2023-08-25): https://securelist.com/lockbit-ransomware-builder-analysis/110370/
* Leaked LockBit 3.0 builder config (mirror): https://github.com/petikvx/LockBit-Black-Builder
* Leaked Conti locker source (mirror): https://github.com/Cracked5pider/conti_locker
* Leaked Babuk source (mirror): https://github.com/Hildaboo/BabukRansomwareSourceCode
* Qualys, Conti: https://blog.qualys.com/vulnerabilities-threat-research/2021/11/18/conti-ransomware
* Gen Digital, Akira: https://www.gendigital.com/blog/insights/research/decrypted-akira-ransomware
* MottaSec Akira RE: https://github.com/MottaSec/akira-ransomware-reverse
* Group-IB, BlackMatter: https://www.group-ib.com/blog/blackmatter-ransomware/
* Ciphertech, BlackMatter: https://ciphertechsolutions.com/?p=1334
* SentinelOne, BlackCat: https://www.sentinelone.com/labs/blackcat-ransomware/
* Splunk, REvil: https://www.splunk.com/en_us/blog/security/revil-ransomware-threat-research-update-and-detections
* VMware Carbon Black, Ryuk: https://blogs.vmware.com/security/2020/02/vmware-carbon-black-tau-ryuk-ransomware-technical-analysis.html
* Trend Micro, Clop: https://trendmicro.com/vinfo/au/threat-encyclopedia/malware/ransom.win32.clop.nv
* Quick Heal, Royal: https://www.quickheal.com/blogs/deep-dive-into-royal-ransomware/
* Gen Digital, Rhysida: https://www.gendigital.com/blog/insights/research/rhysida-ransomware-technical-analysis
* Trend Micro, Phobos: https://trendmicro.com/vinfo/us/threat-encyclopedia/malware/ransom.win32.phobos.jshsnz
* Arete, Qilin: https://areteir.com/resources/malware-spotlight-qilin-ransomware
* Sophos, WCry: https://www.sophos.com/ja-jp/research/wcry-ransomware-analysis
* Microsoft, FindNextFile: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilea
* Raymond Chen, enumeration order: https://devblogs.microsoft.com/oldnewthing/20140304-00/?p=1603
* Elastic Security Labs, canaries: https://www.elastic.co/security-labs/threat-command/ransomware-in-the-honeypot-how-we-capture-keys
* Huntress canaries 2022: https://huntress.com/blog/ransomware-canaries-a-2022-update
* Huntress changelog: https://feedback.huntress.com/changelog/ransomware-canaries-now-enabled-by-default
* RansomFree forum threads: https://www.bleepingcomputer.com/forums/t/665088/ransomware-creates-hidden-folders-not-with-my-files/ , https://www.bleepingcomputer.com/forums/t/670323/ransomfree-questions-bait-files-and-mbr/
* Dark Reading, Cerber vs canaries: https://www.darkreading.com/endpoint-security/cerber-fights-anti-ransomware-tools
* Microsoft, Controlled Folder Access: https://learn.microsoft.com/defender-endpoint/controlled-folders
