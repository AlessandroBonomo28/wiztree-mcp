# wizTree MCP
<p align="center">
<img width="50%" alt="Immagine Codex 22 ago 2026, 11_20_52" src="https://github.com/user-attachments/assets/41ac94ed-4db3-4fff-a39b-894fe73800bd" />
</p>



## How it works
wizTreeMCP is a Python **MCP** server that drives [WizTree](https://antibody-software.com/wiztree) from an LLM.
You can connect it to Claude Code, Cursor, or DeepSeek Harness and you can ask in natural language
*"what's taking up space on drive C:?"*, *"find all files over 1 GB in Downloads"*,
*"how much space do videos take in this folder?"*, *"are there any python orphan dependencies that I can cleanup?"*.

**I find it very useful for wsl, python, docker, npm unused cache files cleanup. Use local models for better privacy**

Single file: [`wiztree_mcp.py`](wiztree_mcp.py). Works on **Windows** only, because
WizTree is a Windows application.

<img width="100%" alt="Immagine Codex 22 ago 2026, 12_10_34" src="https://github.com/user-attachments/assets/bbd35d4e-aae7-4d5d-a6b5-95a94874e674" />

WizTree has no API: it has a command line that exports a CSV of everything it has scanned.
The server uses that.

```
LLM (MCP client) --stdio--> wiztree_mcp.py --CLI--> WizTree64.exe
                                  |                      |
                                  |<----- CSV snapshot ---
                                  |
                        streaming queries on the CSV
```

A scan runs **once** and is saved as a CSV *snapshot* in the cache.
All follow-up questions are answered by reading that CSV in streaming: no
re-scan of the disk, no loading the entire drive into memory. A snapshot of
half a million files takes ~50 MB and answers a query in about a second.

Snapshots are reused automatically: if you scanned `C:\` and then ask
something about `C:\Users\me\Downloads`, the server reuses the existing snapshot instead of
doing the work again.

---

## Installation

Requires Python 3.10+.

```bash
cd wiztree-mcp
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The virtual environment has already been created in `.venv`: if that is enough for you, you are set.

The server finds `WizTree64.exe` on its own if the `wiztree-mcp` folder sits inside the
WizTree portable folder, or if WizTree is installed in `Program Files`. Otherwise point it
with the `WIZTREE_EXE` environment variable.

---

## Connecting to Claude Code

One command, no JSON editing — it handles the merge:

```bash
claude mcp add wiztree --scope user -- "C:\path\to\wiztree-mcp\.venv\Scripts\python.exe" "C:\path\to\wiztree-mcp\wiztree_mcp.py"
```

`--scope` controls where the registration is stored:

| Scope | Where it applies | When to use it |
| --- | --- | --- |
| `user` | all folders | what you want almost always |
| `project` | writes a `.mcp.json` in the current folder | to share with people working on the same repo |
| `local` (default) | only you, only in this folder | quick experiments |

Verify:

```bash
claude mcp list
```

Then **exit and restart `claude`**: MCP servers connect at session startup, never hot.
Inside the session the tools are named `mcp__wiztree__wiztree_scan` and the like, but you do not
need to name them: just ask *"what's using space on D:"*.

If you prefer project scope without the CLI, you can also write a `.mcp.json` by hand in the
folder from which you launch `claude`, with the same structure shown below for
Cursor. On the first session Claude Code asks you to approve it, because a project
`.mcp.json` is not trusted automatically.

---

## Connecting to Cursor
<p align="center">
<img width="70%" alt="Gemini_Generated_Image_pzvhkrpzvhkrpzvh" src="https://github.com/user-attachments/assets/5b121bf7-047e-4dcd-a667-e50dd209ed08" />
</p>
Open Cursor MCP settings (`Settings → MCP → Add new MCP server`) or create
`%USERPROFILE%\.cursor\mcp.json` manually for a global setup, or `.cursor\mcp.json` inside a
project to configure it only there:

```json
{
  "mcpServers": {
    "wiztree": {
      "command": "C:\\path\\to\\wiztree-mcp\\.venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\wiztree-mcp\\wiztree_mcp.py"],
      "env": {
        "WIZTREE_EXE": "C:\\path\\to\\WizTree64.exe"
      }
    }
  }
}
```

Point to `.venv\Scripts\python.exe`, not system `python`: that way you do not need to activate
the environment and Cursor always finds the dependencies.

The file [`cursor-mcp.json`](cursor-mcp.json) already contains the snippet with the correct
absolute paths for this installation: open it and copy it.

Or let the script do it — it keeps other servers already configured and makes a backup:

```bash
.venv\Scripts\python.exe install_mcp.py
```

Restart Cursor: in the MCP list you should see `wiztree` with 16 tools. **Agent** mode is required;
MCP tools are not called in Ask mode.

---

## Connecting to DeepSeek Harness

Here the JSON used by the other two clients **does not** apply, so copying the Cursor config
and changing paths will not work. DeepSeek Harness (`dsh`) has no `mcpServers` key: it mounts each
MCP server as a **plugin instance** of `@deepseek-ai/dsh-mcp-client` in a YAML file.
One plugin instance = one MCP server.

| | Claude Code / Cursor | DeepSeek Harness |
| --- | --- | --- |
| format | JSON | YAML |
| file | `mcp.json` / `.mcp.json` | `cordis.patch.yml` |
| structure | `mcpServers` object | **list** of plugins at the top level |
| one server | one entry in the object | one entry with `name: '@deepseek-ai/dsh-mcp-client'` |
| transport | implicit | explicit `transport: stdio` |

The entry to add to the list:

```yaml
- id: mcp-wiztree
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: wiztree
    transport: stdio
    command: C:\path\to\wiztree-mcp\.venv\Scripts\python.exe
    args:
      - C:\path\to\wiztree-mcp\wiztree_mcp.py
    env:
      WIZTREE_EXE: C:\path\to\WizTree64.exe
    toolCallTimeoutMs: 900000
```

The file [`dsh-cordis-patch.yml`](dsh-cordis-patch.yml) already has the absolute paths ready.

Where to put it: in the profile's `cordis.patch.yml`, or in the harness home one
(`$DSH_HOME`, default `~/.dsh`). Layers stack in this order — profile bundle,
profile `cordis.patch.yml`, harness home `cordis.patch.yml`, and finally overlays passed with
`--patch`. Check the effective result with `dsh --dump-config`.

Three things that matter here:

- **`toolCallTimeoutMs: 900000`.** The default is 60000 ms, one minute. Scanning a full drive
  without administrator privileges takes much longer and the call would be
  cut off halfway. The other clients do not have such a tight limit.
- **Windows paths without double quotes.** In YAML, double quotes interpret escape sequences, so
  `"C:\Users\..."` fails to parse on `\U`. Without quotes, or with
  single quotes, backslashes stay literal.
- **Tool names** become `mcp__wiztree__wiztree_scan` and so on, the same convention
  as Claude Code.

DeepSeek Harness is in developer preview, so this format may change between releases:
if something does not match, compare with the
[official MCP documentation](https://deepseekdocs.com/en/docs/features/mcp).

---

## Tools

| Tool | Purpose |
| --- | --- |
| `wiztree_info` | Which executable is used, version, whether the process is elevated, cache location. Call this first when something goes wrong. |
| `wiztree_list_drives` | List of drives with capacity, used space, and free space. |
| `wiztree_scan` | Scan a drive or folder and create the snapshot. Returns totals, volume free space, and the largest top-level entries. |
| `wiztree_top_files` | Largest files, with filters for subfolder, extension, and minimum size. |
| `wiztree_top_folders` | Largest folders (recursive size), with `max_depth` to stay at a readable level. |
| `wiztree_folder_breakdown` | What is *inside* a folder, one level at a time, with percentage of the total. The tool for stepping down level by level. |
| `wiztree_file_types` | Space aggregated by extension. |
| `wiztree_search` | Search by glob (`*.iso`), plain word (partial match), or regex, sorted by size. |
| `wiztree_duplicates` | Duplicate files and recoverable space. Reads from disk **only** files that share a size: on `AppData\Local` it found 11 GB recoverable while reading 10 MB. |
| `wiztree_treemap` | Generates WizTree's PNG treemap. If a snapshot of the same root already exists, it draws from that without re-reading the disk. With `return_image=true` it also returns it inline. |
| `wiztree_export_csv` | Raw CSV export with all WizTree CLI options, wherever you want. |
| `wiztree_gui_state` | Reads the WizTree window **you** are using: what it loaded, which drive is selected, which tab is active. Used to answer "this drive" / "here" without you typing the path. |
| `wiztree_open_gui` | Opens the WizTree window on a path and returns immediately. To hand off a finding for you to inspect visually. |
| `wiztree_import_csv` | Registers a CSV you exported from the GUI (`File > Export`) as a snapshot: no re-scan, and it inherits an administrator scan too. The file is never modified or deleted. |
| `wiztree_list_scans` | Cached snapshots. |
| `wiztree_clear_cache` | Clears the cache. |

All query tools accept `path`, `refresh`, `max_age_minutes`, `admin`, `filter`,
`filter_exclude`, `timeout_seconds` and scan on their own if they do not find a valid snapshot:
the LLM can go straight to `wiztree_top_files` without calling `wiztree_scan` first.

---

## Using the GUI and the AI together

You can keep the WizTree window open, click around, and ask questions
from chat at the same time. It works, but it is worth knowing how far it goes.

WizTree draws the file list in a `TVirtualDrawTree`: an *owner-drawn* control where
rows do not exist as text but are painted on the fly. From outside the process they are
pixels, not data. **The results you see on screen are not readable.**

What the window does expose through normal Win32 messages is **where it is pointing**, and that
is enough:

```
1. WizTree window (pid 58140)
   Title           : [C:\Users\...\wiztree mcp test]  - WizTree
   Loaded target   : C:\Users\...\wiztree mcp test
   Drive selector  : <Select folder...>
   Available       : [C:] OS , [D:] Local Disk , <Select folder...>, ...
   Tabs            : File View, Tree View
```

So the flow is: you click `[D:]` in the GUI → ask *"what's using space here?"* →
`wiztree_gui_state` reads that the window points to `D:` → the other tools answer about `D:`.
You do not need to type any path.

Two ways to share data with the window open:

- **Re-scan (zero friction).** The server scans on its own the target it reads from the
  GUI. It costs the time of one scan.
- **CSV handoff (instant).** In the GUI do `File > Export`, then `wiztree_import_csv`.
  No re-scan, and if the GUI was running as administrator you carry over the MFT
  scan. This is the fastest way to work on a full drive.

Both approaches coexist: a command-line export was verified to run in half a second
while a WizTree window is open, without disturbing it — the global mutex does not block
concurrent instances.

Note: `WizTree64.exe path.csv` loads the CSV only in headless mode (with `/export` or
`/treemapimagefile`). Launched without switches it does **not** open the GUI on that CSV; it falls
back to a default drive. In the GUI the CSV is opened from the drive dropdown, `<CSV File>` entry.

---

## Fast scans: `admin`

On NTFS volumes WizTree reads the **MFT** directly, which is why it scans a full drive
in seconds. But reading the MFT requires administrator privileges.

- **Non-elevated** process (the normal case with Cursor): WizTree falls back to a recursive
  folder scan. On `C:\` it can take several minutes; on a single folder
  it is still fast (~500k files in 5 seconds).
- `admin: true`: the server starts WizTree elevated and waits for that process to finish
  before reading the export. This triggers the **Windows UAC prompt**, which must be
  accepted manually. The scan timeout starts after consent; cancelling consent returns
  a tool error. Only WizTree is elevated, not the MCP server.

If you need this often, launch Cursor as administrator: the server inherits elevation and
all scans become immediate with no further prompts. `wiztree_info` tells you which
situation you are in.

---

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `WIZTREE_EXE` | auto-discovery | Full path to `WizTree64.exe`. |
| `WIZTREE_DIR` | — | Folder containing the executable, alternative to `WIZTREE_EXE`. |
| `WIZTREE_MCP_CACHE` | `%LOCALAPPDATA%\wiztree-mcp` | Where CSV snapshots and treemaps are stored. |
| `WIZTREE_MCP_MAX_SCANS` | `12` | How many snapshots to keep before deleting the oldest. |

---

## Tests

Windows-only launch regression tests (no UAC prompt or real scan):

```bash
python -m unittest test_launch.py
```

```bash
.venv\Scripts\python.exe test_smoke.py
```

Starts the server over stdio exactly as Cursor does, creates a test tree (with spaces and
commas in names) and exercises all 16 tools: 37 checks.

To try it on real data:

```bash
.venv\Scripts\python.exe test_manual.py "C:\Users\me\AppData\Local"
```

---

## Implementation details that may save you time

Things discovered in the field while working with the WizTree 4.32 CLI, not documented anywhere:

- **CSV headers are localized.** In Italian the first column is called
  `Nome file`, not `File Name`. The first 7 columns are always in the same order, while
  optional ones (`DRIVECAPACITY`, `CREATEDDATE`, `MFTRECNO`, …) keep a stable ASCII
  name. The parser relies on position for the first columns and on name for the others.
- **No quotes inside arguments.** Passing `/export="C:\out.csv"` from `subprocess`
  makes WizTree open an invisible modal error window and the process hangs
  forever. Values must be passed bare (`/export=C:\out.csv`) and let Python do the quoting for
  `CreateProcess`.
- **Files without an extension are exported with a trailing dot**: `payload` becomes
  `payload.`. Windows does not allow trailing dots in names, so the parser removes it.
- **WizTree can re-read its own CSVs.** Passing an exported `.csv` as the scan path
  works: that is how treemaps are drawn from a snapshot without
  touching the disk again.
- **Nonexistent path = exit code 0 and no file.** There is no error code to
  check: you must verify that the output file was created.
- **There is a global mutex** (`WizTreeMutex`): invocations are serialized with a lock.
- **The duplicate finder exists only in the GUI.** The binary contains `Duplicate Files:`,
  `Duplicates only`, the `DUPSIZE`/`DUPCOUNT` columns, and the INI key `dupmethod`, but no
  command-line switch reaches them. `wiztree_duplicates` therefore does not call WizTree:
  it groups by size from the snapshot and reads from disk only files that share
  a size with someone else.
- `/exportlimit=N` truncates the export to N rows *in traversal order*, not a global
  top-N. That is why ranking is done here, in streaming over the CSV, and not by WizTree.
- `/sortby` values: `0` no order, `1` size, `2` allocated, `3` modification date.

---

## License

MIT. WizTree is software by [Antibody Software](https://antibody-software.com/wiztree),
distributed under its own license: this project only invokes its command line.
