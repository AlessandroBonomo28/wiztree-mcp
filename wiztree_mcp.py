"""MCP server that drives WizTree, the Windows disk space analyser.

WizTree has no API - it has a command line that exports a CSV of everything it
scanned. This server runs that scan once, keeps the CSV as a snapshot, and then
answers every question by streaming that file, so a drive is only read once.

Run it with:   python wiztree_mcp.py
"""

from __future__ import annotations

import contextlib
import csv
import ctypes
import fnmatch
import hashlib
import heapq
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Annotated, Any, Callable, Iterator, Literal

from mcp.server.mcpserver import Image, MCPServer
from pydantic import AliasChoices, Field

VERSION = "1.0.0"
MB = 1024 * 1024

# WizTree has a named mutex, so two concurrent runs fight over one instance.
_RUN_LOCK = threading.Lock()

# csv fields can be as long as a full Windows path plus quoting.
csv.field_size_limit(1 << 20)


# --------------------------------------------------------------------- paths


_DRIVE_ONLY = re.compile(r"^[a-zA-Z]:[\\/]?$")


def norm_path(value: str) -> str:
    """Normalise a Windows path for comparison and for passing to WizTree.

    Drive specs are special cased: ``os.path.abspath("C:")`` resolves to the
    *current directory on drive C:*, which is never what the caller means.
    Drive roots keep their trailing backslash, everything else loses it.
    """
    raw = value.strip().strip('"')
    if not raw:
        raise ValueError("Empty path")
    if _DRIVE_ONLY.match(raw):
        return raw[0].upper() + ":\\"
    result = os.path.abspath(raw)
    if len(result) > 1 and result[1] == ":":
        result = result[0].upper() + result[1:]
    if len(result) > 3:
        result = result.rstrip("\\")
    return result


def is_under(child: str, parent: str) -> bool:
    """True when `child` is `parent` itself or lives underneath it."""
    lower_child = child.lower()
    lower_parent = parent.lower()
    if lower_child == lower_parent:
        return True
    prefix = lower_parent if lower_parent.endswith("\\") else lower_parent + "\\"
    return lower_child.startswith(prefix)


def base_name(path: str) -> str:
    trimmed = path[:-1] if path.endswith("\\") else path
    idx = trimmed.rfind("\\")
    return trimmed if idx < 0 else trimmed[idx + 1 :]


def ext_of(path: str) -> str:
    """Lower-case extension including the dot; "" when the file has none."""
    name = base_name(path)
    idx = name.rfind(".")
    if idx <= 0:
        return ""
    return name[idx:].lower()


def depth_below(target: str, root: str) -> int:
    """Number of path separators below `root`. `root` itself is depth 0."""
    root_len = len(root) if root.endswith("\\") else len(root) + 1
    rest = target[root_len:].rstrip("\\")
    if not rest:
        return 0
    return 1 + rest.count("\\")


# ----------------------------------------------------------------- format


_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def human_bytes(size: float) -> str:
    """Human readable size using the 1024-based units WizTree itself shows."""
    sign = "-" if size < 0 else ""
    value = abs(float(size))
    unit = 0
    while value >= 1024 and unit < len(_UNITS) - 1:
        value /= 1024
        unit += 1
    digits = 0 if unit == 0 else (1 if value >= 100 else 2)
    return f"{sign}{value:.{digits}f} {_UNITS[unit]}"


def pct(part: float, whole: float) -> str:
    if not whole:
        return "-"
    return f"{part / whole * 100:.1f}%"


def human_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{int(seconds * 1000)} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes = int(seconds // 60)
    return f"{minutes}m {int(seconds - minutes * 60)}s"


def markdown_table(
    headers: list[str],
    rows: list[list[Any]],
    right_align: tuple[int, ...] = (),
) -> str:
    separator = ["---:" if i in right_align else "---" for i in range(len(headers))]

    def line(cells: list[Any]) -> str:
        return "| " + " | ".join(str(c).replace("|", "\\|") for c in cells) + " |"

    return "\n".join([line(headers), line(separator), *(line(r) for r in rows)])


def tidy_date(value: str) -> str:
    """WizTree writes 1899/12/30 when a timestamp is unknown."""
    if not value or value.startswith("1899/12/30"):
        return ""
    return value


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(fnmatch.translate(pattern), re.IGNORECASE)


# --------------------------------------------------------------- windows


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - any failure means "assume not elevated"
        return False


class _FixedFileInfo(ctypes.Structure):
    _fields_ = [
        ("dwSignature", ctypes.c_uint32),
        ("dwStrucVersion", ctypes.c_uint32),
        ("dwFileVersionMS", ctypes.c_uint32),
        ("dwFileVersionLS", ctypes.c_uint32),
        ("dwProductVersionMS", ctypes.c_uint32),
        ("dwProductVersionLS", ctypes.c_uint32),
        ("dwFileFlagsMask", ctypes.c_uint32),
        ("dwFileFlags", ctypes.c_uint32),
        ("dwFileOS", ctypes.c_uint32),
        ("dwFileType", ctypes.c_uint32),
        ("dwFileSubtype", ctypes.c_uint32),
        ("dwFileDateMS", ctypes.c_uint32),
        ("dwFileDateLS", ctypes.c_uint32),
    ]


def file_version(path: str) -> str | None:
    """Read the PE version resource, so wiztree_info can report it."""
    try:
        version_dll = ctypes.WinDLL("version")
        size = version_dll.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        buffer = ctypes.create_string_buffer(size)
        if not version_dll.GetFileVersionInfoW(path, 0, size, buffer):
            return None
        block = ctypes.c_void_p()
        length = ctypes.c_uint()
        if not version_dll.VerQueryValueW(
            buffer, "\\", ctypes.byref(block), ctypes.byref(length)
        ):
            return None
        info = ctypes.cast(block, ctypes.POINTER(_FixedFileInfo)).contents
        return (
            f"{info.dwFileVersionMS >> 16}.{info.dwFileVersionMS & 0xFFFF}."
            f"{info.dwFileVersionLS >> 16}.{info.dwFileVersionLS & 0xFFFF}"
        )
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------- live WizTree window
#
# WizTree paints its file list into a TVirtualDrawTree, an owner-drawn control
# whose rows never exist as text, so the scan *results* cannot be read from
# outside the process. What the window does expose through ordinary Win32
# messages is which target it currently points at - the title bar and the drive
# selector - and that is enough to follow along with whoever is driving the GUI.

_WM_GETTEXT = 0x000D
_WM_GETTEXTLENGTH = 0x000E
_SB_GETTEXTLENGTHW = 0x040C
_SB_GETTEXTW = 0x040D
_CB_GETCOUNT = 0x0146
_CB_GETCURSEL = 0x0147
_CB_GETLBTEXT = 0x0148
_CB_GETLBTEXTLEN = 0x0149
_SMTO_ABORTIFHUNG = 0x0002

_MAIN_WINDOW_CLASS = "TfrmWizTreeMain"
_TITLE_TARGET = re.compile(r"^\[(?P<target>.+?)\]\s*-\s*WizTree", re.IGNORECASE)
_DRIVE_ITEM = re.compile(r"^\[[A-Za-z]:\]")

_ENUM_PROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


def _win32():
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SendMessageTimeoutW.argtypes = [
        wintypes.HWND,
        ctypes.c_uint,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    user32.SendMessageTimeoutW.restype = ctypes.c_size_t
    return user32


def _send(user32, hwnd, message, wparam=0, lparam=None, timeout_ms=1500) -> int | None:
    """SendMessage that gives up instead of hanging on a busy WizTree."""
    result = ctypes.c_size_t()
    ok = user32.SendMessageTimeoutW(
        hwnd, message, wparam, lparam, _SMTO_ABORTIFHUNG, timeout_ms, ctypes.byref(result)
    )
    return None if ok == 0 else result.value


def _control_text(user32, hwnd) -> str:
    length = _send(user32, hwnd, _WM_GETTEXTLENGTH)
    if not length:
        return ""
    buffer = ctypes.create_unicode_buffer(length + 1)
    if _send(user32, hwnd, _WM_GETTEXT, length + 1, ctypes.cast(buffer, ctypes.c_void_p)) is None:
        return ""
    return buffer.value


def _class_name(user32, hwnd) -> str:
    buffer = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, buffer, 256)
    return buffer.value


def _combo_items(user32, hwnd) -> list[str]:
    count = _send(user32, hwnd, _CB_GETCOUNT) or 0
    items = []
    for index in range(min(count, 32)):
        length = _send(user32, hwnd, _CB_GETLBTEXTLEN, index)
        if not length or length > 4096:
            continue
        buffer = ctypes.create_unicode_buffer(length + 1)
        if _send(user32, hwnd, _CB_GETLBTEXT, index, ctypes.cast(buffer, ctypes.c_void_p)) is None:
            continue
        items.append(buffer.value)
    return items


@dataclass
class GuiInstance:
    pid: int
    hwnd: int
    title: str
    target: str | None
    drive_selection: str
    drive_choices: list[str]
    tabs: list[str]
    status: str
    responding: bool


def find_gui_instances() -> list[GuiInstance]:
    """Report every visible WizTree main window and what it points at."""
    user32 = _win32()
    windows: list[int] = []

    def collect(hwnd, _):
        if user32.IsWindowVisible(hwnd):
            buffer = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, buffer, 256)
            if buffer.value == _MAIN_WINDOW_CLASS:
                windows.append(hwnd)
        return True

    user32.EnumWindows(_ENUM_PROC(collect), 0)

    instances: list[GuiInstance] = []
    for hwnd in windows:
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        title = _control_text(user32, hwnd)
        responding = _send(user32, hwnd, _WM_GETTEXTLENGTH) is not None

        target = None
        match = _TITLE_TARGET.match(title)
        if match:
            with contextlib.suppress(ValueError):
                target = norm_path(match.group("target"))

        children: list[int] = []

        def gather(child, _):
            children.append(child)
            return True

        user32.EnumChildWindows(hwnd, _ENUM_PROC(gather), 0)

        drive_selection = ""
        drive_choices: list[str] = []
        tabs: list[str] = []
        status_parts: list[str] = []
        for child in children:
            cls = _class_name(user32, child)
            if cls == "TComboBox":
                items = _combo_items(user32, child)
                # The drive picker is the only combo listing "[C:] ..." entries,
                # which keeps this working whatever the UI language is.
                if any(_DRIVE_ITEM.match(item) for item in items):
                    drive_choices = items
                    drive_selection = _control_text(user32, child)
            elif cls == "TTabSheet":
                text = _control_text(user32, child)
                if text:
                    tabs.append(text)
            elif cls == "TStatusBar":
                for part in range(4):
                    length = _send(user32, child, _SB_GETTEXTLENGTHW, part)
                    if not length:
                        continue
                    length &= 0xFFFF
                    buffer = ctypes.create_unicode_buffer(length + 1)
                    if _send(user32, child, _SB_GETTEXTW, part, ctypes.cast(buffer, ctypes.c_void_p)) is None:
                        continue
                    if buffer.value:
                        status_parts.append(buffer.value)

        instances.append(
            GuiInstance(
                pid=pid.value,
                hwnd=hwnd,
                title=title,
                target=target,
                drive_selection=drive_selection,
                drive_choices=drive_choices,
                tabs=tabs,
                status=" | ".join(status_parts),
                responding=responding,
            )
        )
    return instances


def launch_gui(target: str | None) -> int:
    """Start a WizTree window and return immediately - it stays open for the user."""
    exe = resolve_wiztree_exe()
    args = [exe]
    if target:
        args.append(target)
    process = subprocess.Popen(args)  # noqa: S603 - deliberately not awaited
    return process.pid


_DRIVE_TYPES = {
    0: "unknown",
    1: "no root dir",
    2: "removable",
    3: "local",
    4: "network",
    5: "CD-ROM",
    6: "RAM disk",
}


@dataclass
class DriveEntry:
    letter: str
    label: str
    filesystem: str
    kind: str
    capacity: int
    used: int
    free: int


def list_logical_drives() -> list[DriveEntry]:
    kernel32 = ctypes.windll.kernel32
    buffer = ctypes.create_unicode_buffer(512)
    written = kernel32.GetLogicalDriveStringsW(len(buffer), buffer)
    roots = [r for r in buffer[:written].split("\0") if r]

    drives: list[DriveEntry] = []
    for root in roots:
        kind = _DRIVE_TYPES.get(kernel32.GetDriveTypeW(root), "unknown")
        label_buf = ctypes.create_unicode_buffer(261)
        fs_buf = ctypes.create_unicode_buffer(261)
        label = fs = ""
        if kernel32.GetVolumeInformationW(
            root, label_buf, len(label_buf), None, None, None, fs_buf, len(fs_buf)
        ):
            label, fs = label_buf.value, fs_buf.value
        capacity = used = free = 0
        with contextlib.suppress(OSError):
            usage = shutil.disk_usage(root)
            capacity, used, free = usage.total, usage.used, usage.free
        drives.append(
            DriveEntry(root.rstrip("\\"), label, fs, kind, capacity, used, free)
        )
    return drives


# ------------------------------------------------------- wiztree executable


_HERE = Path(__file__).resolve().parent
_cached_exe: str | None = None


def _candidate_paths() -> Iterator[Path]:
    env_exe = os.environ.get("WIZTREE_EXE")
    if env_exe:
        yield Path(env_exe)

    directories: list[Path] = []
    env_dir = os.environ.get("WIZTREE_DIR")
    if env_dir:
        directories.append(Path(env_dir))
    # This file usually lives in <wiztree-portable>/wiztree-mcp
    directories += [_HERE.parent, _HERE, _HERE.parent.parent, Path.cwd()]
    for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        base = os.environ.get(key)
        if base:
            directories.append(Path(base) / "WizTree")
    local = os.environ.get("LOCALAPPDATA")
    if local:
        directories.append(Path(local) / "Programs" / "WizTree")

    wide = sys.maxsize > 2**32
    names = ("WizTree64.exe", "WizTree.exe") if wide else ("WizTree.exe", "WizTree64.exe")
    for directory in directories:
        for name in names:
            yield directory / name


def resolve_wiztree_exe() -> str:
    global _cached_exe
    if _cached_exe:
        return _cached_exe
    for candidate in _candidate_paths():
        with contextlib.suppress(OSError):
            if candidate.is_file():
                _cached_exe = str(candidate)
                return _cached_exe
    raise RuntimeError(
        "WizTree executable not found. Set the WIZTREE_EXE environment variable to the "
        "full path of WizTree64.exe, or WIZTREE_DIR to the folder containing it."
    )


@dataclass
class RunResult:
    exit_code: int | None
    duration: float
    timed_out: bool


class _ShellExecuteInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def _run_elevated(exe: str, args: list[str], timeout: float) -> int:
    """Keep a handle to the elevated process, not WizTree's short-lived launcher."""
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_ShellExecuteInfo)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    info = _ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    # NOCLOSEPROCESS | NOASYNC | FLAG_NO_UI: UAC consent is still shown by Windows.
    info.fMask = 0x40 | 0x100 | 0x400
    info.lpVerb = "runas"
    info.lpFile = exe
    info.lpParameters = subprocess.list2cmdline(args)
    info.nShow = 0  # SW_HIDE
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.get_last_error()
        if error == 1223:  # ERROR_CANCELLED
            raise RuntimeError("WizTree administrator request was cancelled.")
        raise ctypes.WinError(error)
    if not info.hProcess:
        raise RuntimeError("Windows returned no handle for elevated WizTree.")
    try:
        # The scan timeout starts after Windows finishes the UAC consent dialog.
        status = kernel32.WaitForSingleObject(info.hProcess, int(timeout * 1000))
        if status == 0x102:  # WAIT_TIMEOUT
            if not kernel32.TerminateProcess(info.hProcess, 1):
                raise RuntimeError(
                    "Elevated WizTree timed out and could not be stopped; "
                    "close that scan before retrying."
                )
            kernel32.WaitForSingleObject(info.hProcess, 10000)
            # Never let callers accept a partial export on timeout.
            raise TimeoutError(f"Elevated WizTree scan aborted after {timeout}s.")
        if status != 0:  # WAIT_OBJECT_0
            raise ctypes.WinError(ctypes.get_last_error())
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code)):
            raise ctypes.WinError(ctypes.get_last_error())
        if exit_code.value:
            raise RuntimeError(f"Elevated WizTree failed (exit code {exit_code.value}).")
        return exit_code.value
    finally:
        kernel32.CloseHandle(info.hProcess)


def run_wiztree(args: list[str], timeout: float) -> RunResult:
    """Run WizTree once, serialised against every other run."""
    exe = resolve_wiztree_exe()
    # WizTree documents drive targets as C:, avoiding a quoted trailing backslash.
    if args and _DRIVE_ONLY.fullmatch(args[0]):
        args = [args[0][:2], *args[1:]]
    with _RUN_LOCK:
        started = time.monotonic()
        if "/admin=1" in args and not is_elevated():
            exit_code = _run_elevated(exe, args, timeout)
            return RunResult(exit_code, time.monotonic() - started, False)
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        process = subprocess.Popen(  # noqa: S603 - arguments are built here, never shell
            [exe, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags,
        )
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            # WizTree is a GUI process; taskkill is more reliable than terminate().
            with contextlib.suppress(Exception):
                subprocess.run(  # noqa: S603
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    capture_output=True,
                    check=False,
                    creationflags=creation_flags,
                )
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=10)
        return RunResult(process.returncode, time.monotonic() - started, timed_out)


def _flag(name: str, value: bool) -> str:
    return f"/{name}={1 if value else 0}"


@dataclass
class ExportOptions:
    export_folders: bool = True
    export_files: bool = True
    drive_capacity: bool = True
    all_dates: bool = False
    all_sizes: bool = False
    mft_rec_no: bool = False
    split_file_name: bool = False
    percent_of_parent: bool = False
    utc_time: bool = False
    filter: str | None = None
    filter_exclude: str | None = None
    filter_full_path: bool = False
    sort_by: int | None = None
    export_limit: int | None = None
    export_max_depth: int | None = None
    admin: bool = False


def build_export_args(
    target: str, csv_out: str, opts: ExportOptions, config_folder: str | None = None
) -> list[str]:
    # Values are passed unquoted. Python quotes each argv entry for CreateProcess,
    # and WizTree hangs on an invisible modal error if it receives doubled quotes.
    args = [target, f"/export={csv_out}"]
    args.append(_flag("exportfolders", opts.export_folders))
    args.append(_flag("exportfiles", opts.export_files))
    args.append(_flag("exportdrivecapacity", opts.drive_capacity))
    if opts.all_dates:
        args.append(_flag("exportalldates", True))
    if opts.all_sizes:
        args.append(_flag("exportallsizes", True))
    if opts.mft_rec_no:
        args.append(_flag("exportmftrecno", True))
    if opts.split_file_name:
        args.append(_flag("exportsplitfilename", True))
    if opts.percent_of_parent:
        args.append(_flag("exportpercentofparent", True))
    if opts.utc_time:
        args.append(_flag("exportUTCTime", True))
    if opts.filter:
        args.append(f"/filter={opts.filter}")
    if opts.filter_exclude:
        args.append(f"/filterexclude={opts.filter_exclude}")
    if opts.filter_full_path:
        args.append(_flag("filterfullpath", True))
    if opts.sort_by is not None:
        args.append(f"/sortby={opts.sort_by}")
    if opts.export_limit:
        args.append(f"/exportlimit={opts.export_limit}")
    if opts.export_max_depth:
        args.append(f"/exportmaxdepth={opts.export_max_depth}")
    args.append(_flag("admin", opts.admin))
    if config_folder:
        args.append(f"/configfolder={config_folder}")
    return args


def build_treemap_args(
    target: str,
    image_out: str,
    width: int,
    height: int,
    grayscale: bool,
    free_space: bool,
    allocated: bool,
    admin: bool,
    config_folder: str | None = None,
) -> list[str]:
    args = [target, f"/treemapimagefile={image_out}"]
    args.append(f"/treemapimagewidth={width}")
    args.append(f"/treemapimageheight={height}")
    if grayscale:
        args.append(_flag("treemapimagegray", True))
    if free_space:
        args.append(_flag("treemapimagefreespace", True))
    if allocated:
        args.append(_flag("treemapimageshowallocated", True))
    args.append(_flag("admin", admin))
    if config_folder:
        args.append(f"/configfolder={config_folder}")
    return args


# --------------------------------------------------------------------- csv

# WizTree CSV layout
# ------------------
# line 1 : localised banner ("Generated by WizTree 4.32 ..."), absent for supporters
# line 2 : header. The first seven columns are localised (in Italian the first one
#          is "Nome file"), while optional columns keep stable uppercase ASCII
#          names, which is what we key on. Folder rows end with a backslash.

BASE_COLUMNS = 7


@dataclass(slots=True)
class Row:
    path: str
    is_folder: bool
    size: int
    allocated: int
    modified: str
    attributes: int
    files: int
    folders: int


@dataclass
class DriveInfo:
    capacity: int = 0
    free: int = 0
    used: int = 0
    reserved: int = 0


@dataclass
class CsvMeta:
    header: list[str] = field(default_factory=list)
    extra_index: dict[str, int] = field(default_factory=dict)
    drive: DriveInfo | None = None
    rows: int = 0


def _to_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def read_wiztree_csv(path: str, on_row: Callable[[Row], Any] | None = None) -> CsvMeta:
    """Stream a WizTree export. `on_row` returning False stops the scan early."""
    meta = CsvMeta()
    with open(path, encoding="utf-8-sig", newline="") as handle:
        preamble: list[str] = []
        first_data: str | None = None
        for line in handle:
            if line.startswith('"'):
                first_data = line
                break
            preamble.append(line.rstrip("\r\n"))

        header_line = preamble[-1] if preamble else ""
        meta.header = next(csv.reader([header_line])) if header_line else []
        for index in range(BASE_COLUMNS, len(meta.header)):
            meta.extra_index[meta.header[index].strip().upper()] = index

        capacity_index = meta.extra_index.get("DRIVECAPACITY")
        free_index = meta.extra_index.get("FREESPACE", -1)
        used_index = meta.extra_index.get("USEDSPACE", -1)
        reserved_index = meta.extra_index.get("RESERVEDSPACE", -1)

        def remaining() -> Iterator[str]:
            if first_data is not None:
                yield first_data
            yield from handle

        for fields in csv.reader(remaining()):
            if not fields or not fields[0]:
                continue
            path_value = fields[0]
            meta.rows += 1

            if (
                capacity_index is not None
                and meta.drive is None
                and len(fields) > capacity_index
            ):
                capacity = _to_int(fields[capacity_index])
                if capacity > 0:
                    meta.drive = DriveInfo(
                        capacity=capacity,
                        free=_to_int(fields[free_index]) if free_index >= 0 else 0,
                        used=_to_int(fields[used_index]) if used_index >= 0 else 0,
                        reserved=_to_int(fields[reserved_index]) if reserved_index >= 0 else 0,
                    )

            if on_row is None:
                continue

            is_folder = path_value.endswith("\\")
            # WizTree writes extension-less files as "name." - Windows never allows
            # a real trailing dot, so dropping it restores the actual file name.
            if not is_folder and path_value.endswith("."):
                path_value = path_value[:-1]

            result = on_row(
                Row(
                    path=path_value,
                    is_folder=is_folder,
                    size=_to_int(fields[1]) if len(fields) > 1 else 0,
                    allocated=_to_int(fields[2]) if len(fields) > 2 else 0,
                    modified=fields[3] if len(fields) > 3 else "",
                    attributes=_to_int(fields[4]) if len(fields) > 4 else 0,
                    files=_to_int(fields[5]) if len(fields) > 5 else 0,
                    folders=_to_int(fields[6]) if len(fields) > 6 else 0,
                )
            )
            if result is False:
                break
    return meta


# ------------------------------------------------------------------ cache


def cache_dir() -> Path:
    override = os.environ.get("WIZTREE_MCP_CACHE")
    if override:
        base = Path(override)
    else:
        local = os.environ.get("LOCALAPPDATA")
        base = Path(local) / "wiztree-mcp" if local else Path(os.environ.get("TEMP", ".")) / "wiztree-mcp"
    base.mkdir(parents=True, exist_ok=True)
    return base


def config_dir() -> Path:
    directory = cache_dir() / "wiztree-config"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _registry_file() -> Path:
    return cache_dir() / "scans.json"


@dataclass
class ScanRecord:
    id: str
    root: str
    csv_path: str
    created_at: float
    duration: float
    csv_bytes: int
    rows: int
    admin: bool
    signature: str
    total_size: int
    total_allocated: int
    total_files: int
    total_folders: int
    filter: str | None = None
    filter_exclude: str | None = None
    drive_capacity: int = 0
    drive_free: int = 0
    drive_used: int = 0
    # False for CSVs the user exported themselves: those are never deleted by
    # pruning or by wiztree_clear_cache, we only stop tracking them.
    owned: bool = True


def _load_registry() -> list[ScanRecord]:
    try:
        raw = json.loads(_registry_file().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    records = []
    for item in raw if isinstance(raw, list) else []:
        with contextlib.suppress(TypeError):
            records.append(ScanRecord(**item))
    return records


def _save_registry(records: list[ScanRecord]) -> None:
    _registry_file().write_text(
        json.dumps([asdict(r) for r in records], indent=2), encoding="utf-8"
    )


def list_scans() -> list[ScanRecord]:
    records = [r for r in _load_registry() if Path(r.csv_path).exists()]
    records.sort(key=lambda r: r.created_at, reverse=True)
    return records


def clear_scans(scan_id: str | None = None) -> int:
    keep: list[ScanRecord] = []
    removed = 0
    for record in _load_registry():
        if scan_id and record.id != scan_id:
            keep.append(record)
            continue
        if record.owned:
            with contextlib.suppress(OSError):
                Path(record.csv_path).unlink(missing_ok=True)
        removed += 1
    _save_registry(keep)
    return removed


def _prune() -> None:
    limit = int(os.environ.get("WIZTREE_MCP_MAX_SCANS", "12"))
    records = _load_registry()
    records.sort(key=lambda r: r.created_at, reverse=True)
    for record in records[limit:]:
        if record.owned:
            with contextlib.suppress(OSError):
                Path(record.csv_path).unlink(missing_ok=True)
    _save_registry([r for r in records[:limit] if Path(r.csv_path).exists()])


def _signature(filter_: str | None, filter_exclude: str | None) -> str:
    return json.dumps({"f": filter_ or "", "x": filter_exclude or ""}, sort_keys=True)


def ensure_scan(
    raw_target: str,
    *,
    refresh: bool = False,
    max_age_minutes: int = 60,
    admin: bool = False,
    filter_: str | None = None,
    filter_exclude: str | None = None,
    timeout_seconds: int = 900,
) -> tuple[ScanRecord, bool]:
    """Return a snapshot covering `raw_target`, scanning only when needed."""
    target = norm_path(raw_target)
    signature = _signature(filter_, filter_exclude)

    if not refresh:
        max_age = max(0, max_age_minutes) * 60
        now = time.time()
        covering = [
            r
            for r in list_scans()
            if r.signature == signature
            and now - r.created_at <= max_age
            and is_under(target, r.root)
        ]
        # Most specific root first, then most recent.
        covering.sort(key=lambda r: (len(r.root), r.created_at), reverse=True)
        if covering:
            return covering[0], True

    if not Path(target).exists():
        raise ValueError(f"Path not found or not accessible: {target}")

    scan_id = hashlib.sha1(
        f"{target.lower()}{signature}{time.time()}".encode()
    ).hexdigest()[:12]
    csv_path = cache_dir() / f"scan-{scan_id}.csv"

    options = ExportOptions(
        filter=filter_,
        filter_exclude=filter_exclude,
        sort_by=0,
        admin=admin,
    )
    timeout = min(max(timeout_seconds, 10), 7200)
    run = run_wiztree(
        build_export_args(target, str(csv_path), options, str(config_dir())), timeout
    )

    if not csv_path.exists():
        if run.timed_out:
            raise RuntimeError(
                f"Scan of {target} aborted after {timeout}s. Raise timeout_seconds, or "
                "pass admin=true to read the NTFS master file table (far faster on whole volumes)."
            )
        raise RuntimeError(
            f"WizTree produced no export for {target} (exit code {run.exit_code}). "
            "Check that the path exists and is readable; a whole volume may require admin=true."
        )

    # The root row (first row of a folder export) already carries tree totals, so a
    # single streaming pass gives us row count, drive info and totals at once.
    totals = {"size": 0, "allocated": 0, "files": 0, "folders": 0}
    seen_root = False

    def collect(row: Row) -> None:
        nonlocal seen_root
        if seen_root:
            return
        seen_root = True
        totals.update(
            size=row.size, allocated=row.allocated, files=row.files, folders=row.folders
        )

    meta = read_wiztree_csv(str(csv_path), collect)
    drive = meta.drive or DriveInfo()

    record = ScanRecord(
        id=scan_id,
        root=target,
        csv_path=str(csv_path),
        created_at=time.time(),
        duration=run.duration,
        csv_bytes=csv_path.stat().st_size,
        rows=meta.rows,
        admin=admin,
        signature=signature,
        total_size=totals["size"],
        total_allocated=totals["allocated"],
        total_files=totals["files"],
        total_folders=totals["folders"],
        filter=filter_,
        filter_exclude=filter_exclude,
        drive_capacity=drive.capacity,
        drive_free=drive.free,
        drive_used=drive.used,
    )

    records = _load_registry()
    records.append(record)
    _save_registry(records)
    _prune()
    return record, False


# ---------------------------------------------------------------- queries


@dataclass(slots=True)
class Entry:
    path: str
    name: str
    is_folder: bool
    size: int
    allocated: int
    modified: str
    files: int
    folders: int


def _to_entry(row: Row) -> Entry:
    return Entry(
        path=row.path[:-1] if row.is_folder else row.path,
        name=base_name(row.path),
        is_folder=row.is_folder,
        size=row.size,
        allocated=row.allocated,
        modified=row.modified,
        files=row.files,
        folders=row.folders,
    )


@dataclass
class RowFilter:
    under: str | None = None
    kind: Literal["file", "folder", "any"] = "any"
    min_size: int | None = None
    extensions: list[str] | None = None
    name_match: re.Pattern[str] | None = None
    path_match: re.Pattern[str] | None = None
    exclude: str | None = None
    max_depth: int | None = None
    use_allocated: bool = False


def _make_predicate(rf: RowFilter, root: str) -> Callable[[Row], bool]:
    # Queries are always relative to an anchor: the explicit scope when given,
    # otherwise the scan root. The anchor row itself is never a result.
    anchor = (rf.under or root).rstrip("\\").lower()
    anchor_prefix = anchor + "\\"
    scoped = rf.under is not None
    depth_base = rf.under or root
    extensions = (
        {e if e.startswith(".") else "." + e for e in (x.lower() for x in rf.extensions)}
        if rf.extensions
        else None
    )
    exclude = rf.exclude.lower() if rf.exclude else None

    def predicate(row: Row) -> bool:
        if rf.kind == "file" and row.is_folder:
            return False
        if rf.kind == "folder" and not row.is_folder:
            return False

        value = row.allocated if rf.use_allocated else row.size
        if rf.min_size is not None and value < rf.min_size:
            return False

        bare = row.path[:-1] if row.is_folder else row.path
        lower = bare.lower()
        if lower == anchor:
            return False
        if scoped and not lower.startswith(anchor_prefix):
            return False

        if rf.max_depth is not None and depth_below(bare, depth_base) > rf.max_depth:
            return False
        if extensions is not None and (row.is_folder or ext_of(row.path) not in extensions):
            return False
        if exclude and exclude in lower:
            return False
        # search(), not match(): glob patterns are already anchored by
        # fnmatch.translate, while a user regex should behave like a find.
        if rf.name_match and not rf.name_match.search(base_name(row.path)):
            return False
        if rf.path_match and not rf.path_match.search(row.path):
            return False
        return True

    return predicate


@dataclass
class TopResult:
    entries: list[Entry]
    matched: int
    matched_size: int
    scope_size: int


def top_entries(
    csv_path: str,
    root: str,
    rf: RowFilter,
    limit: int,
    sort: Literal["size", "allocated", "modified", "name"] = "size",
) -> TopResult:
    """Single streaming pass returning the `limit` biggest matching rows."""
    predicate = _make_predicate(rf, root)
    anchor = (rf.under or root).rstrip("\\").lower()
    heap: list[tuple[Any, int, Entry]] = []
    by_name: list[Entry] = []
    counter = 0
    matched = 0
    matched_size = 0
    scope_size = 0

    def score(entry: Entry) -> Any:
        if sort == "allocated":
            return entry.allocated
        if sort == "modified":
            digits = re.sub(r"\D", "", entry.modified)
            return int(digits) if digits else 0
        return entry.size

    def visit(row: Row) -> None:
        nonlocal counter, matched, matched_size, scope_size
        if not scope_size and row.is_folder and row.path[:-1].lower() == anchor:
            scope_size = row.allocated if rf.use_allocated else row.size
        if not predicate(row):
            return
        matched += 1
        matched_size += row.size
        entry = _to_entry(row)
        if sort == "name":
            if len(by_name) < max(limit * 4, 5000):
                by_name.append(entry)
            return
        counter += 1
        item = (score(entry), counter, entry)
        if len(heap) < limit:
            heapq.heappush(heap, item)
        elif item[0] > heap[0][0]:
            heapq.heapreplace(heap, item)

    read_wiztree_csv(csv_path, visit)

    if sort == "name":
        entries = sorted(by_name, key=lambda e: e.path.lower())[:limit]
    else:
        entries = [e for _, _, e in sorted(heap, key=lambda i: i[0], reverse=True)]

    return TopResult(entries, matched, matched_size, scope_size)


@dataclass
class Breakdown:
    folder: Entry | None
    children: list[Entry]
    other_count: int
    other_size: int


def breakdown(csv_path: str, folder: str, limit: int, use_allocated: bool) -> Breakdown:
    """du-style listing of the direct children of one folder."""
    target = folder.rstrip("\\").lower()
    prefix = target + "\\"
    found: Entry | None = None
    children: list[Entry] = []

    def visit(row: Row) -> None:
        nonlocal found
        bare = (row.path[:-1] if row.is_folder else row.path).lower()
        if bare == target:
            found = _to_entry(row)
            return
        if not bare.startswith(prefix):
            return
        if "\\" in bare[len(prefix) :]:
            return  # deeper than one level
        children.append(_to_entry(row))

    read_wiztree_csv(csv_path, visit)
    key = (lambda e: e.allocated) if use_allocated else (lambda e: e.size)
    children.sort(key=key, reverse=True)
    rest = children[limit:]
    return Breakdown(found, children[:limit], len(rest), sum(key(e) for e in rest))


@dataclass
class TypeAggregate:
    extension: str
    count: int
    size: int
    allocated: int


def file_types(
    csv_path: str, root: str, rf: RowFilter, limit: int
) -> tuple[list[TypeAggregate], int, int]:
    rf.kind = "file"
    predicate = _make_predicate(rf, root)
    totals: dict[str, TypeAggregate] = {}
    total_size = 0
    total_count = 0

    def visit(row: Row) -> None:
        nonlocal total_size, total_count
        if not predicate(row):
            return
        extension = ext_of(row.path) or "(no extension)"
        aggregate = totals.get(extension)
        if aggregate is None:
            aggregate = TypeAggregate(extension, 0, 0, 0)
            totals[extension] = aggregate
        aggregate.count += 1
        aggregate.size += row.size
        aggregate.allocated += row.allocated
        total_size += row.size
        total_count += 1

    read_wiztree_csv(csv_path, visit)
    ordered = sorted(totals.values(), key=lambda a: a.size, reverse=True)[:limit]
    return ordered, total_size, total_count


# ------------------------------------------------------------- duplicates

# WizTree's duplicate finder lives in the GUI and has no command line switch,
# so this is computed here instead. The snapshot already holds every file and
# its size, which is the expensive half of the job; only the surviving
# same-size candidates ever get read from disk.

SAMPLE_WINDOW = 64 * 1024


def _long_path(path: str) -> str:
    r"""Add the \\?\ prefix so deep paths (node_modules...) stay openable."""
    if len(path) < 240 or path.startswith("\\\\"):
        return path
    return "\\\\?\\" + path


def _sample_digest(path: str, size: int) -> bytes | None:
    """Hash of size + first and last 64 KB. Bounded cost whatever the file size."""
    digest = hashlib.blake2b(digest_size=16)
    digest.update(size.to_bytes(8, "little"))
    try:
        with open(_long_path(path), "rb") as handle:
            digest.update(handle.read(SAMPLE_WINDOW))
            if size > 2 * SAMPLE_WINDOW:
                handle.seek(-SAMPLE_WINDOW, os.SEEK_END)
                digest.update(handle.read(SAMPLE_WINDOW))
    except OSError:
        return None
    return digest.digest()


def _full_digest(path: str, chunk: int = 1 << 20) -> bytes | None:
    digest = hashlib.blake2b(digest_size=16)
    try:
        with open(_long_path(path), "rb") as handle:
            while True:
                block = handle.read(chunk)
                if not block:
                    break
                digest.update(block)
    except OSError:
        return None
    return digest.digest()


@dataclass
class DuplicateGroup:
    size: int
    paths: list[str]
    verified: bool

    @property
    def wasted(self) -> int:
        return self.size * (len(self.paths) - 1)


@dataclass
class DuplicateReport:
    groups: list[DuplicateGroup]
    total_groups: int
    total_copies: int
    total_wasted: int
    candidates: int
    hashed: int
    bytes_read: int
    unreadable: int
    truncated: bool
    budget_exhausted: bool


def _split_by_digest(
    paths: list[str], digest_of: Callable[[str], bytes | None]
) -> tuple[list[list[str]], int]:
    """Bucket paths by content digest, reporting how many could not be read."""
    buckets: dict[bytes, list[str]] = {}
    unreadable = 0
    for path in paths:
        digest = digest_of(path)
        if digest is None:
            unreadable += 1
            continue
        buckets.setdefault(digest, []).append(path)
    return [group for group in buckets.values() if len(group) > 1], unreadable


def find_duplicates(
    csv_path: str,
    root: str,
    rf: RowFilter,
    *,
    verify_full: bool,
    max_read_bytes: int,
    max_candidates: int,
) -> DuplicateReport:
    rf.kind = "file"
    predicate = _make_predicate(rf, root)
    by_size: dict[int, list[str]] = {}
    candidates = 0
    truncated = False

    def visit(row: Row) -> None:
        nonlocal candidates, truncated
        if row.size <= 0 or not predicate(row):
            return
        if candidates >= max_candidates:
            truncated = True
            return
        candidates += 1
        by_size.setdefault(row.size, []).append(row.path)

    read_wiztree_csv(csv_path, visit)

    hashed = 0
    bytes_read = 0
    unreadable = 0
    budget_exhausted = False
    groups: list[DuplicateGroup] = []

    # Biggest files first: that is where the reclaimable space is, and it is the
    # order a reader cares about if the read budget runs out.
    for size in sorted((s for s, p in by_size.items() if len(p) > 1), reverse=True):
        paths = by_size[size]
        hashed += len(paths)
        bytes_read += min(size, 2 * SAMPLE_WINDOW) * len(paths)
        sampled, missing = _split_by_digest(paths, lambda p, s=size: _sample_digest(p, s))
        unreadable += missing

        for group in sampled:
            # A file at or below the sample window was read whole already.
            already_complete = size <= 2 * SAMPLE_WINDOW
            if not verify_full or already_complete:
                groups.append(DuplicateGroup(size, group, verified=already_complete))
                continue
            cost = size * len(group)
            if bytes_read + cost > max_read_bytes:
                budget_exhausted = True
                groups.append(DuplicateGroup(size, group, verified=False))
                continue
            bytes_read += cost
            hashed += len(group)
            confirmed, missing = _split_by_digest(group, _full_digest)
            unreadable += missing
            for exact in confirmed:
                groups.append(DuplicateGroup(size, exact, verified=True))

    groups.sort(key=lambda g: g.wasted, reverse=True)
    return DuplicateReport(
        groups=groups,
        total_groups=len(groups),
        total_copies=sum(len(g.paths) - 1 for g in groups),
        total_wasted=sum(g.wasted for g in groups),
        candidates=candidates,
        hashed=hashed,
        bytes_read=bytes_read,
        unreadable=unreadable,
        truncated=truncated,
        budget_exhausted=budget_exhausted,
    )


# ---------------------------------------------------------------- rendering


def snapshot_line(record: ScanRecord, target: str, reused: bool) -> str:
    age = int(time.time() - record.created_at)
    scope = "" if target.lower() == record.root.lower() else f" | query scope {target}"
    state = f"cached {age}s ago" if reused else f"fresh, scan took {human_duration(record.duration)}"
    return f"Snapshot {record.id} | root {record.root}{scope} | {record.rows:,} rows | {state}"


def render_entries(entries: list[Entry], total: int, share_label: str = "% of scope") -> str:
    if not entries:
        return "_No matching entries._"
    rows = [
        [
            index,
            human_bytes(entry.size),
            pct(entry.size, total) if total else "-",
            tidy_date(entry.modified),
            entry.path + "\\" if entry.is_folder else entry.path,
        ]
        for index, entry in enumerate(entries, start=1)
    ]
    return markdown_table(["#", "Size", share_label, "Modified", "Path"], rows, (0, 1, 2))


def join(*parts: str) -> str:
    return "\n\n".join(p for p in parts if p)


# ------------------------------------------------------------------ server


server = MCPServer(
    name="wiztree",
    version=VERSION,
    instructions=(
        "Drives WizTree (Windows disk space analyser) to answer questions about what is using "
        "disk space. Scans are cached as CSV snapshots and reused across tools, so call "
        "wiztree_scan once per drive and then query it with wiztree_top_files / "
        "wiztree_top_folders / wiztree_folder_breakdown / wiztree_file_types / wiztree_search. "
        "A full NTFS volume scan is near-instant with admin=true (MFT read) but triggers a UAC "
        "prompt; without it WizTree falls back to a much slower directory walk, so prefer "
        "scanning a specific folder in that case. "
        "The user may also have the WizTree window open and be driving it by hand: when they "
        "refer to what is on their screen ('this drive', 'here', 'what I have open') call "
        "wiztree_gui_state to find out what it points at, then query that target."
    ),
)

# A model asked to "scan drive D" tends to invent the argument name from the
# sentence rather than read the schema, and {"drive": "D:"} then fails validation.
# The published schema still advertises only "path"; these are just accepted too.
PATH_ALIASES = AliasChoices("path", "drive", "folder", "directory", "target")

# Shared parameter annotations, so every query tool speaks the same language.
PathArg = Annotated[
    str | None,
    Field(
        default=None,
        validation_alias=PATH_ALIASES,
        description='Drive or folder to analyse, e.g. "C:" or "C:\\Users\\me\\Downloads". '
        "Defaults to the most recent scan.",
    ),
]
RefreshArg = Annotated[
    bool, Field(default=False, description="Force a fresh scan instead of reusing the snapshot.")
]
MaxAgeArg = Annotated[
    int, Field(default=60, ge=0, le=10080, description="Reuse a snapshot only if younger than this, in minutes.")
]
AdminArg = Annotated[
    bool,
    Field(
        default=False,
        description="Run WizTree elevated so NTFS volumes are read straight from the MFT "
        "(seconds instead of minutes). Triggers a Windows UAC prompt.",
    ),
]
FilterArg = Annotated[
    str | None,
    Field(default=None, description='WizTree include filter applied while scanning, e.g. "*.mp4|*.mkv".'),
]
FilterExcludeArg = Annotated[
    str | None,
    Field(default=None, description='WizTree exclude filter applied while scanning, e.g. "*.tmp|*.log".'),
]
TimeoutArg = Annotated[
    int, Field(default=900, ge=10, le=7200, description="Abort the WizTree run after this many seconds.")
]


def resolve_target(value: str | None) -> str:
    if value and value.strip():
        return norm_path(value)
    scans = list_scans()
    if not scans:
        raise ValueError(
            'No cached scan yet - pass "path" (for example "C:") or call wiztree_scan first.'
        )
    return scans[0].root


def snapshot_for(
    path: str | None,
    refresh: bool,
    max_age_minutes: int,
    admin: bool,
    filter_: str | None,
    filter_exclude: str | None,
    timeout_seconds: int,
) -> tuple[ScanRecord, str, bool]:
    target = resolve_target(path)
    record, reused = ensure_scan(
        target,
        refresh=refresh,
        max_age_minutes=max_age_minutes,
        admin=admin,
        filter_=filter_,
        filter_exclude=filter_exclude,
        timeout_seconds=timeout_seconds,
    )
    return record, target, reused


@server.tool(
    name="wiztree_info",
    description=(
        "Report the WizTree executable in use, its version, whether this process is elevated "
        "(needed for fast MFT scans), the snapshot cache location and how many cached scans "
        "exist. Call this first when something is not working."
    ),
)
def wiztree_info() -> str:
    exe = resolve_wiztree_exe()
    elevated = (
        "yes - fast MFT scans available"
        if is_elevated()
        else "no - whole-volume scans fall back to a slow directory walk unless admin=true is passed (UAC prompt)"
    )
    return "\n".join(
        [
            f"WizTree executable : {exe}",
            f"WizTree version    : {file_version(exe) or 'unknown'}",
            f"Elevated process   : {elevated}",
            f"Snapshot cache     : {cache_dir()}",
            f"Cached snapshots   : {len(list_scans())}",
            f"Server version     : wiztree-mcp {VERSION} on Python {sys.version.split()[0]}",
        ]
    )


@server.tool(
    name="wiztree_list_drives",
    description=(
        "List the Windows logical drives with capacity, free space and file system. "
        "Use it to pick a target before scanning."
    ),
)
def wiztree_list_drives() -> str:
    drives = list_logical_drives()
    if not drives:
        return "No logical drives reported by Windows."
    rows = [
        [
            d.letter,
            d.label or "-",
            d.filesystem or "-",
            d.kind,
            human_bytes(d.capacity) if d.capacity else "-",
            human_bytes(d.used) if d.capacity else "-",
            human_bytes(d.free) if d.capacity else "-",
            pct(d.used, d.capacity) if d.capacity else "-",
        ]
        for d in drives
    ]
    return markdown_table(
        ["Drive", "Label", "FS", "Type", "Capacity", "Used", "Free", "Used %"],
        rows,
        (4, 5, 6, 7),
    )


@server.tool(
    name="wiztree_scan",
    description=(
        "Run WizTree over a drive or folder and cache the result as a reusable snapshot. "
        "Returns totals, drive free space and the biggest top-level items. Every other "
        "wiztree_* query reuses this snapshot automatically, so you rarely need to call it "
        "twice for the same target."
    ),
)
def wiztree_scan(
    path: Annotated[
        str,
        Field(
            validation_alias=PATH_ALIASES,
            description='Drive or folder to scan, e.g. "C:" or "C:\\Users\\me\\Downloads".',
        ),
    ],
    top_level_limit: Annotated[
        int, Field(default=15, ge=0, le=100, description="How many top-level items to include in the summary.")
    ] = 15,
    refresh: RefreshArg = False,
    max_age_minutes: MaxAgeArg = 60,
    admin: AdminArg = False,
    filter: FilterArg = None,
    filter_exclude: FilterExcludeArg = None,
    timeout_seconds: TimeoutArg = 900,
) -> str:
    record, target, reused = snapshot_for(
        path, refresh, max_age_minutes, admin, filter, filter_exclude, timeout_seconds
    )
    summary = [
        f"Scanned root  : {record.root}",
        f"Total size    : {human_bytes(record.total_size)} ({record.total_size:,} bytes)",
        f"On disk       : {human_bytes(record.total_allocated)} allocated",
        f"Contents      : {record.total_files:,} files in {record.total_folders:,} folders",
    ]
    if record.drive_capacity:
        summary.append(
            f"Volume        : {human_bytes(record.drive_capacity)} capacity, "
            f"{human_bytes(record.drive_used)} used ({pct(record.drive_used, record.drive_capacity)}), "
            f"{human_bytes(record.drive_free)} free"
        )
    if record.filter or record.filter_exclude:
        summary.append(
            f"Scan filters  : include={record.filter or '-'} exclude={record.filter_exclude or '-'}"
        )

    parts = [snapshot_line(record, target, reused), "\n".join(summary)]
    if top_level_limit > 0:
        view = breakdown(record.csv_path, record.root, top_level_limit, False)
        scope_total = view.folder.size if view.folder else record.total_size
        parts.append(
            f"Biggest items directly under {record.root}:\n"
            + render_entries(view.children, scope_total, "% of root")
        )
        if view.other_count:
            parts.append(
                f"+ {view.other_count} smaller items totalling {human_bytes(view.other_size)}."
            )
    return join(*parts)


@server.tool(
    name="wiztree_top_files",
    description=(
        "List the largest files in a snapshot, optionally restricted to a subfolder, to certain "
        "extensions or to a minimum size. This is the tool to answer 'what is eating my disk space'."
    ),
)
def wiztree_top_files(
    path: PathArg = None,
    limit: Annotated[int, Field(default=25, ge=1, le=500, description="How many files to return.")] = 25,
    min_size_mb: Annotated[
        float, Field(default=0, ge=0, description="Ignore files smaller than this many MB.")
    ] = 0,
    extensions: Annotated[
        list[str] | None,
        Field(default=None, description='Only these extensions, e.g. ["mp4", ".iso"].'),
    ] = None,
    exclude_pattern: Annotated[
        str | None,
        Field(default=None, description="Drop files whose full path contains this text (case-insensitive)."),
    ] = None,
    use_allocated: Annotated[
        bool, Field(default=False, description="Rank by space allocated on disk instead of logical size.")
    ] = False,
    sort_by: Annotated[
        Literal["size", "allocated", "modified"], Field(default="size", description="Ranking key.")
    ] = "size",
    refresh: RefreshArg = False,
    max_age_minutes: MaxAgeArg = 60,
    admin: AdminArg = False,
    filter: FilterArg = None,
    filter_exclude: FilterExcludeArg = None,
    timeout_seconds: TimeoutArg = 900,
) -> str:
    record, target, reused = snapshot_for(
        path, refresh, max_age_minutes, admin, filter, filter_exclude, timeout_seconds
    )
    scoped = target.lower() != record.root.lower()
    rf = RowFilter(
        under=target if scoped else None,
        kind="file",
        min_size=int(min_size_mb * MB) if min_size_mb else None,
        extensions=extensions or None,
        exclude=exclude_pattern,
        use_allocated=use_allocated,
    )
    result = top_entries(record.csv_path, record.root, rf, limit, sort_by)
    return join(
        snapshot_line(record, target, reused),
        f"{result.matched:,} files match, totalling {human_bytes(result.matched_size)}. "
        f"Showing the top {len(result.entries)}.",
        render_entries(result.entries, result.matched_size, "% of matches"),
    )


@server.tool(
    name="wiztree_top_folders",
    description=(
        "List the largest folders in a snapshot. Folder sizes are recursive totals, so a parent "
        "and its child can both appear; use max_depth to keep the answer at a readable level of "
        "the tree."
    ),
)
def wiztree_top_folders(
    path: PathArg = None,
    limit: Annotated[int, Field(default=25, ge=1, le=500, description="How many folders to return.")] = 25,
    min_size_mb: Annotated[
        float, Field(default=0, ge=0, description="Ignore folders smaller than this many MB.")
    ] = 0,
    max_depth: Annotated[
        int | None,
        Field(default=None, ge=1, le=30, description="Only folders at most this many levels below the scope (1 = direct children)."),
    ] = None,
    exclude_pattern: Annotated[
        str | None,
        Field(default=None, description="Drop folders whose full path contains this text (case-insensitive)."),
    ] = None,
    use_allocated: Annotated[
        bool, Field(default=False, description="Rank by allocated size instead of logical size.")
    ] = False,
    refresh: RefreshArg = False,
    max_age_minutes: MaxAgeArg = 60,
    admin: AdminArg = False,
    filter: FilterArg = None,
    filter_exclude: FilterExcludeArg = None,
    timeout_seconds: TimeoutArg = 900,
) -> str:
    record, target, reused = snapshot_for(
        path, refresh, max_age_minutes, admin, filter, filter_exclude, timeout_seconds
    )
    scoped = target.lower() != record.root.lower()
    rf = RowFilter(
        under=target if scoped else None,
        kind="folder",
        min_size=int(min_size_mb * MB) if min_size_mb else None,
        exclude=exclude_pattern,
        max_depth=max_depth,
        use_allocated=use_allocated,
    )
    result = top_entries(
        record.csv_path,
        target if scoped else record.root,
        rf,
        limit,
        "allocated" if use_allocated else "size",
    )
    scope_total = result.scope_size or record.total_size
    return join(
        snapshot_line(record, target, reused),
        f"{result.matched:,} folders match, inside {human_bytes(scope_total)} of scanned data. "
        f"Showing the top {len(result.entries)}. Sizes include everything underneath each folder, "
        "so a parent and its child can both appear.",
        render_entries(result.entries, scope_total),
    )


@server.tool(
    name="wiztree_folder_breakdown",
    description=(
        "Show what sits directly inside one folder - subfolders and files side by side, biggest "
        "first, with their share of the parent. This is the drill-down tool: call it repeatedly "
        "to walk down towards whatever is using the space."
    ),
)
def wiztree_folder_breakdown(
    path: Annotated[
        str,
        Field(
            validation_alias=PATH_ALIASES,
            description='Folder to break down, e.g. "C:\\Users\\me\\AppData".',
        ),
    ],
    limit: Annotated[int, Field(default=25, ge=1, le=200, description="How many children to show.")] = 25,
    use_allocated: Annotated[
        bool, Field(default=False, description="Use allocated size instead of logical size.")
    ] = False,
    refresh: RefreshArg = False,
    max_age_minutes: MaxAgeArg = 60,
    admin: AdminArg = False,
    filter: FilterArg = None,
    filter_exclude: FilterExcludeArg = None,
    timeout_seconds: TimeoutArg = 900,
) -> str:
    record, target, reused = snapshot_for(
        path, refresh, max_age_minutes, admin, filter, filter_exclude, timeout_seconds
    )
    view = breakdown(record.csv_path, target, limit, use_allocated)
    if view.folder is None and not view.children:
        return join(
            snapshot_line(record, target, reused),
            f"No entry for {target} in this snapshot. Check the path, or rescan with refresh=true.",
        )
    total = 0
    header = target
    if view.folder is not None:
        total = view.folder.allocated if use_allocated else view.folder.size
        header = (
            f"{target} - {human_bytes(total)} across {view.folder.files:,} files "
            f"in {view.folder.folders:,} folders."
        )
    parts = [
        snapshot_line(record, target, reused),
        header,
        render_entries(view.children, total, "% of folder"),
    ]
    if view.other_count:
        parts.append(
            f"+ {view.other_count} smaller children totalling {human_bytes(view.other_size)}."
        )
    return join(*parts)


@server.tool(
    name="wiztree_file_types",
    description=(
        "Aggregate disk usage by file extension across the snapshot (or a subfolder), biggest "
        "first. Answers questions like 'how much of this drive is video' or 'what kind of files "
        "fill this folder'."
    ),
)
def wiztree_file_types(
    path: PathArg = None,
    limit: Annotated[int, Field(default=20, ge=1, le=200, description="How many extensions to list.")] = 20,
    min_size_mb: Annotated[
        float, Field(default=0, ge=0, description="Ignore files smaller than this many MB.")
    ] = 0,
    refresh: RefreshArg = False,
    max_age_minutes: MaxAgeArg = 60,
    admin: AdminArg = False,
    filter: FilterArg = None,
    filter_exclude: FilterExcludeArg = None,
    timeout_seconds: TimeoutArg = 900,
) -> str:
    record, target, reused = snapshot_for(
        path, refresh, max_age_minutes, admin, filter, filter_exclude, timeout_seconds
    )
    scoped = target.lower() != record.root.lower()
    rf = RowFilter(
        under=target if scoped else None,
        min_size=int(min_size_mb * MB) if min_size_mb else None,
    )
    types, total_size, total_count = file_types(record.csv_path, record.root, rf, limit)
    if not types:
        body = "_No files in scope._"
    else:
        rows = [
            [
                index,
                aggregate.extension,
                human_bytes(aggregate.size),
                pct(aggregate.size, total_size),
                f"{aggregate.count:,}",
                human_bytes(aggregate.allocated),
            ]
            for index, aggregate in enumerate(types, start=1)
        ]
        body = markdown_table(
            ["#", "Extension", "Size", "% of scope", "Files", "On disk"], rows, (0, 2, 3, 4, 5)
        )
    return join(
        snapshot_line(record, target, reused),
        f"{total_count:,} files totalling {human_bytes(total_size)} in scope.",
        body,
    )


@server.tool(
    name="wiztree_search",
    description=(
        "Find files or folders by name pattern inside a snapshot, ranked by size. Supports glob "
        "patterns (default) or regular expressions, matched against the name or the whole path."
    ),
)
def wiztree_search(
    pattern: Annotated[
        str,
        Field(
            validation_alias=AliasChoices("pattern", "query", "name", "search"),
            description='Glob such as "*.iso" or "node_modules", or a regular expression when regex=true.',
        ),
    ],
    path: PathArg = None,
    regex: Annotated[
        bool, Field(default=False, description="Treat pattern as a Python regular expression.")
    ] = False,
    match_full_path: Annotated[
        bool, Field(default=False, description="Match against the full path instead of just the name.")
    ] = False,
    kind: Annotated[
        Literal["file", "folder", "any"], Field(default="any", description="What to return.")
    ] = "any",
    limit: Annotated[int, Field(default=30, ge=1, le=500, description="How many hits to return.")] = 30,
    min_size_mb: Annotated[
        float, Field(default=0, ge=0, description="Ignore entries smaller than this many MB.")
    ] = 0,
    sort_by: Annotated[
        Literal["size", "modified", "name"], Field(default="size", description="Ranking key.")
    ] = "size",
    refresh: RefreshArg = False,
    max_age_minutes: MaxAgeArg = 60,
    admin: AdminArg = False,
    filter: FilterArg = None,
    filter_exclude: FilterExcludeArg = None,
    timeout_seconds: TimeoutArg = 900,
) -> str:
    record, target, reused = snapshot_for(
        path, refresh, max_age_minutes, admin, filter, filter_exclude, timeout_seconds
    )
    scoped = target.lower() != record.root.lower()

    # A bare word is treated as a substring match, which is what people expect from "search".
    looks_like_glob = any(c in pattern for c in "*?[")
    effective = pattern if (regex or looks_like_glob or match_full_path) else f"*{pattern}*"
    compiled = re.compile(effective, re.IGNORECASE) if regex else glob_to_regex(effective)

    rf = RowFilter(
        under=target if scoped else None,
        kind=kind,
        min_size=int(min_size_mb * MB) if min_size_mb else None,
        name_match=None if match_full_path else compiled,
        path_match=compiled if match_full_path else None,
    )
    result = top_entries(record.csv_path, record.root, rf, limit, sort_by)
    if not result.entries:
        body = "_No matches._"
    else:
        rows = [
            [
                index,
                "folder" if entry.is_folder else "file",
                human_bytes(entry.size),
                tidy_date(entry.modified),
                entry.path + "\\" if entry.is_folder else entry.path,
            ]
            for index, entry in enumerate(result.entries, start=1)
        ]
        body = markdown_table(["#", "Type", "Size", "Modified", "Path"], rows, (0, 2))
    return join(
        snapshot_line(record, target, reused),
        f"{result.matched:,} matches totalling {human_bytes(result.matched_size)}. "
        f"Showing {len(result.entries)}.",
        body,
    )


@server.tool(
    name="wiztree_duplicates",
    description=(
        "Find duplicate files - same size and same content - and report how much space could be "
        "reclaimed by keeping one copy of each. Only files that share a size are ever read from "
        "disk, so this stays fast even on a large snapshot. WizTree's own duplicate finder is "
        "GUI-only, so this is computed from the snapshot instead."
    ),
)
def wiztree_duplicates(
    path: PathArg = None,
    min_size_mb: Annotated[
        float,
        Field(default=1, ge=0, description="Ignore files smaller than this many MB. Small files create a lot of uninteresting noise."),
    ] = 1,
    limit: Annotated[
        int, Field(default=25, ge=1, le=200, description="How many duplicate groups to show, biggest waste first.")
    ] = 25,
    paths_per_group: Annotated[
        int, Field(default=10, ge=2, le=100, description="How many paths to list per group.")
    ] = 10,
    extensions: Annotated[
        list[str] | None,
        Field(default=None, description='Only these extensions, e.g. ["iso", ".mp4"].'),
    ] = None,
    exclude_pattern: Annotated[
        str | None,
        Field(default=None, description="Drop files whose full path contains this text (case-insensitive)."),
    ] = None,
    verify: Annotated[
        Literal["sample", "full"],
        Field(
            default="sample",
            description="'sample' compares size plus the first and last 64 KB - fast and reliable in "
            "practice. 'full' hashes the whole file, which is exact but reads every candidate.",
        ),
    ] = "sample",
    max_read_gb: Annotated[
        float,
        Field(default=8, ge=0.1, le=1000, description="Read budget for verify='full'. Groups beyond it stay sample-verified."),
    ] = 8,
    max_candidates: Annotated[
        int, Field(default=200000, ge=1000, le=5000000, description="Safety cap on how many files enter the comparison.")
    ] = 200000,
    refresh: RefreshArg = False,
    max_age_minutes: MaxAgeArg = 60,
    admin: AdminArg = False,
    filter: FilterArg = None,
    filter_exclude: FilterExcludeArg = None,
    timeout_seconds: TimeoutArg = 900,
) -> str:
    record, target, reused = snapshot_for(
        path, refresh, max_age_minutes, admin, filter, filter_exclude, timeout_seconds
    )
    scoped = target.lower() != record.root.lower()
    rf = RowFilter(
        under=target if scoped else None,
        min_size=int(min_size_mb * MB) if min_size_mb else None,
        extensions=extensions or None,
        exclude=exclude_pattern,
    )

    started = time.monotonic()
    report = find_duplicates(
        record.csv_path,
        record.root,
        rf,
        verify_full=verify == "full",
        max_read_bytes=int(max_read_gb * 1024 * MB),
        max_candidates=max_candidates,
    )
    elapsed = time.monotonic() - started

    if not report.groups:
        return join(
            snapshot_line(record, target, reused),
            f"No duplicates found among {report.candidates:,} files of at least "
            f"{human_bytes(int(min_size_mb * MB))}.",
        )

    headline = (
        f"{report.total_groups:,} duplicate groups, {report.total_copies:,} redundant copies, "
        f"{human_bytes(report.total_wasted)} reclaimable."
    )
    method = (
        "whole-file hash"
        if verify == "full"
        else "size plus first and last 64 KB (not a whole-file comparison)"
    )
    stats = (
        f"Compared {report.candidates:,} files by size, then hashed {report.hashed:,} of them "
        f"({human_bytes(report.bytes_read)} read) in {human_duration(elapsed)}. Method: {method}."
    )

    notes = []
    if report.unreadable:
        notes.append(f"{report.unreadable:,} files could not be read and were skipped.")
    if report.budget_exhausted:
        notes.append(
            f"The {max_read_gb} GB read budget ran out; groups marked [sample] were not fully "
            "verified. Raise max_read_gb to confirm them."
        )
    if report.truncated:
        notes.append(
            f"Only the first {max_candidates:,} matching files were compared. Raise min_size_mb "
            "or max_candidates for full coverage."
        )

    blocks = []
    for index, group in enumerate(report.groups[:limit], start=1):
        mark = "" if group.verified else "  [sample]"
        header = (
            f"{index}. {human_bytes(group.size)} x {len(group.paths)} = "
            f"{human_bytes(group.wasted)} reclaimable{mark}"
        )
        shown = group.paths[:paths_per_group]
        lines = [f"   {p}" for p in shown]
        if len(group.paths) > len(shown):
            lines.append(f"   ... and {len(group.paths) - len(shown)} more copies")
        blocks.append("\n".join([header, *lines]))

    tail = ""
    if report.total_groups > limit:
        remaining = report.groups[limit:]
        tail = (
            f"+ {len(remaining):,} smaller groups worth "
            f"{human_bytes(sum(g.wasted for g in remaining))}."
        )

    return join(
        snapshot_line(record, target, reused),
        headline,
        stats,
        " ".join(notes),
        "\n\n".join(blocks),
        tail,
    )


@server.tool(
    name="wiztree_treemap",
    description=(
        "Render WizTree's treemap of a drive or folder as a PNG file - a visual map where each "
        "rectangle is sized by disk usage. Returns the image path, and optionally the image itself."
    ),
    structured_output=False,
)
def wiztree_treemap(
    path: PathArg = None,
    output_path: Annotated[
        str | None,
        Field(default=None, description="Where to write the PNG. Defaults to a file in the snapshot cache folder."),
    ] = None,
    width: Annotated[int, Field(default=1600, ge=160, le=7680, description="Image width in pixels.")] = 1600,
    height: Annotated[int, Field(default=1000, ge=120, le=4320, description="Image height in pixels.")] = 1000,
    grayscale: Annotated[
        bool, Field(default=False, description="Render in shades of grey instead of colour.")
    ] = False,
    show_free_space: Annotated[
        bool, Field(default=False, description="Include free space as a block in the map.")
    ] = False,
    show_allocated: Annotated[
        bool, Field(default=False, description="Size blocks by allocated space instead of file size.")
    ] = False,
    return_image: Annotated[
        bool, Field(default=False, description="Also return the PNG inline so it can be viewed directly (only under 4 MB)."),
    ] = False,
    refresh: RefreshArg = False,
    admin: AdminArg = False,
    timeout_seconds: TimeoutArg = 900,
) -> list[Any]:
    target = resolve_target(path)
    out = Path(output_path).resolve() if output_path else cache_dir() / f"treemap-{int(time.time())}.png"
    out.parent.mkdir(parents=True, exist_ok=True)

    # WizTree can re-open one of its own CSV exports, so an existing snapshot of
    # exactly this root gives us the picture without touching the disk again.
    source = target
    note = "rendered from a fresh WizTree scan"
    if not refresh:
        for record in list_scans():
            if record.root.lower() == target.lower() and Path(record.csv_path).exists():
                source = record.csv_path
                note = f"rendered from cached snapshot {record.id}"
                break
    if source == target and not Path(target).exists():
        raise ValueError(f"Path not found: {target}")

    run = run_wiztree(
        build_treemap_args(
            source,
            str(out),
            width,
            height,
            grayscale,
            show_free_space,
            show_allocated,
            admin,
            str(config_dir()),
        ),
        min(max(timeout_seconds, 10), 7200),
    )
    if not out.exists():
        raise RuntimeError(
            f"WizTree produced no treemap for {target} (exit {run.exit_code}"
            f"{', timed out' if run.timed_out else ''})."
        )

    size = out.stat().st_size
    summary = (
        f"Treemap of {target} -> {out} ({human_bytes(size)}, {note}, "
        f"{human_duration(run.duration)})."
    )
    if return_image and size <= 4 * MB:
        return [summary, Image(path=str(out))]
    return [summary]


@server.tool(
    name="wiztree_export_csv",
    description=(
        "Run WizTree with full control over its export options and write the CSV wherever you "
        "want - useful to hand the raw data to another tool or to keep a report. Prefer the query "
        "tools for answering questions."
    ),
)
def wiztree_export_csv(
    path: Annotated[
        str, Field(validation_alias=PATH_ALIASES, description="Drive or folder to scan.")
    ],
    output_path: Annotated[str, Field(description="Destination .csv file.")],
    include_folders: Annotated[bool, Field(default=True, description="Include folder rows.")] = True,
    include_files: Annotated[bool, Field(default=True, description="Include file rows.")] = True,
    filter: FilterArg = None,
    filter_exclude: FilterExcludeArg = None,
    filter_full_path: Annotated[
        bool, Field(default=False, description="Apply filters to the whole path.")
    ] = False,
    all_dates: Annotated[
        bool, Field(default=False, description="Add LASTACCESSDATE and CREATEDDATE columns.")
    ] = False,
    all_sizes: Annotated[
        bool, Field(default=False, description="Add FOLDERSIZE and FOLDERALLOCATED columns.")
    ] = False,
    mft_rec_no: Annotated[
        bool, Field(default=False, description="Add MFTRECNO and MFTPARENTRECNO columns.")
    ] = False,
    split_file_name: Annotated[
        bool, Field(default=False, description="Add ROOT, FOLDERNAME, FILENAME and FILEEXT columns.")
    ] = False,
    percent_of_parent: Annotated[
        bool, Field(default=False, description="Add the PERCENTOFPARENT column.")
    ] = False,
    utc_time: Annotated[bool, Field(default=False, description="Write timestamps in UTC.")] = False,
    sort_by: Annotated[
        int,
        Field(default=0, ge=0, le=3, description="0 = unsorted, 1 = size desc, 2 = allocated desc, 3 = modified desc."),
    ] = 0,
    export_limit: Annotated[
        int | None, Field(default=None, ge=1, description="Stop after N exported rows.")
    ] = None,
    export_max_depth: Annotated[
        int | None, Field(default=None, ge=1, description="Only export N levels below the root.")
    ] = None,
    admin: AdminArg = False,
    timeout_seconds: TimeoutArg = 900,
) -> str:
    target = norm_path(path)
    if not Path(target).exists():
        raise ValueError(f"Path not found: {target}")
    out = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    options = ExportOptions(
        export_folders=include_folders,
        export_files=include_files,
        filter=filter,
        filter_exclude=filter_exclude,
        filter_full_path=filter_full_path,
        all_dates=all_dates,
        all_sizes=all_sizes,
        mft_rec_no=mft_rec_no,
        split_file_name=split_file_name,
        percent_of_parent=percent_of_parent,
        utc_time=utc_time,
        sort_by=sort_by,
        export_limit=export_limit,
        export_max_depth=export_max_depth,
        admin=admin,
    )
    run = run_wiztree(
        build_export_args(target, str(out), options, str(config_dir())),
        min(max(timeout_seconds, 10), 7200),
    )
    if not out.exists():
        raise RuntimeError(
            f"WizTree produced no export for {target} (exit {run.exit_code}"
            f"{', timed out' if run.timed_out else ''})."
        )
    return (
        f"Exported {target} to {out} ({human_bytes(out.stat().st_size)}) "
        f"in {human_duration(run.duration)}."
    )


@server.tool(
    name="wiztree_gui_state",
    description=(
        "Look at the WizTree window the user is driving right now and report what it points at: "
        "the loaded target, the selected drive, the active tab and the status bar. Call this "
        "whenever the user says things like 'what I have open in WizTree', 'this drive' or 'here' "
        "without naming a path, then pass the reported target to the other tools. Note that "
        "WizTree's result list is owner-drawn, so its rows cannot be read - only what it is "
        "pointing at."
    ),
)
def wiztree_gui_state() -> str:
    instances = find_gui_instances()
    if not instances:
        return (
            "No WizTree window is open. Use wiztree_open_gui to start one, or just pass an "
            "explicit path to the query tools - they do not need the GUI."
        )

    blocks = []
    for index, gui in enumerate(instances, start=1):
        lines = [
            f"{index}. WizTree window (pid {gui.pid})",
            f"   Title           : {gui.title or '(none)'}",
            f"   Loaded target   : {gui.target or 'nothing scanned yet'}",
        ]
        if gui.drive_selection:
            lines.append(f"   Drive selector  : {gui.drive_selection}")
        if gui.drive_choices:
            lines.append(f"   Available       : {', '.join(gui.drive_choices)}")
        if gui.tabs:
            lines.append(f"   Tabs            : {', '.join(gui.tabs)}")
        if gui.status:
            lines.append(f"   Status bar      : {gui.status}")
        if not gui.responding:
            lines.append("   (window is busy, probably mid-scan)")
        blocks.append("\n".join(lines))

    targets = [gui.target for gui in instances if gui.target]
    hint = ""
    if targets:
        hint = (
            f"To answer questions about what is on screen, query {targets[0]} with the other "
            "tools. If the user scanned it elevated in the GUI, exporting from WizTree "
            "(File > Export) and calling wiztree_import_csv avoids rescanning it here."
        )
    return join("\n\n".join(blocks), hint)


@server.tool(
    name="wiztree_open_gui",
    description=(
        "Open the WizTree window so the user can look at a drive or folder interactively - the "
        "treemap, the drill-down, the sortable list. Returns immediately; the window stays open "
        "until the user closes it. Use it to hand a finding over to the user visually."
    ),
)
def wiztree_open_gui(
    path: Annotated[
        str | None,
        Field(
            default=None,
            validation_alias=PATH_ALIASES,
            description='Drive or folder to open, e.g. "D:". Omit to open WizTree with nothing loaded.',
        ),
    ] = None,
) -> str:
    target = norm_path(path) if path else None
    if target and not Path(target).exists():
        raise ValueError(f"Path not found: {target}")
    pid = launch_gui(target)
    where = target or "no target"
    return (
        f"Opened WizTree on {where} (pid {pid}). The window belongs to the user now - it stays "
        "open and this server keeps working alongside it."
    )


@server.tool(
    name="wiztree_import_csv",
    description=(
        "Register a CSV that WizTree exported (File > Export in the GUI) as a snapshot, so it can "
        "be queried here without rescanning. This is the fast bridge when the user already "
        "scanned a whole drive in the GUI, especially elevated: the scan is inherited instead of "
        "repeated. The file is never modified or deleted."
    ),
)
def wiztree_import_csv(
    csv_path: Annotated[
        str,
        Field(
            validation_alias=AliasChoices("csv_path", "path", "file", "csv"),
            description="Path to a CSV previously exported by WizTree.",
        ),
    ],
    root: Annotated[
        str | None,
        Field(default=None, description="Scan root, if it cannot be derived from the file itself."),
    ] = None,
) -> str:
    source = Path(csv_path).resolve()
    if not source.is_file():
        raise ValueError(f"CSV not found: {source}")

    totals = {"size": 0, "allocated": 0, "files": 0, "folders": 0}
    first: list[Row] = []
    files = 0
    summed = 0

    def visit(row: Row) -> None:
        nonlocal files, summed
        if not first:
            first.append(row)
        if not row.is_folder:
            files += 1
            summed += row.size

    meta = read_wiztree_csv(str(source), visit)
    if not meta.rows or not first:
        raise ValueError(
            f"{source} does not look like a WizTree export (no data rows found). "
            "Export it from WizTree with File > Export, not from another tool."
        )

    head = first[0]
    if root:
        derived = norm_path(root)
    elif head.is_folder:
        derived = norm_path(head.path)
    else:
        derived = norm_path(str(Path(head.path).parent))

    if head.is_folder and norm_path(head.path).lower() == derived.lower():
        # A folder export starts with the root row, which carries the real totals.
        totals.update(
            size=head.size, allocated=head.allocated, files=head.files, folders=head.folders
        )
    else:
        totals.update(size=summed, allocated=summed, files=files, folders=0)

    scan_id = hashlib.sha1(f"import{source}{time.time()}".encode()).hexdigest()[:12]
    drive = meta.drive or DriveInfo()
    record = ScanRecord(
        id=scan_id,
        root=derived,
        csv_path=str(source),
        created_at=time.time(),
        duration=0.0,
        csv_bytes=source.stat().st_size,
        rows=meta.rows,
        admin=False,
        signature=_signature(None, None),
        total_size=totals["size"],
        total_allocated=totals["allocated"],
        total_files=totals["files"],
        total_folders=totals["folders"],
        drive_capacity=drive.capacity,
        drive_free=drive.free,
        drive_used=drive.used,
        owned=False,
    )
    records = _load_registry()
    records.append(record)
    _save_registry(records)
    _prune()

    return join(
        f"Imported {source} as snapshot {scan_id}.",
        "\n".join(
            [
                f"Root        : {derived}",
                f"Rows        : {meta.rows:,}",
                f"Total size  : {human_bytes(totals['size'])}",
                f"Contents    : {totals['files']:,} files in {totals['folders']:,} folders",
            ]
        ),
        f"Query it like any other snapshot, e.g. wiztree_top_files with path={derived}. "
        "The CSV stays where it is; clearing the cache only stops tracking it.",
    )


@server.tool(
    name="wiztree_list_scans",
    description="Show the cached WizTree snapshots: root, age, size on disk and totals.",
)
def wiztree_list_scans() -> str:
    scans = list_scans()
    if not scans:
        return "No cached snapshots. Run wiztree_scan first."
    rows = [
        [
            record.id,
            record.root,
            f"{int((time.time() - record.created_at) / 60)} min",
            human_bytes(record.total_size),
            f"{record.total_files:,}",
            f"{record.rows:,}",
            human_bytes(record.csv_bytes),
            "yes" if (record.filter or record.filter_exclude) else "no",
        ]
        for record in scans
    ]
    return markdown_table(
        ["ID", "Root", "Age", "Total size", "Files", "CSV rows", "CSV size", "Filtered"],
        rows,
        (3, 4, 5, 6),
    )


@server.tool(
    name="wiztree_clear_cache",
    description=(
        "Delete cached snapshots and their CSV files. Pass an id to remove a single snapshot, "
        "otherwise all are removed."
    ),
)
def wiztree_clear_cache(
    id: Annotated[
        str | None,
        Field(default=None, description="Snapshot id from wiztree_list_scans. Omit to clear everything."),
    ] = None,
) -> str:
    if id and not any(record.id == id for record in list_scans()):
        raise ValueError(f"Unknown snapshot id: {id}")
    removed = clear_scans(id)
    plural = "" if removed == 1 else "s"
    return f"Removed {removed} cached snapshot{plural} from {cache_dir()}."


def main() -> None:
    if sys.platform != "win32":
        print("wiztree-mcp only runs on Windows: WizTree is a Windows application.", file=sys.stderr)
        raise SystemExit(1)
    print(f"wiztree-mcp {VERSION} ready (cache: {cache_dir()})", file=sys.stderr)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
