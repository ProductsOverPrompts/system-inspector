#!/usr/bin/env python3
"""
System Inspector
Products Over Prompts - v1.0.0

Standard-library only. No shell commands or external programs.
Collects useful system, CPU, memory, storage, network, path, runtime,
and local port information, then displays or exports reports.
"""

from __future__ import annotations

import ctypes
import datetime as dt
import json
import os
import platform
import shutil
import socket
import struct
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

APP_NAME = "System Inspector"
APP_VERSION = "1.0.0"


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def human_bytes(value: int | None) -> str:
    if value is None:
        return "Unavailable"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(size) < 1024.0 or unit == "PB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024.0
    return str(value)


def program_directory() -> Path:
    # When bundled by PyInstaller, __file__ points inside the temporary
    # extraction directory. sys.executable points to the real EXE.
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    try:
        return Path(__file__).resolve().parent
    except NameError:
        return Path.cwd().resolve()


def clean(value: Any) -> str:
    text = "" if value is None else str(value).strip()
    return text or "Unavailable"


def get_wow64_status() -> str:
    if os.name != "nt":
        return "Not applicable"
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        is_wow64 = ctypes.c_bool(False)
        ok = kernel32.IsWow64Process(kernel32.GetCurrentProcess(), ctypes.byref(is_wow64))
        if ok:
            return "Yes" if is_wow64.value else "No"
    except Exception:
        pass
    return "Unavailable"


def get_system_info() -> dict[str, Any]:
    bits = struct.calcsize("P") * 8
    return {
        "operating_system": clean(platform.system()),
        "release": clean(platform.release()),
        "version": clean(platform.version()),
        "platform": clean(platform.platform()),
        "machine": clean(platform.machine()),
        "architecture_summary": f"{platform.machine() or 'Unknown'} / {bits}-bit Python",
        "pointer_width_bits": bits,
        "byte_order": sys.byteorder,
        "wow64_process": get_wow64_status(),
    }


def get_cpu_info() -> dict[str, Any]:
    data: dict[str, Any] = {
        "logical_cpu_count": os.cpu_count(),
        "processor": clean(platform.processor()),
        "machine": clean(platform.machine()),
    }
    if os.name == "nt":
        data.update({
            "processor_identifier": os.environ.get("PROCESSOR_IDENTIFIER", "Unavailable"),
            "processor_architecture": os.environ.get("PROCESSOR_ARCHITECTURE", "Unavailable"),
            "processor_level": os.environ.get("PROCESSOR_LEVEL", "Unavailable"),
            "processor_revision": os.environ.get("PROCESSOR_REVISION", "Unavailable"),
        })
    elif sys.platform.startswith("linux"):
        try:
            text = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
            vendor = model = "Unavailable"
            mhz = []
            for line in text.splitlines():
                if ":" not in line:
                    continue
                key, value = [x.strip() for x in line.split(":", 1)]
                if key == "vendor_id" and vendor == "Unavailable":
                    vendor = value
                elif key == "model name" and model == "Unavailable":
                    model = value
                elif key == "cpu MHz":
                    try:
                        mhz.append(float(value))
                    except ValueError:
                        pass
            data["vendor_id"] = vendor
            data["model_name"] = model
            if mhz:
                data["reported_mhz_average"] = round(sum(mhz) / len(mhz), 2)
        except OSError:
            pass
    return data


def get_memory_info() -> dict[str, Any]:
    data: dict[str, Any] = {}
    try:
        if os.name == "nt":
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            status = MEMORYSTATUSEX()
            status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            if kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                data = {
                    "memory_load_percent": int(status.dwMemoryLoad),
                    "total_physical_bytes": int(status.ullTotalPhys),
                    "available_physical_bytes": int(status.ullAvailPhys),
                    "used_physical_bytes": int(status.ullTotalPhys - status.ullAvailPhys),
                }
        else:
            page_size = os.sysconf("SC_PAGE_SIZE")
            total = page_size * os.sysconf("SC_PHYS_PAGES")
            available = page_size * os.sysconf("SC_AVPHYS_PAGES")
            data = {
                "total_physical_bytes": int(total),
                "available_physical_bytes": int(available),
                "used_physical_bytes": int(max(0, total - available)),
                "memory_load_percent": round((1 - available / total) * 100, 1) if total else 0,
            }
    except Exception:
        data = {"status": "Memory information unavailable"}

    for key in list(data):
        if key.endswith("_bytes") and isinstance(data[key], int):
            data[key.replace("_bytes", "_human")] = human_bytes(data[key])
    return data


def get_storage_info() -> dict[str, Any]:
    targets = [Path.home()]
    targets.append(Path(Path.home().anchor or ("C:\\" if os.name == "nt" else "/")))
    seen = set()
    volumes = []
    for target in targets:
        name = str(target)
        if name in seen:
            continue
        seen.add(name)
        try:
            usage = shutil.disk_usage(target)
            volumes.append({
                "path": name,
                "total": human_bytes(usage.total),
                "used": human_bytes(usage.used),
                "free": human_bytes(usage.free),
            })
        except OSError:
            volumes.append({"path": name, "status": "Unavailable"})
    return {"checked_locations": volumes}


def get_linux_macs() -> list[dict[str, str]]:
    out = []
    base = Path("/sys/class/net")
    if not base.exists():
        return out
    for item in sorted(base.iterdir(), key=lambda p: p.name.lower()):
        try:
            mac = (item / "address").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if mac and mac != "00:00:00:00:00:00":
            out.append({"interface": item.name, "mac_address": mac.upper()})
    return out


def get_network_info() -> dict[str, Any]:
    hostname = clean(socket.gethostname())
    fqdn = clean(socket.getfqdn())
    addresses = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            if family in (socket.AF_INET, socket.AF_INET6):
                addresses.add(sockaddr[0].split("%", 1)[0])
    except socket.gaierror:
        pass

    macs = get_linux_macs() if sys.platform.startswith("linux") else []
    return {
        "hostname": hostname,
        "fqdn": fqdn,
        "resolved_ip_addresses": sorted(addresses),
        "adapter_mac_addresses": macs,
        "note": "Per-adapter MAC enumeration is included on Linux in this public stdlib build.",
    }


TCP_STATES_LINUX = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


def parse_proc_net(path: Path, protocol: str) -> list[dict[str, Any]]:
    rows = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]
    except OSError:
        return rows
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            _, port_hex = parts[1].rsplit(":", 1)
            port = int(port_hex, 16)
        except (ValueError, IndexError):
            continue
        state = TCP_STATES_LINUX.get(parts[3].upper(), parts[3]) if protocol == "TCP" else "BOUND"
        rows.append({"protocol": protocol, "local_port": port, "state": state})
    return rows


def get_local_ports() -> dict[str, Any]:
    if sys.platform.startswith("linux"):
        rows = []
        rows += parse_proc_net(Path("/proc/net/tcp"), "TCP")
        rows += parse_proc_net(Path("/proc/net/tcp6"), "TCP")
        rows += parse_proc_net(Path("/proc/net/udp"), "UDP")
        rows += parse_proc_net(Path("/proc/net/udp6"), "UDP")
        rows.sort(key=lambda x: (x["protocol"], x["local_port"]))
        return {"collection_method": "Linux /proc/net", "entry_count": len(rows), "entries": rows}
    if os.name == "nt":
        return {
            "collection_method": "Windows",
            "entry_count": 0,
            "entries": [],
            "note": "Port enumeration can be expanded with the Windows IP Helper API in a later build.",
        }
    return {
        "collection_method": "Unavailable on this platform in this stdlib-only build",
        "entry_count": 0,
        "entries": [],
    }


def get_paths_info() -> dict[str, str]:
    return {
        "working_directory": str(Path.cwd().resolve()),
        "home_directory": str(Path.home().resolve()),
        "program_directory": str(program_directory()),
        "default_output_directory": str(program_directory()),
        "temporary_directory": tempfile.gettempdir(),
    }


def get_runtime_info() -> dict[str, Any]:
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "python_maxsize": sys.maxsize,
        "python_is_64_bit": struct.calcsize("P") * 8 == 64,
    }


def build_report() -> dict[str, Any]:
    return {
        "report": {"application": APP_NAME, "version": APP_VERSION, "generated_at": now_iso()},
        "system": get_system_info(),
        "cpu": get_cpu_info(),
        "memory": get_memory_info(),
        "storage": get_storage_info(),
        "network": get_network_info(),
        "local_ports": get_local_ports(),
        "paths": get_paths_info(),
        "runtime": get_runtime_info(),
    }


def format_value(value: Any, indent: int = 0) -> list[str]:
    pad = " " * indent
    lines = []
    if isinstance(value, dict):
        for key, child in value.items():
            label = key.replace("_", " ").title()
            if isinstance(child, (dict, list)):
                lines.append(f"{pad}{label}:")
                lines.extend(format_value(child, indent + 2))
            else:
                lines.append(f"{pad}{label}: {child}")
    elif isinstance(value, list):
        if not value:
            lines.append(f"{pad}(none)")
        for i, child in enumerate(value, 1):
            if isinstance(child, (dict, list)):
                lines.append(f"{pad}[{i}]")
                lines.extend(format_value(child, indent + 2))
            else:
                lines.append(f"{pad}- {child}")
    else:
        lines.append(f"{pad}{value}")
    return lines


def render_text(report: dict[str, Any]) -> str:
    sections = [
        ("REPORT", "report"), ("SYSTEM", "system"), ("CPU", "cpu"),
        ("MEMORY", "memory"), ("STORAGE", "storage"), ("NETWORK", "network"),
        ("LOCAL TCP / UDP PORTS", "local_ports"), ("PATHS", "paths"),
        ("PYTHON RUNTIME", "runtime"),
    ]
    lines = ["=" * 72, APP_NAME.upper(), "=" * 72]
    for title, key in sections:
        lines += ["", f"[{title}]", "-" * 72]
        lines += format_value(report.get(key, {}))
    lines += ["", "=" * 72]
    return "\n".join(lines)


def report_stem() -> str:
    return f"system_inspector_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}"


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def save_report(report: dict[str, Any], save_txt: bool, save_json: bool) -> list[Path]:
    """Save selected report formats automatically next to the program."""
    folder = program_directory()
    folder.mkdir(parents=True, exist_ok=True)

    stem = report_stem()
    saved_paths: list[Path] = []

    if save_txt:
        txt_path = folder / f"{stem}.txt"
        txt_path.write_text(render_text(report), encoding="utf-8")
        saved_paths.append(txt_path)

    if save_json:
        json_path = folder / f"{stem}.json"
        json_path.write_text(render_json(report), encoding="utf-8")
        saved_paths.append(json_path)

    return saved_paths


def save_zip_report(report: dict[str, Any]) -> Path:
    """Save TXT + JSON together inside a ZIP next to the program."""
    folder = program_directory()
    folder.mkdir(parents=True, exist_ok=True)

    stem = report_stem()
    zip_path = folder / f"{stem}.zip"

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{stem}.txt", render_text(report))
        archive.writestr(f"{stem}.json", render_json(report))

    return zip_path


def clear_screen() -> None:
    """Clear the active console without shell commands or external programs."""
    if os.name == "nt":
        try:
            class COORD(ctypes.Structure):
                _fields_ = [
                    ("X", ctypes.c_short),
                    ("Y", ctypes.c_short),
                ]

            class SMALL_RECT(ctypes.Structure):
                _fields_ = [
                    ("Left", ctypes.c_short),
                    ("Top", ctypes.c_short),
                    ("Right", ctypes.c_short),
                    ("Bottom", ctypes.c_short),
                ]

            class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
                _fields_ = [
                    ("dwSize", COORD),
                    ("dwCursorPosition", COORD),
                    ("wAttributes", ctypes.c_ushort),
                    ("srWindow", SMALL_RECT),
                    ("dwMaximumWindowSize", COORD),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            kernel32.GetStdHandle.argtypes = [ctypes.c_ulong]
            kernel32.GetStdHandle.restype = ctypes.c_void_p
            kernel32.GetConsoleScreenBufferInfo.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(CONSOLE_SCREEN_BUFFER_INFO),
            ]
            kernel32.GetConsoleScreenBufferInfo.restype = ctypes.c_int
            kernel32.FillConsoleOutputCharacterW.argtypes = [
                ctypes.c_void_p,
                ctypes.c_wchar,
                ctypes.c_ulong,
                COORD,
                ctypes.POINTER(ctypes.c_ulong),
            ]
            kernel32.FillConsoleOutputCharacterW.restype = ctypes.c_int
            kernel32.FillConsoleOutputAttribute.argtypes = [
                ctypes.c_void_p,
                ctypes.c_ushort,
                ctypes.c_ulong,
                COORD,
                ctypes.POINTER(ctypes.c_ulong),
            ]
            kernel32.FillConsoleOutputAttribute.restype = ctypes.c_int
            kernel32.SetConsoleCursorPosition.argtypes = [
                ctypes.c_void_p,
                COORD,
            ]
            kernel32.SetConsoleCursorPosition.restype = ctypes.c_int

            STD_OUTPUT_HANDLE = ctypes.c_ulong(-11).value
            INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

            handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
            if not handle or handle == INVALID_HANDLE_VALUE:
                raise OSError("No active Windows console handle")

            info = CONSOLE_SCREEN_BUFFER_INFO()
            if not kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(info)):
                raise OSError("Could not read console buffer information")

            cell_count = int(info.dwSize.X) * int(info.dwSize.Y)
            origin = COORD(0, 0)
            written = ctypes.c_ulong(0)

            kernel32.FillConsoleOutputCharacterW(
                handle, " ", cell_count, origin, ctypes.byref(written)
            )
            kernel32.FillConsoleOutputAttribute(
                handle, info.wAttributes, cell_count, origin, ctypes.byref(written)
            )
            kernel32.SetConsoleCursorPosition(handle, origin)
            return
        except Exception:
            pass

    # ANSI fallback for Linux, macOS, Windows Terminal, and compatible consoles.
    try:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
    except Exception:
        pass


def pause() -> None:
    try:
        input("\nPress Enter to continue...")
    except (EOFError, KeyboardInterrupt):
        pass


def print_menu() -> None:
    print("\n" + "=" * 72)
    print(f"{APP_NAME} v{APP_VERSION}")
    print("=" * 72)
    print("\n[1] View Reports")
    print("\n[2] Save Reports\n")
    print("[3] Exit\n")
    print()


def display_report_menu() -> None:
    clear_screen()
    print("View Reports")
    print()
    print("[1] TXT")
    print()
    print("[2] JSON")
    print()
    print("[3] Back")
    print()

    try:
        choice = input("Select an option: ").strip()
    except (EOFError, KeyboardInterrupt):
        return

    if choice == "3":
        return

    if choice not in {"1", "2"}:
        print("\nInvalid choice.")
        pause()
        return

    clear_screen()
    print("Collecting system information...")
    report = build_report()

    if choice == "1":
        print("\n" + render_text(report))
    else:
        print("\n" + render_json(report))

    pause()


def save_report_menu() -> None:
    clear_screen()
    print("Save Reports")
    print()
    print("[1] TXT")
    print()
    print("[2] JSON")
    print()
    print("[3] TXT + JSON")
    print()
    print("[4] ZIP")
    print()
    print("[5] Back")
    print()

    try:
        choice = input("Select an option: ").strip()
    except (EOFError, KeyboardInterrupt):
        return

    if choice == "5":
        return

    if choice not in {"1", "2", "3", "4"}:
        print("\nInvalid choice.")
        pause()
        return

    clear_screen()
    print("Collecting system information...")
    report = build_report()

    try:
        if choice == "4":
            saved_path = save_zip_report(report)
            print(f"\nSaved ZIP report:\n{saved_path}")
        else:
            saved_paths = save_report(
                report,
                save_txt=choice in {"1", "3"},
                save_json=choice in {"2", "3"},
            )

            if len(saved_paths) == 1:
                print(f"\nSaved report:\n{saved_paths[0]}")
            else:
                print("\nSaved reports:")
                for path in saved_paths:
                    print(path)
    except (OSError, zipfile.BadZipFile) as exc:
        print(f"\nCould not save report: {exc}")

    pause()


def main() -> int:
    while True:
        clear_screen()
        print_menu()

        try:
            choice = input("Choose an option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            return 0

        if choice == "1":
            display_report_menu()
        elif choice == "2":
            save_report_menu()
        elif choice == "3":
            print("Exiting.")
            return 0
        else:
            print("\nInvalid choice.")
            pause()


if __name__ == "__main__":
    raise SystemExit(main())
