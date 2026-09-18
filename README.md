# System Inspector v1.0.0

The first public release of **System Inspector**.

System Inspector is a lightweight Python tool for collecting useful information about a computer and organizing it into readable reports.

It uses only the Python standard library, with no third-party packages, shell commands, or external programs required to run from source.

## Features

System Inspector can collect and display information about:

- Operating system
- CPU
- Memory
- Storage
- Network configuration
- Local TCP/UDP ports
- System paths
- Python runtime

## Report Export

Reports can be saved as:

- TXT
- JSON
- ZIP report bundles

## Requirements

- Python 3
- No additional packages required to run from source

## How to Run

Run System Inspector with:

```bash
python system-inspector.py
```

On some Linux and macOS systems, you may need to use:

```bash
python3 system-inspector.py
```

## Build a Standalone Executable

System Inspector can be packaged as a standalone executable using PyInstaller.

PyInstaller is only needed to build the standalone version. It is not required to run System Inspector directly from source.

Install PyInstaller:

```bash
pip install pyinstaller
```

If your system uses `pip3`, use:

```bash
pip3 install pyinstaller
```

### Windows

Build the Windows executable with the included icon:

```bash
pyinstaller --onefile --icon=assets/system-inspector.ico system-inspector.py
```

After the build finishes:

```text
dist/system-inspector.exe
```

### macOS

Build the macOS executable:

```bash
pyinstaller --onefile system-inspector.py
```

After the build finishes:

```text
dist/system-inspector
```

If a macOS `.icns` icon is added to the project later, it can be used with:

```bash
pyinstaller --onefile --icon=assets/system-inspector.icns system-inspector.py
```

### Linux

Build the Linux executable:

```bash
pyinstaller --onefile system-inspector.py
```

After the build finishes:

```text
dist/system-inspector
```

If needed, make the file executable:

```bash
chmod +x dist/system-inspector
```

Then run it with:

```bash
./dist/system-inspector
```

## Important Build Note

PyInstaller packages applications for the operating system it is running on.

To create builds for multiple platforms, build System Inspector separately on each target operating system:

- Build the Windows `.exe` on Windows
- Build the macOS executable on macOS
- Build the Linux executable on Linux

System Inspector itself remains standard-library-only. PyInstaller is an optional third-party packaging tool used only to create standalone builds.

## Notes

System information may vary depending on the operating system and what the Python standard library can access on that platform.

Built by **Products Over Prompts**

**Build something real.**
