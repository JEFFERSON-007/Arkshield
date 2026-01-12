# Installation Guide

## Install as CLI Tool

To use `storage-manager` as a proper command-line tool (like `storage-manager scan` instead of `python storage-manager.py scan`):

### Option 1: Install in Development Mode (Recommended)

```bash
# Navigate to the sys scanner directory
cd "c:\Users\mariy\OneDrive\Documents\extra tasks i do when i am bored\system scanner\sys scanner"

# Install in editable mode
pip install -e .
```

This installs the tool so you can use it anywhere, and changes to the code are reflected immediately.

### Option 2: Regular Install

```bash
cd "c:\Users\mariy\OneDrive\Documents\extra tasks i do when i am bored\system scanner\sys scanner"
pip install .
```

## Usage After Installation

Once installed, you can use it from anywhere:

```bash
# List junk categories
storage-manager categories

# Scan a directory
storage-manager scan C:\Users\YourName\Downloads

# Clean junk (dry-run)
storage-manager clean . --categories cache,temporary --dry-run

# Clean junk (actually delete)
storage-manager clean . --categories cache,logs

# Get help
storage-manager --help
storage-manager scan --help
storage-manager clean --help
```

## Verify Installation

```bash
# Check if installed correctly
storage-manager --version

# Should show: storage-manager, version 2.0.0
```

## Uninstall

```bash
pip uninstall storage-manager
```

## Troubleshooting

### Command not found

If you get "command not found" or similar error:

1. Make sure Python Scripts directory is in your PATH
2. On Windows, it's usually: `C:\Users\YourName\AppData\Local\Programs\Python\Python3X\Scripts`
3. Restart your terminal after installation

### Import errors

If you get import errors, make sure all dependencies are installed:

```bash
pip install -r requirements.txt
```

## Quick Start Commands

```bash
# After installation, try these:
storage-manager categories
storage-manager scan .
storage-manager clean . --categories temporary --dry-run
```

That's it! You now have a professional CLI tool. 🚀
