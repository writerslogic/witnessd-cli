# witnessd-cli

Command-line interface for [witnessd](https://github.com/writerslogic/witnessd) — cryptographic authorship witnessing for writers and creators.

[![Build Status](https://github.com/writerslogic/witnessd-cli/workflows/CI/badge.svg)](https://github.com/writerslogic/witnessd-cli/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

## Installation

### Package Managers

| Platform | Command |
|:---------|:--------|
| **macOS** | `brew install writerslogic/tap/witnessd` |
| **Linux** | `brew install writerslogic/tap/witnessd` |
| **Windows** | `scoop bucket add witnessd https://github.com/writerslogic/scoop-bucket && scoop install witnessd` |

### Quick Install Script

```bash
curl -sSf https://raw.githubusercontent.com/writerslogic/witnessd-cli/main/install.sh | sh
```

### Build from Source

```bash
git clone https://github.com/writerslogic/witnessd-cli && cd witnessd-cli
cargo build --release
sudo cp target/release/witnessd-cli /usr/local/bin/witnessd
```

## Usage

```bash
witnessd init                              # Initialize witnessd
witnessd calibrate                         # Calibrate VDF for your machine
witnessd commit document.md -m "Draft"     # Create checkpoint
witnessd log document.md                   # View history
witnessd export document.md -t enhanced    # Export as JSON
witnessd export document.md -f war -o proof.war  # Export as WAR block
witnessd verify evidence.json              # Verify JSON packet
witnessd verify proof.war                  # Verify WAR block
```

## Linux Packaging

Linux packaging configs (Debian, RPM, AppImage, systemd) are in the `packaging/linux/` directory.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

## Related

- [witnessd](https://github.com/writerslogic/witnessd) — Core cryptographic library
- [witnessd-docs](https://github.com/writerslogic/witnessd-docs) — Documentation, schemas, and specifications
