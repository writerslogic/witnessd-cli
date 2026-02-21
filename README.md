# witnessd-cli

Command-line interface for [witnessd](https://github.com/writerslogic/witnessd) — cryptographic authorship witnessing for writers and creators.

[![Build Status](https://github.com/writerslogic/witnessd-cli/workflows/CI/badge.svg)](https://github.com/writerslogic/witnessd-cli/actions)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)

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

Licensed under the [GNU General Public License v3.0](LICENSE).

For commercial licensing inquiries (embedding witnessd in proprietary software), contact: licensing@writerslogic.com

## Related

- [witnessd](https://github.com/writerslogic/witnessd) — Core cryptographic library
- [witnessd-docs](https://github.com/writerslogic/witnessd-docs) — Documentation, schemas, and specifications
