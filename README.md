# ghostwire

> **Passive USB device fingerprinting and anomaly detection daemon for Linux.**
> You'll know what plugged in before your OS does.

---

## Threat Context

USB-based attacks are physical-layer threats that most endpoint security completely ignores. BadUSB firmware implants, HID injection devices, malicious charging cables — they all look like legitimate hardware to the kernel. By the time your EDR sees suspicious process activity, the payload has already run.

Ghostwire sits below that. It watches the hardware enumeration layer.

---

## What It Does

Ghostwire is a passive daemon written in Rust that listens to kernel uevents on the netlink socket, fingerprints USB devices at enumeration time, maintains a trust store of known devices, and scores every connection for anomalies. No kernel module required. No modification to your USB stack.

- **Passive fingerprinting** — SHA-256 fingerprint over vendor/product IDs, manufacturer and product strings, device class, and interface count. Serial numbers are deliberately excluded from the fingerprint because they're trivially spoofable.
- **Automatic baselining** — every device is profiled on first sight and tracked across reconnects (first/last seen, seen count, port history). Devices can be explicitly marked trusted via the CLI.
- **Anomaly scoring** — each event is scored against seven weighted detection flags (see below); severity escalates with the cumulative score.
- **Tamper-evident event log** — every event is appended to a SQLite log with a SHA-256 hash chain covering the full event record; `ghostwire verify` walks the chain and reports broken links.
- **Structured output** — human/journald logs via `tracing`, plus a newline-delimited JSON event log for SIEM ingestion, plus optional desktop notifications.

> **Privileges:** binding the netlink uevent socket requires **root or `CAP_NET_ADMIN`** — ghostwire is not an unprivileged service. The bundled systemd unit confines it with `CapabilityBoundingSet=CAP_NET_ADMIN`, `ProtectSystem=strict`, and related hardening.

---

## Detection Flags

| Flag | Score | Trigger |
|------|------:|---------|
| `UNKNOWN_DEVICE` | +30 | Fingerprint never seen and no VID/PID history at all |
| `DESCRIPTOR_MISMATCH` | +50 | VID/PID known, but descriptor fingerprint is new — possible BadUSB reflash |
| `NEW_PORT` | +10 | Known device appeared on a different physical port |
| `COMPOSITE_HID_STORAGE` | +60 | Device exposes both HID and mass-storage interfaces |
| `NEW_INTERFACE_COUNT` | +40 | Interface count differs from the stored profile |
| `ODD_HOURS` | +10 | Event occurred between 01:00 and 04:59 local time |
| `SERIAL_MISSING` | +15 | HID or storage device with no serial number |

Flag scores are additive. Severity thresholds: **score ≥ 50** logs at ERROR (and fires a desktop notification if enabled), **score ≥ 20** logs at WARN, everything else at INFO. Both thresholds are configurable (`alert_threshold`, `warn_threshold` — see Configuration).

## Attack Surface Coverage

| Attack Type | Example | Detection Signal |
|-------------|---------|-----------------|
| BadUSB / Firmware implant | Reprogrammed microcontroller spoofing HID | `DESCRIPTOR_MISMATCH`, `NEW_INTERFACE_COUNT` |
| HID Injection | USB Rubber Ducky, O.MG Cable | `UNKNOWN_DEVICE` + `SERIAL_MISSING` |
| Composite implant | HID payload with staging storage | `COMPOSITE_HID_STORAGE` |
| Malicious charging cable | O.MG cable, OMG Plug | `UNKNOWN_DEVICE` on a previously clean port, `NEW_PORT` |

---

## Architecture

```
                 Kernel uevents (netlink)
                          │
              ┌───────────▼───────────┐
              │  collector (OS thread) │  SUBSYSTEM=usb, DEVTYPE=usb_device
              │  + sysfs enrichment    │  add / change / bind / remove
              └───────────┬───────────┘
                          │ mpsc channel
┌─────────────────────────▼────────────────────────┐
│              ghostwire daemon (tokio)            │
│                                                  │
│  ┌──────────────┐      ┌──────────────────────┐  │
│  │  Fingerprint │      │  Trust Store (SQLite) │  │
│  │  (SHA-256)   │─────▶│  profiles + hash-     │  │
│  └──────────────┘      │  chained event log    │  │
│                        └──────────┬───────────┘  │
│  ┌────────────────────────────◄──┘               │
│  │       Anomaly Scorer (8 flags)                │
│  └──────────────────┬────────────────────────────┘
└─────────────────────┼─────────────────────────────┘
                      │
        ┌─────────────┼──────────────┐
        │             │              │
   tracing log   NDJSON event    desktop
  (stderr /      log file        notification
   journald)                     (optional)
```

---

## Quick Start

```bash
# Requirements: Rust stable, Linux
git clone https://github.com/noisyloop/ghostwire
cd ghostwire
cargo build --release

# Run the daemon in the foreground (root or CAP_NET_ADMIN required)
sudo ./target/release/ghostwire --foreground

# Plug in your known-good devices — each is fingerprinted and profiled
# automatically on first sight. Then review and trust them:
sudo ./target/release/ghostwire list
sudo ./target/release/ghostwire trust <fingerprint>
```

There is no separate enrollment mode: the first time a device connects it's flagged `UNKNOWN_DEVICE` and registered; subsequent connections are compared against its stored profile.

### CLI Reference

```
ghostwire [--db-path <path>] [--log-path <path>] [-f|--foreground] [--notify] [COMMAND]

  daemon              Run the daemon (default when no subcommand is given)
  list                List all known device profiles in the trust store
  show <fingerprint>  Show full details for one profile (prefix match supported)
  trust <fingerprint>   Mark a device as explicitly trusted
  untrust <fingerprint> Remove the trusted flag
  forget <fingerprint>  Delete a profile (historical events are preserved)
  history [-l N]      Show recent USB events with anomaly scores
  export              Dump the full event log as JSON to stdout
  verify              Verify the tamper-evident event chain (exit 1 if broken)
```

Defaults: trust store at `/var/lib/ghostwire/devices.db`, event log at `/var/log/ghostwire/events.log` (both created `0600`).

### Configuration

Persistent defaults are read from `/etc/ghostwire/config.toml`, then `~/.config/ghostwire/config.toml` (user file wins); CLI flags override both:

```toml
db_path  = "/var/lib/ghostwire/devices.db"
log_path = "/var/log/ghostwire/events.log"
notify   = true
alert_threshold = 50   # score ≥ this → ERROR + desktop notification
warn_threshold  = 20   # score ≥ this → WARN
```

Desktop notifications require building with `cargo build --release --features desktop-notify` and a running notification daemon.

---

## Alert Format

Events are appended to the event log as newline-delimited JSON, one object per line (pretty-printed here for readability):

```json
{
  "event": {
    "timestamp": "2026-03-12T04:22:11Z",
    "action": "add",
    "vid": "05ac",
    "pid": "0259",
    "manufacturer": null,
    "product": "USB Keyboard",
    "serial": null,
    "device_class": "00",
    "subclass": "00",
    "protocol": "00",
    "interface_count": 1,
    "port_path": "/devices/pci0000:00/0000:00:14.0/usb1/1-3",
    "bus_num": "1",
    "dev_num": "12",
    "interfaces": [
      { "class": "03", "subclass": "01", "protocol": "01" }
    ]
  },
  "score": 55,
  "flags": ["UNKNOWN_DEVICE", "SERIAL_MISSING", "ODD_HOURS"],
  "known_profile": null
}
```

---

## Deployment

Ghostwire runs as a `systemd` service; a sample unit file (`ghostwire.service`) is included with capability and filesystem hardening. Operational logs go to journald; the NDJSON event log at `/var/log/ghostwire/events.log` can be tailed by Wazuh, Elastic, or any file-based SIEM shipper.

---

## Limitations

Know what this tool does *not* do:

- **Perfect clones are invisible.** A device that reproduces an enrolled device's descriptors exactly (VID, PID, strings, class, interface count) produces the same fingerprint and is treated as that device. Serial numbers are excluded from the fingerprint precisely because they are spoofable, so a spoofed serial neither helps nor hurts an attacker here.
- **Detection is heuristic.** Scores are static weights, not a learned model; expect to tune your workflow around `trust` to suppress noise from legitimate new hardware. `ODD_HOURS` uses the daemon host's local clock. There is no enumeration-*timing* signal: the only timing observable from uevents (kernel `add`→`bind` latency) is sub-millisecond for every device and distinguishes nothing.
- **The hash chain covers the full event record** (timestamp, action, fingerprint, raw event JSON, score, flags, previous hash) — it makes modification, deletion, and reordering of logged events evident, but is not a substitute for shipping logs off-host. The chain format changed pre-1.0; event logs written by earlier builds will fail `verify`.
- **No webhook/network output yet** — alerting beyond the log file and desktop notifications is up to your log shipper.

---

## License

MIT

---

*Part of the [noisyloop](https://github.com/noisyloop) security tooling portfolio.*
