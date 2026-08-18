# MicroTech Device Link Contract

This repository defines the small Device Link v3 wire contract shared by the
Android App and the ESP32 firmware. Version `0.1.0` is an unverified draft;
real-device interoperability and firmware-size measurements are intentionally
outside this repository's current acceptance gate.

## Design rules

- one BLE service with one write characteristic and one notify characteristic;
- LE Secure Connections with MITM/passkey inside an explicit physical pairing
  window; no application crypto and no persistent Bond in the preferred mode;
- fixed little-endian binary messages, not a generic TLV or reflection runtime;
- negotiated ATT MTU must be at least 247; application messages are single
  packets and use command-specific paging for scan results;
- one connection and one active Wi-Fi task; no job history, recovery or cancel
  protocol;
- Wi-Fi is the only application domain in this draft.

`protocol.yaml` is the only protocol source. `vectors/` contains byte-level
examples consumed by platform tests. The checker is a development tool only;
it is not linked into firmware or the App.

## Repository checks

```text
python -m pip install PyYAML
python -m tooling.check
python -m unittest discover -s tests -v
```

The contract is a clean break from the archived Device Link v2 contract. It
uses a new service UUID and protocol major `3`; v2 and v3 are not implemented
in the same runtime.
