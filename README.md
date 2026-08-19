# MicroTech Device Link Contract

This repository is the canonical source for the deliberately small
`device-link/v1` contract. It is a clean break from all previous provisioning
and Device Link profiles; no compatibility framing is defined.

`protocol.yaml` is the only normative protocol source. `vectors/golden.json`
contains byte messages, ATT boundaries, and connection-scoped transaction
scenarios. The checker validates both and includes both in the normalized
digest.

## GATT profile

The fixed-binary profile uses one service and two encrypted characteristics:

| Characteristic | Property | Maximum ATT value |
| --- | --- | ---: |
| `command_rx` | Write Request | 495 bytes |
| `server_tx` | Indicate | 495 bytes |

Clients discover the service by its complete 128-bit UUID in advertising data
(AD type `0x07`). The local name is informational. UUID text is canonical
lowercase RFC 4122 form; the contract also fixes each complete 16-byte
little-endian ATT representation. The `server_tx` CCCD is `0x2902`; a client
writes `02 00` over the encrypted link to enable indications before writing a
command.

GATT rejections use fixed ATT errors: insufficient encryption `0x0f`, invalid
attribute value length `0x0d`, invalid header value `0x13`, indications not
enabled `0xfd`, and an unconfirmed prior `server_tx` Indication `0xfe`.

The link uses LE Secure Connections in SC-only mode without MITM, Bonding, QR,
Security 2, or application encryption. Pairing is accepted only in a
device-controlled physical-confirmation window. The window mechanism and
duration are device policy; `GET_INFO` reports whether it is currently open.

## MTU and data length

The preferred and required ATT MTU is 498. A Write or Indication PDU has three
bytes before the attribute value, leaving `498 - 3 = 495` bytes.

The 498-byte ATT PDU is the L2CAP SDU. A Basic L2CAP header adds four bytes, so
the complete L2CAP PDU is 502 bytes. If a 251-byte Link Layer payload has been
negotiated, the L2CAP PDU occupies exactly two payloads:

```text
ATT PDU / L2CAP SDU       498
Basic L2CAP header          4
L2CAP PDU                 502
Link Layer payload        251
Payload count               2
```

This is protocol and buffer-sizing arithmetic. It does not claim that DLE,
controller/HCI segmentation, peer MTU negotiation, or real hardware
interoperability has been validated. Device Link does not add application
fragmentation. The 495/496-byte vectors are opaque ATT value boundary cases,
not Device Link messages.

`GET_INFO` is the only command allowed below MTU 498. Its fixed response is 11
bytes including the response header, so it fits the default ATT MTU 23. Every
other command returns an empty `MTU_TOO_SMALL` response below MTU 498.

## Wire messages

All integers are little endian. `u8`/`u16` are unsigned; `i8` is one-byte
two's complement; `bool` is one byte and accepts only 0 or 1. `enum_u8` uses
the named registry value. `bytes_u8` is a one-byte octet count followed by
exactly that many octets. A `repeated` field concatenates items and takes its
count from the named preceding `u8` field.

```text
request   [opcode:u8, request_id:u8, payload...]
response  [opcode|0x80:u8, request_id:u8, status:u8, payload...]
event     [0xf0:u8, event_id:u8, payload...]
```

Request IDs 1..255 are scoped to one BLE connection. Request ID zero, opcode
zero, opcode `0x70`, and request opcodes with bit 7 set are invalid. Error
responses have no payload. Unknown request opcodes that can be represented
without colliding with event framing receive `UNSUPPORTED`.

| Opcode | Command | Terminal result |
| ---: | --- | --- |
| 1 | `GET_INFO` | Fixed protocol, firmware, pairing-window, and MTU fields |
| 2 | `GET_STATUS` | Current canonical Wi-Fi snapshot |
| 3 | `SCAN` | `SCAN_COMPLETE` |
| 4 | `SET_CREDENTIALS` | `OPERATION_COMPLETE`; saves only |
| 5 | `CONNECT` | `OPERATION_COMPLETE`; uses the stored profile, or immediate `NOT_FOUND` |
| 6 | `DISCONNECT` | `OPERATION_COMPLETE` |
| 7 | `FORGET` | `OPERATION_COMPLETE`; disconnects and removes the profile, or immediate `NOT_FOUND` |

The three events are:

- `WIFI_STATUS [state, failure, profile_ssid]`
- `SCAN_COMPLETE [request_id, failure, count, networks...]`
- `OPERATION_COMPLETE [request_id, operation, failure]`

`CONNECTED` means IPv4 is available. An empty `profile_ssid` means no
persistent profile. `WIFI_STATUS` has no request correlation; operation result
and state are intentionally separate. `UNAVAILABLE` permits only `RADIO` or
`INTERNAL`; ordinary active states require `NONE`; `ERROR` requires a non-zero
failure, including `STORAGE`.

`GET_INFO` and `GET_STATUS` remain available when the Wi-Fi service is
unavailable. `GET_STATUS` reports the `UNAVAILABLE` snapshot; commands that
need the service return an empty `UNAVAILABLE` response.

## Transactions

Only one `server_tx` Indication may await confirmation. A command Write remains
pending until its response is confirmed. While any response or event
Indication is unconfirmed, a new Write is rejected with GATT `Procedure Already
in Progress` (`0xfe`).

SCAN and the four mutating commands share one device-scoped active-operation
slot. While it is active, `GET_INFO` and `GET_STATUS` may use a different
request ID; another operation or reuse of the active ID returns `BUSY`.

An `ACCEPTED` response must be confirmed before its terminal event. When an
operation changes the canonical Wi-Fi snapshot, the final `WIFI_STATUS` must
also be confirmed before the terminal event. Intermediate status changes may
be coalesced to the latest snapshot. Every accepted operation has exactly one
terminal event while the BLE connection remains alive.

For a successful `SET_CREDENTIALS`, the profile is stored and the command does
not initiate a connection. Successful `CONNECT` reaches `CONNECTED` (and
therefore has IPv4); successful `DISCONNECT` is no longer connecting or
connected when it completes; successful `FORGET` is both disconnected and has
no profile. A later automatic reconnect after `DISCONNECT` is outside this
contract. On failure, rollback is not required and the final `WIFI_STATUS` is
the state of record.

If BLE disconnects, the device operation continues but its request correlation
is discarded. Completion is not retained or replayed to another connection.
A reconnected client uses `GET_STATUS`; a still-active operation continues to
make new operations return `BUSY`. Automatic connection and reconnection are
Wi-Fi manager policy and are not controlled by this BLE contract.

## Text and scan rules

SSIDs are 1..32 bytes of strict UTF-8 and may not contain Unicode control
characters. They are neither trimmed nor normalized. OPEN credentials require
an empty password. PERSONAL passwords are 8..63 printable ASCII bytes
(`0x20..0x7e`); 64-character raw PSKs are not supported.

Scan output omits empty SSIDs, invalid UTF-8, and unsupported security types.
Records are deduplicated by exact SSID octets, retaining the strongest RSSI,
then sorted by descending RSSI and ascending SSID octets. At most five records
are returned. RSSI is signed i8 in -127..0 dBm; the maximum event is 180 bytes.

## Verification

```sh
python3 -m pip install -r requirements.txt
python3 -m tooling.check
python3 -O -m tooling.check --print-digest
python3 -m unittest discover -s tests -v
python3 -O -m unittest discover -s tests -v
python3 -m compileall -q tooling tests
git diff --check
```

The repository remains a `VERSION=1.0.0` freeze candidate. A clean immutable
commit, independent review, and explicit authorization are required before a
`v1.0.0` tag or push. Passing these checks proves the contract source, vectors,
checker, and CI are self-consistent; it does not prove firmware, mobile-client,
BLE controller, DLE, or on-air interoperability.
