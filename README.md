# MicroTech Device Link Contract

This repository is the canonical source for the `device-link/v1` BLE contract.
`protocol.yaml` is normative. `vectors/golden.json` contains byte-level examples
and bounded operation-lifecycle scenarios; both files contribute to the
normalized contract digest.

The profile is a clean break from previous Device Link profiles. It defines the
BLE transport and the Wi-Fi information exchanged over that transport. It does
not define Wi-Fi retry, automatic connection, persistence implementation, scan
selection, or rollback policy.

## GATT and discovery

The profile uses one service and two authenticated encrypted characteristics:

| Characteristic | Property | Maximum ATT value |
| --- | --- | ---: |
| `command_rx` | Write Request | 495 bytes |
| `server_tx` | Indicate | 495 bytes |

Clients discover the service by its complete 128-bit UUID in advertising data
(AD type `0x07`). The local name is informational. The contract fixes each UUID
in canonical text form and in complete little-endian ATT octet order. A client
enables `server_tx` indications by writing `02 00` to its encrypted and
authenticated CCCD before sending a command.

GATT rejections use fixed ATT errors: insufficient authentication `0x05`,
insufficient encryption `0x0f`, invalid attribute value length `0x0d`, invalid
header value `0x13`, indications not enabled `0xfd`, and an unconfirmed prior
`server_tx` indication `0xfe`.

## Security

Pairing uses LE Secure Connections Numeric Comparison with MITM protection and
a 16-byte encryption key. The device exposes DisplayYesNo capability and accepts
an unbonded peer only while a locally opened physical-confirmation window is
active. This is the authenticated Numeric Comparison association model defined
by the [Bluetooth Core Security Manager specification][bluetooth-sm].

The device retains one persistent bond. That peer may reconnect outside the
pairing window. A replacement is held as a temporary candidate and requires new
physical confirmation. The old bond is deleted only after Numeric Comparison
has completed, a 16-byte key is available, and the candidate bond is durably
stored. Before that commit point, pairing failure, storage failure, or power
loss leaves the old bond in place. The temporary candidate does not count
against the one-bond limit. OOB bootstrap and application encryption are not
part of this profile.

## MTU and capacity

The preferred and required ATT MTU is 498. A Write or Indication PDU uses three
bytes before the attribute value, leaving `498 - 3 = 495` bytes for one Device
Link message. Device Link does not add application fragmentation.

The 498-byte ATT PDU is also the L2CAP SDU. The four-byte Basic L2CAP header
makes a 502-byte L2CAP PDU, which occupies two 251-byte Link Layer payloads when
DLE has negotiated that payload size.

MTU 498 is a v1 capability baseline that reserves one complete 495-byte ATT
Value, and therefore one 495-byte application message, for future commands and
events. It is intentionally not
derived from the largest message currently defined. Existing fixed-binary
messages still require a new opcode or protocol version when their layouts
change.

`GET_INFO` is the only command admitted below MTU 498. Every other known
command returns an empty `MTU_TOO_SMALL` response, so recovery first negotiates
MTU 498 before `GET_OPERATION`, `GET_STATUS`, or `ACK_OPERATION`. An ATT Value
that exceeds 495 bytes is rejected by ATT length validation before application
MTU routing. The 495/496-byte vectors validate the ATT Value boundary; they are
not application messages.

For an otherwise valid request, unknown or reserved opcodes are resolved before
the full-MTU check. Known commands then apply the MTU check, payload validation,
operation-slot admission, and observable command preconditions in that order.

## Messages

All integers are little endian. Messages use these headers:

```text
request   [opcode:u8, request_id:u8, payload...]
response  [opcode|0x80:u8, request_id:u8, status:u8, payload...]
unknown   [0x80:u8, request_id:u8, UNSUPPORTED:u8, offending_opcode:u8]
event     [0xf0:u8, event_id:u8, payload...]
```

Request IDs 1..255 are scoped to one BLE connection and correlate a command
with its immediate response. Opcodes `0x00` and `0x70` are reserved. An unknown
or reserved opcode with a valid header uses the fixed four-byte `unknown`
response; this avoids the `0x70 | 0x80 == 0xf0` event-marker collision. An
opcode with bit 7 set, request ID zero, or a truncated header is rejected with
ATT `0x13` instead. Ordinary non-success command responses have no payload.

| Opcode | Command | Successful result |
| ---: | --- | --- |
| 1 | `GET_INFO` | Link, firmware, pairing-window, and required-MTU fields |
| 2 | `GET_STATUS` | Current Wi-Fi snapshot |
| 3 | `SCAN` | `operation_id`, followed by `SCAN_COMPLETE` |
| 4 | `SET_CREDENTIALS` | `operation_id`, followed by `OPERATION_COMPLETE` |
| 5 | `CONNECT` | `operation_id`, followed by `OPERATION_COMPLETE` |
| 6 | `DISCONNECT` | `operation_id`, followed by `OPERATION_COMPLETE` |
| 7 | `FORGET` | `operation_id`, followed by `OPERATION_COMPLETE` |
| 8 | `GET_OPERATION` | The current active or retained terminal record |
| 9 | `ACK_OPERATION` | Clears the matching retained terminal record |

The events are:

- `WIFI_STATUS [state, failure, profile_ssid]`
- `SCAN_COMPLETE [operation_id, failure, count, networks...]`
- `OPERATION_COMPLETE [operation_id, operation, failure]`

SSID and profile fields are strict UTF-8 without Unicode control characters.
OPEN credentials require an empty password. PERSONAL passwords contain 8..63
printable ASCII bytes. Scan results carry at most five records; their selection
and ordering are not part of this contract. `profile_ssid` identifies the saved
profile, so it can temporarily differ from the SSID of an existing link after
`SET_CREDENTIALS` succeeds while connected.

The minimum observable success meanings are fixed: `SET_CREDENTIALS` leaves a
profile available without initiating a connection and does not change an
existing link; `CONNECT` reaches IPv4; `DISCONNECT` is disconnected when it
completes and retains the profile; and `FORGET` is disconnected with no
profile. `CONNECT` and `FORGET` return immediate `NOT_FOUND` without creating
an operation when no profile exists. `DISCONNECT` while already disconnected
is accepted and completes successfully. An occupied operation slot therefore
returns `BUSY` before a missing-profile precondition is evaluated. Internal
persistence, retry, rollback, and later automatic connection behavior remain
outside the BLE contract.

## Transactions and recovery

Only one `server_tx` indication may await confirmation. A command remains
pending until its response indication is confirmed, and a new Write is rejected
with ATT `0xfe` while any response or event indication remains unconfirmed.

Accepted asynchronous commands return a nonzero little-endian `operation_id`
(`u32`). Operation IDs are unique within one boot and are independent of the
connection-scoped request ID. The device has one operation slot. An active or
unacknowledged terminal record makes another asynchronous command return
`BUSY`; status and operation queries remain available.

Operation IDs never wrap or repeat within a boot. After the allocator is
exhausted, new asynchronous commands return an empty `INTERNAL` response until
reboot. While that boot continues, every accepted operation eventually reaches
`SUCCEEDED` or `FAILED`; the contract does not set an internal retry algorithm
or timeout duration.

`GET_OPERATION` returns the slot's operation, phase, failure and retained scan
results. With no record it returns `NOT_FOUND`. `ACK_OPERATION` applies only to
the matching terminal record; an active record or a terminal event that has not
yet been confirmed on the current connection is not acknowledged, and a
missing or mismatched ID returns `NOT_FOUND`.

A BLE disconnect neither cancels the operation nor clears its record. The
terminal event is not replayed automatically. After reconnecting, the bonded
client first negotiates MTU 498, reads the exact operation result through
`GET_OPERATION`, reads the current Wi-Fi snapshot through `GET_STATUS`, and then
acknowledges the terminal record. A reboot clears the RAM record, after which
`GET_OPERATION` returns `NOT_FOUND` and only the current `GET_STATUS` snapshot
remains available.

An accepted response must be confirmed before its terminal event. If the
operation changes the Wi-Fi snapshot, the final `WIFI_STATUS` indication is
confirmed before the terminal event. While a terminal indication is
outstanding, a new ACK Write is rejected by ATT `0xfe`. On the current
connection, `ACK_OPERATION` is accepted only after the terminal indication is
confirmed; after a disconnect, the queried retained record may be acknowledged
without replay. A successful ACK does not remove the record until the ACK
response indication itself is confirmed, so a disconnect before that
confirmation leaves the record recoverable.

## Verification status

The schema, vectors, and checker are internally consistent. The profile remains
a freeze candidate. Numeric Comparison, bond replacement and reconnect, ATT MTU
498, DLE, 495/496-byte boundaries, disconnect recovery, and on-air
interoperability have not yet been validated on firmware and a mobile client.

[bluetooth-sm]: https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core_v6.3/out/en/host/security-manager-specification.html
