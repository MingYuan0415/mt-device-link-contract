[English](README.md) | **简体中文**

# MicroTech Device Link 契约

本仓库是 `device-link/v1` BLE 契约的规范来源。`protocol.yaml` 具有规范性。
`vectors/golden.json` 包含字节级示例与有界的操作生命周期场景；两者共同参与规范化
契约摘要。

本 profile 与旧 Device Link profile 是彻底断代。它定义 BLE 传输以及在该传输上交
换的 Wi-Fi 信息；不定义 Wi-Fi 重试、自动连接、持久化实现、扫描选择或回滚策略。

## GATT 与服务发现

该 profile 使用一个服务与两个已认证加密特征：

| 特征 | 属性 | 最大 ATT 值 |
| --- | --- | ---: |
| `command_rx` | Write Request | 495 字节 |
| `server_tx` | Indicate | 495 字节 |

客户端通过广播数据中的完整 128 位 UUID（AD type `0x07`）发现该服务。本地名称仅供
参考。契约同时固定每个 UUID 的规范文本形式与完整小端 ATT 字节序。客户端在发送命令
之前，向其已加密且已认证的 CCCD 写入 `02 00` 以启用 `server_tx` indication。

GATT 拒绝在应用访问回调之前使用 NimBLE SC-only 安全闸门。服务端必须拒绝既未加密
又未认证的链路，并使用 insufficient authentication `0x05`。`0x0f` 仍是标准的
insufficient encryption 值；客户端应将 `0x05` 与 `0x0f` 都视为完成安全配对或重新
加密的请求。属性值长度无效为 `0x0d`，头部值无效为 `0x13`，未启用 indication 为
profile 值 `0xfd`，前一个 `server_tx` indication 未确认则为 profile 值 `0xfe`。

## 安全

配对使用带 MITM 保护的 LE Secure Connections Numeric Comparison 与 16 字节加密密钥。
设备暴露 DisplayYesNo 能力，且仅在本地打开的物理确认窗口激活时接受未绑定 peer。这
是 [Bluetooth Core Security Manager 规范][bluetooth-sm] 定义的已认证 Numeric
Comparison 关联模型。

设备保留一个持久 bond。该 peer 可以在配对窗口之外重连。替换它需要在本地确认清除旧
bond，随后重新打开物理确认配对窗口。远程无损 bond 替换不是 v1 保证：本地清除之后，
配对或存储失败不会恢复旧 bond。OOB 引导与应用层加密不属于本 profile。

## MTU 与容量

首选且必需的 ATT MTU 为 498。一个 Write 或 Indication PDU 在属性值之前使用三个
字节，为单条 Device Link 消息留下 `498 - 3 = 495` 字节。Device Link 不增加应用层
分片。

实现可以使用 L2CAP 与 Link Layer Data Length Extension（DLE）承载 ATT PDU。它们的
头部与分片算术属于 ESP-IDF 实现细节，不是跨主机 v1 一致性条件。

MTU 498 是 v1 能力基线，为未来的命令与事件预留一条完整的 495 字节 ATT Value，也即
一条 495 字节应用消息。它刻意不从当前已定义的最大消息推导而来。既有固定二进制消息
在布局变化时仍需新的 opcode 或协议版本。

`GET_INFO` 是唯一允许在 MTU 498 以下接纳的命令。其他所有已知命令返回空的
`MTU_TOO_SMALL` 响应，因此恢复流程先协商 MTU 498，然后再执行 `GET_OPERATION`、
`GET_STATUS` 或 `ACK_OPERATION`。超过 495 字节的 ATT Value 会在应用层 MTU 路由之前
被 ATT 长度校验拒绝。495/496 字节向量校验的是 ATT Value 边界，它们不是应用消息。

对于其余方面有效的请求，未知或保留 opcode 在全 MTU 检查之前解析。已知命令随后按
该顺序执行 MTU 检查、payload 校验、操作槽接纳与可观察命令前置条件。

## 消息

所有整数均为小端。消息使用如下头部：

```text
request   [opcode:u8, request_id:u8, payload...]
response  [opcode|0x80:u8, request_id:u8, status:u8, payload...]
unknown   [0x80:u8, request_id:u8, UNSUPPORTED:u8, offending_opcode:u8]
event     [0xf0:u8, event_id:u8, payload...]
```

Request ID 1..255 以单条 BLE 连接为作用域，将命令与其即时响应关联。Opcode `0x00`
与 `0x70` 为保留值。带有合法头部的未知或保留 opcode 使用固定的四字节 `unknown`
响应；这避免了 `0x70 | 0x80 == 0xf0` 的事件标记冲突。位 7 被置位的 opcode、request
ID 为零或头部被截断则以 ATT `0x13` 拒绝。普通非成功命令响应没有 payload。

| Opcode | 命令 | 成功结果 |
| ---: | --- | --- |
| 1 | `GET_INFO` | 链路、产品兼容固件三元组、配对窗口与必需 MTU 字段 |
| 2 | `GET_STATUS` | 当前 Wi-Fi 快照 |
| 3 | `SCAN` | `operation_id` |
| 4 | `SET_CREDENTIALS` | `operation_id` |
| 5 | `CONNECT` | `operation_id` |
| 6 | `DISCONNECT` | `operation_id` |
| 7 | `FORGET` | `operation_id` |
| 8 | `GET_OPERATION` | 当前活动或保留的终态记录 |
| 9 | `ACK_OPERATION` | 清除匹配的保留终态记录 |

已接纳的异步命令返回 `operation_id`。匹配的终态事件至多发送一次；若客户端先行 ACK，
或 ACCEPTED indication 在断开时被丢弃，则不发送该事件。

命令状态码 `UNAVAILABLE` 与 `STORAGE` 保留各自数值，但不是接纳结果。`UNAVAILABLE`
是一个 `wifi_state`。`STORAGE` 是一个 `wifi_failure`，并且对 `SET_CREDENTIALS` 与
`FORGET` 是终态失败。

事件为：

- `WIFI_STATUS [state, failure, profile_ssid]`
- `SCAN_COMPLETE [operation_id, failure, count, networks...]`
- `OPERATION_COMPLETE [operation_id, operation, failure]`

SSID 与 profile 字段是严格 UTF-8，不含 Unicode 控制字符。OPEN 凭据要求空密码。
PERSONAL 密码包含 8..63 个可打印 ASCII 字节。扫描结果至多携带五条记录；空 SSID 与
隐藏 SSID、非法 UTF-8、控制字符以及超过 32 字节的 SSID 在编码前被过滤。安全类别
不是 `OPEN` 或 `PERSONAL` 的源记录被过滤。其余记录按 `(SSID, security)` 合并，保留
最强 RSSI（`>` 替换；RSSI 相等保留较早记录）。空口不带 BSSID，因此这些键是客户端
唯一可见的身份。`count` 是经过滤、合并与五条记录限制后保留的空口记录数；不同键之间
的顺序不属于本契约。RSSI 是 `i8`，闭区间 -127..127。

`GET_INFO` 的 `firmware_major/minor/patch` 是产品兼容三元组，不是 git 身份或构建
指纹。

`SET_CREDENTIALS` 只校验空口 profile。若实际 AP 安全类别与所选 profile 不符，
`CONNECT` 仍被接纳，并以 `AUTHENTICATION` 结束。

`profile_ssid` 标识已保存的 profile，因此当 `SET_CREDENTIALS` 在已连接状态下成功时，
它可以临时与既有链路的 SSID 不同。

可观察的成功后置条件以完整的 `WIFI_STATUS(state, failure, profile_ssid)` 快照为准：

| 操作 | 状态 | 失败 | Profile |
| --- | --- | --- | --- |
| `SCAN` | 不变 | 不变 | 不变 |
| `SET_CREDENTIALS` | 不变 | 不变 | 存在 |
| `CONNECT` | `CONNECTED` | `NONE` | 存在 |
| `DISCONNECT` | `IDLE` | `NONE` | 保持不变 |
| `FORGET` | `IDLE` | `NONE` | 不存在 |

因此 `SET_CREDENTIALS` 既不发起连接也不改变既有链路，而 `CONNECTED` 意味着 IPv4
可用。不存在 profile 时，`CONNECT` 与 `FORGET` 立即返回 `NOT_FOUND` 且不创建操作。
已断开状态下执行 `DISCONNECT` 会被接纳并成功结束。因此占用的操作槽会在评估
profile 缺失前置条件之前返回 `BUSY`。内部持久化、重试、回滚以及后续自动连接行为
仍在本 BLE 契约之外。

## 事务与恢复

同一时刻只允许一个 `server_tx` indication 等待确认。命令在其响应 indication 被确认
前保持 pending，且在任何响应或事件 indication 仍未确认时，新的 Write 以 ATT `0xfe`
拒绝。

已接纳的异步命令返回非零小端 `operation_id`（`u32`）。操作 ID 在单次启动内唯一，且
与以连接为作用域的 request ID 无关。设备只有一个操作槽。活动或未确认的终态记录会
使另一条异步命令返回 `BUSY`；状态与操作查询仍可用。

操作 ID 在单次启动内绝不回绕或重复。分配器耗尽后，新的异步命令返回空的 `INTERNAL`
响应，直到重启。在该次启动持续期间，每个已接纳的操作最终都会在实现定义但有限的超时
内到达 `SUCCEEDED` 或 `FAILED`。超时从操作被接纳并占用操作槽时开始计算。超时产生
`TIMEOUT` 失败与一条终态记录；协议不设定内部重试算法或超时时长。

`GET_OPERATION` 返回该槽位的操作、阶段、失败与保留的扫描结果。若发送了终态事件，
它必须在操作 ID、操作、失败以及（对 `SCAN_COMPLETE`）计数与完整网络列表上与保留记录
一致。无记录时返回 `NOT_FOUND`。

`ACK_OPERATION` 在每条连接上使用同一规则：匹配的终态记录返回 `OK`，活动记录返回
`BUSY`，缺失或不匹配的 ID 返回 `NOT_FOUND`。未完成的 indication 仍以 ATT `0xfe`
阻塞 Write。ACK 不要求先前的 `GET_STATUS`、终态 indication 或恢复序列。若客户端在
记录已是终态但终态事件尚未发送时 ACK，设备省略该事件。成功 ACK 在 ACK 响应
indication 本身被确认之后才移除记录，因此该确认之前断开会使记录仍可恢复。

BLE 断开既不取消操作也不清除其记录。已接纳的响应、`WIFI_STATUS` indication 与终态
事件从不重放。若某条已接纳响应未被确认，它被丢弃而操作继续。由于已接纳响应必须先于
其终态事件被确认，该事件在新连接上同样被省略；客户端读取 `GET_OPERATION`。重连后，
已绑定客户端应协商 MTU 498，然后读取 `GET_OPERATION` 与 `GET_STATUS`，并在存在终态
记录时 ACK 它。该顺序是客户端流程；除上述 ACK 规则外，设备不会拒绝查询或 ACK 的
乱序。若 `GET_OPERATION` 为 `ACTIVE`，客户端等待后再次查询。重启会清除 RAM 记录，
此后 `GET_OPERATION` 返回 `NOT_FOUND`，只有当前 `GET_STATUS` 快照仍可用。

已接纳响应必须先于其终态事件被确认。`WIFI_STATUS` 更新是尽力而为的通知：只保留最新
的待处理完整快照，重复的 `(state, failure, profile_ssid)` 快照被合并，待处理的普通
更新可能在断开时被丢弃。`GET_STATUS` 具有权威性并立即反映当前快照。`WIFI_STATUS`
与终态事件彼此不保证顺序。普通通知可以在重连后发送，无需等待 ACK。

## 验证状态

schema、向量与检查器彼此一致。该 profile 仍是 freeze candidate。其 profile 身份、
UUID、特征属性、安全闸门、帧标记、498/495 传输边界、枚举与状态值、操作集合以及 ATT
错误名与值在 v1 中已冻结；改动它们需要新的 profile/版本。Numeric Comparison、本地
bond 清除与重连、ATT MTU 498、DLE、495/496 字节边界、断开查询恢复、有限操作超时与
空口互操作性尚未在固件与移动客户端上验证。

[bluetooth-sm]: https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core_v6.3/out/en/host/security-manager-specification.html
