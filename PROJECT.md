# SwiftIPMI

用 Swift 重写 ipmitool 的子集：实现 `lanplus` 协议能力与传感器/原始命令对应的**库接口**，按 Dell iDRAC（PowerEdge / iDRAC7+）的实际行为适配。本项目以 `SwiftIPMI` 库为唯一交付形态，用于在 Apple 设备上直接管理远程服务器的 BMC。

参考资料：
- `ipmitool-source/`:原版 C 源码，重点参考下列文件：
  - `src/ipmitool.c`、`src/ipmi_main.c`：命令分发与参数解析
  - `src/plugins/lanplus/lanplus.c`、`lanplus_crypt.c`、`lanplus_dump.c`：RMCP+ 会话与加密
  - `lib/ipmi_sdr.c`：SDR 读取、M/B/K1/K2 公式
  - `lib/ipmi_sensor.c`：`sensor` 命令的输出格式（**和 sensor_output.log 对照看**）
  - `lib/ipmi_raw.c`：`raw` 命令
  - `include/ipmitool/ipmi_sdr.h`、`ipmi_constants.h`、`ipmi_strings.h`：常量与位域定义

---

## 1. 范围与非目标

### 必须实现
- `lanplus` 接口（IPMI v2.0 / RMCP+，UDP 623）
- 命令：`sensor`（无子命令时等价于 `sensor list`）、`raw <netfn> <cmd> [data...]`
- 仅 IPv4（iDRAC 默认是 IPv4，先跑通主路径，IPv6 后续可加）

### 明确不做
- `lan`（IPMI v1.5）、`open`、`serial-*`、`bridge` 多跳
- `sdr`/`sel`/`fru`/`chassis`/`user`/`channel`/`sol`/`dcmi`/`pef`/`hpm`/`picmg`/`vita`/OEM 子命令
- 任何 SDR 缓存到本地文件的功能（`-S`）
- 交互式 shell

---

## 2. 目标平台

| 项 | 值 |
|---|---|
| Swift | 5.9+ |
| macOS | 12+（Monterey 起）|
| iOS / iPadOS | 15+ |
| visionOS | 1+（顺带支持，靠 iOS API）|
| 加密 | CryptoKit（HMAC-SHA256），CommonCrypto（AES-CBC-128）|
| 网络 | `Network.framework`（NWConnection, UDP）|
| 并发 | Swift Concurrency（`async`/`await`，`actor`），不使用 Combine/Dispatch 队列 |

---

## 3. 仓库结构

SwiftIPMI/
├── Package.swift
├── PROJECT.md                    ← 本文件
├── Sources/
│   ├── SwiftIPMI/                ← 库:协议 + SDR + 命令实现
│   │   ├── Transport/
│   │   │   ├── RMCPSocket.swift           // NWConnection 包装,UDP send/recv
│   │   │   └── Endian.swift               // ipmi16toh / ipmi32toh 等
│   │   ├── Session/
│   │   │   ├── LanPlusSession.swift       // actor:打开/保持/关闭会话
│   │   │   ├── OpenSession.swift          // RMCP+ Open Session Req/Rsp
│   │   │   ├── RAKP.swift                 // RAKP1-4
│   │   │   ├── CipherSuite.swift          // 0/3/17 等的算法映射
│   │   │   └── Crypto.swift               // HMAC-SHA256 / AES-CBC-128 包装
│   │   ├── Message/
│   │   │   ├── IPMIRequest.swift          // netfn/cmd/data + 序列号
│   │   │   ├── IPMIResponse.swift         // ccode + data
│   │   │   ├── PacketBuilder.swift        // 组帧:RMCP+IPMI 头+加密+HMAC
│   │   │   └── PacketParser.swift         // 解帧:校验 HMAC+解密+取 payload
│   │   ├── SDR/
│   │   │   ├── SDRRepository.swift        // Reserve / Get SDR Repo Info / Get SDR (分片)
│   │   │   ├── SDRRecord.swift            // Full / Compact / EventOnly 的 struct
│   │   │   ├── SDRParser.swift            // 二进制 -> SDRRecord
│   │   │   └── SensorReadingConverter.swift // M/B/K1/K2 + 线性化函数
│   │   ├── Commands/
│   │   │   ├── SensorCommand.swift        // 复刻 lib/ipmi_sensor.c 的列表输出
│   │   │   └── RawCommand.swift           // 复刻 lib/ipmi_raw.c
│   │   ├── Constants/
│   │   │   ├── NetFn.swift
│   │   │   ├── CompletionCode.swift
│   │   │   ├── SensorUnits.swift          // 与 ipmi_sdr.c 中 unit_desc[] 完全一致
│   │   │   └── SensorTypes.swift
│   │   ├── Logging/
│   │   │   └── VerboseLogger.swift 
│   │   └── IPMIClient.swift               // 对外门面:connect / sensor / raw / close
└── Tests/
└── SwiftIPMITests/
    ├── SDRDecodeTests.swift            // 已知 raw bytes -> 期望读数
    └── CryptoVectorTests.swift         // RAKP/HMAC/AES 测试向量

---

## 4. 协议层(基于 ipmi_output_vvv.log 推导)

### 4.1 会话建立顺序
1. **Get Channel Authentication Capabilities**（NetFn `0x06`，Cmd `0x38`，data `0x8E 0x04`）
   - 用 IPMI v1.5 帧（auth type = NONE，session id = 0）发出，原样照抄日志里的字节。
2. **Get Channel Cipher Suites**（NetFn `0x06`，Cmd `0x54`，channel `0x0E`）
   - 多次循环（index 0..N），每次 list_index 自增，直到返回长度变短表示结束。
   - 选最优可用 cipher：iDRAC 通常返回 17 可用，按 `(17, 3)` 顺序选。
3. **RMCP+ Open Session Request / Response**
   - Console session ID 固定 `0xA0A2A3A4`（与原版一致，便于调试时和日志比对）。
   - Auth = HMAC-SHA256，Integrity = HMAC-SHA256-128，Confidentiality = AES-CBC-128。
4. **RAKP1 / RAKP2**：发 16 字节 console rand；校验 BMC 回的 HMAC（用密码做 key）。
5. **RAKP3 / RAKP4**：发 HMAC（用密码做 key），校验 BMC 回的 integrity check。
6. **生成 SIK / K1 / K2**：HMAC-SHA256 over `console_rand || bmc_rand || role || username`。
7. **Set Session Privilege Level**（NetFn `0x06`，Cmd `0x3B`，data `0x04` = ADMIN）。
8. （可选）`Get Device ID` 验活。
9. 业务报文走加密（AES-CBC-128，IV 16 字节随机）+ 完整性 HMAC-SHA256-128（取前 16 字节）。
10. **Close Session**（NetFn `0x06`，Cmd `0x3C`，data = 4 字节 BMC session ID）。

### 4.2 帧结构（每包必须按位逐字段拼）

RMCP header (4):  06 00 FF 07
Session header (12 for v2): 06 | payload_type(.7=enc,.6=auth) | session_id(4) | seq(4) | msg_len(2)
Confidentiality header (16): random IV
Encrypted payload: ipmi message,以 AES-CBC-128 加密,尾部 PKCS-like pad(数值=填充长度,最后一字节是 pad 长度)
Integrity pad: 0xFF 填到 4 字节对齐（按 length_before_authcode）
Pad length(1) + Next header(1, 固定 0x07)
AuthCode (16 字节, HMAC-SHA256-128 取前 16)

> 加密填充的具体规则、length_before_authcode 的口径直接对照 `lanplus.c` 中 `ipmi_lanplus_build_v2x_msg` 实现，不要自己发明。

### 4.3 iDRAC 行为差异（必须容忍）
| 探测包 | NetFn/Cmd | iDRAC 返回 | 处理 |
|---|---|---|---|
| HPM.2 capabilities | `0x2C / 0x3E` | ccode `0xC1` | 静默忽略，仅 `verbose` 时打印 |
| PICMG Get Properties | `0x2C / 0x00` data `0x00` | `0xC1` | 同上 |
| VITA Get Capabilities | `0x2C / 0x00` data `0x03` | `0xC1` | 同上 |
| IPMB 地址发现 | — | 退化到 `0x00` | `my_addr` 仍用 `0x20` |

我们直接**跳过**这些探测，反正 sensor/raw 不需要桥接。日志里 ipmitool 也都是失败一次然后用本地 `0x20` 继续。

---

## 5. SDR 与 sensor 读数

### 5.1 拉取流程
1. `Get SDR Repository Info`（NetFn `0x0A`，Cmd `0x20`）拿 record count。
2. `Reserve SDR Repository`（NetFn `0x0A`，Cmd `0x22`）拿 reservation id。
3. 循环 `Get SDR`（NetFn `0x0A`，Cmd `0x23`），分片读取（每次最大 0xFE 或被 ccode `0xCA` 自适应缩小）。
4. 解析记录类型：
   - `0x01` Full Sensor Record
   - `0x02` Compact Sensor Record
   - `0x03` Event-Only Sensor Record
   - `0x10` Generic Device Locator
   - `0x11` FRU Device Locator
   - `0x12` MC Device Locator
   - `0x14` OEM
5. 对 Full / Compact 记录，逐个发 `Get Sensor Reading`（NetFn `0x04`，Cmd `0x2D`）。
6. 对 Full（且是 Threshold 类型）记录，发 `Get Sensor Thresholds`（NetFn `0x04`，Cmd `0x27`）。

### 5.2 读数换算（来自 `sdr_convert_sensor_reading`）

m  = signed 10-bit from mtol
b  = signed 10-bit from bacc
k1 = signed 4-bit  exponent of b (B exp)
k2 = signed 4-bit  exponent of result (R exp)
analog_format ∈ { 0=unsigned, 1=1's compl, 2=2's compl }

raw' = analog_format 转换后的 raw
result = (m * raw' + b * 10^k1) * 10^k2

线性化（`linearization & 0x7F`）支持 LINEAR / LN / LOG10 / LOG2 / E / EXP10 / EXP2 / 1_X / SQR / CUBE / SQRT / CUBERT；非线性时（`0x70..0x7F`）需要先调用 `Get Sensor Reading Factors`（NetFn `0x04`，Cmd `0x23`）刷新 m/b/k1/k2。

实现见 `SensorReadingConverter.swift`，必须有针对 `Fan1=3360.000 RPM`、`Inlet Temp=27.000 degrees C`、`Pwr Consumption=84.000 Watts` 这几个已知样本的单元测试。

---

## 6. 公开 API（库）

```swift
public actor IPMIClient {
    public init(host: String, port: UInt16 = 623,
                username: String, password: String,
                privilege: PrivilegeLevel = .administrator,
                cipherSuiteID: UInt8? = nil,           // nil = 自动协商
                timeout: TimeInterval = 2.0,
                retries: Int = 4,
                verbosity: Verbosity = .quiet)

    public func connect() async throws
    public func close() async

    /// 等价于命令行 `sensor list`。返回值已按 sensor_output.log 的顺序排列。
    public func sensorList() async throws -> [SensorRow]

    /// 渲染成与原版 ipmitool 完全一致的多行字符串(尾随空格保留)。
    public func sensorListFormatted() async throws -> String

    /// 等价于命令行 `raw`。
    public func raw(netFn: UInt8, command: UInt8, data: [UInt8]) async throws -> RawResponse
}
```
SensorRow 携带原始字段（name, valueKind: .analog(Double, unit) / .discrete(UInt8, state: UInt16) / .unavailable, thresholds），渲染层独立，方便 GUI 在 iOS 上重新排版。

---

## 7. 加密实现要点

| 用途 | 算法 | API |
|---|---|---|
| RAKP HMAC | HMAC-SHA256 | CryptoKit.HMAC<SHA256> |
| 完整性码 | HMAC-SHA256-128（取前 16 字节）| 同上,truncate |
| 载荷加密 | AES-CBC-128 | CommonCrypto.CCCrypt |
| 随机数 | 16 字节 | SystemRandomNumberGenerator / SecRandomCopyBytes |

注意点：
• AES-CBC 的填充：原版不是 PKCS#7，而是 IPMI 自定义——填充字节内容是 0x01,0x02,0x03,...，最后一个字节是 pad 长度（不含自身）。详见 lanplus_crypt.c::lanplus_encrypt_aes_cbc_128。
• HMAC 的 key 长度：用密码当 RAKP key，需要补到 20 字节（IPMI 规范 13.31，截断或 NUL 填充）。
• 所有多字节字段都是小端序，跟主机字节序无关，统一过 Endian.swift 里的 UInt16/32(littleEndian:) 进出。

---

## 8. 实现里程碑

1. M1 - 协议骨架：能用硬编码密码完成 Open Session + RAKP1-4，打印和日志一致的 IPMIv2 / RMCP+ SESSION OPENED SUCCESSFULLY。
2. M2 - 通用消息收发：Set Session Privilege + Get Device ID + Close Session 通过。
3. M3 - SDR 拉取：完整下载 SDR Repo，单元测试覆盖 Full/Compact/EventOnly 解析。
4. M4 - sensor list 格式化：黄金对比 sensor_output.log，逐字节相同。
5. M5 - raw 命令：基本路径 + 错误码透传。
6. M6 - iDRAC 兼容收尾与调试日志对齐。
7. M7 - iOS demo target（可选）：一个 SwiftUI 视图调用 IPMIClient.sensorList() 显示传感器表。

---

## 9. 测试策略

• 协议向量测试：把 ipmi_output_vvv.log 里的 hex dump 解析成测试 fixture（Tests/Fixtures/）。RAKP2 的 bmc_rand、bmc_guid、auth_code 全部可对照计算。
• 加密测试：CommonCrypto/CryptoKit 的输出 vs 已知向量。
• SDR 解析测试：用从 iDRAC 抓的真实 SDR（建议运行一次原版 ipmitool sdr dump file.bin 拿到 binary）作为 fixture。
• golden output 测试：mock 一组 SensorRow，渲染后与 sensor_output.log ==。
• 集成测试：xcodebuild test/swift test，CI 不连真实 BMC，靠 fixture。

测试统一用 Swift Testing（@Suite / @Test / #expect）。

---

## 10. 给后续 agent 的工作约定

• 任何新文件优先放进 Sources/SwiftIPMI/<合适子目录>/。
• 所有十六进制常量加 0x 前缀，写成 UInt8/UInt16/UInt32，避免 Int 推断。
• 公开 API 写 doc comment，注明对应原版 C 函数，方便 cross-reference。
