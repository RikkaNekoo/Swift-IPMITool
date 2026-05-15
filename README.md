# Swift IPMITool
使用 Swift 编写的 IPMITool 库，面向 Dell iDRAC 等 BMC 场景，提供传感器读取与原始命令能力（目前仅在 Dell iDRAC 上测试）  
适用于 Apple 平台（macOS / iOS），可直接在 Swift 项目中集成

## 特性
- 纯 Swift 库，核心入口：`IPMIClient`
- 支持 RMCP+ / IPMI v2.0 `lanplus`
- 支持：
  - `sensor list`（结构化结果 + 文本渲染）
  - `raw <netfn> <cmd> [data...]`

## 编译环境
- Swift 6
- macOS 12.0 (Monterey) 或更高版本

## 库调用示例

### 连接 + 读取传感器（结构化）

```swift
import Foundation
import SwiftIPMI

@main
struct DemoApp {
    static func main() async {
        let client = IPMIClient(
            host: "10.21.0.100",
            username: "admin",
            password: "your_password",
            privilege: .administrator,
            cipherSuiteID: nil,
            timeout: 2.0,
            retries: 4,
            loggingEnabled: false
        )

        do {
            try await client.connect()
            defer { Task { await client.close() } }

            let rows = try await client.sensorList()
            for row in rows.prefix(5) {
                switch row.valueKind {
                case let .analog(value, unit):
                    print("\(row.name): \(String(format: "%.3f", value)) \(unit) [\(row.status)]")
                case let .discrete(raw, state):
                    print("\(row.name): raw=0x\(String(raw, radix: 16)) state=0x\(String(state, radix: 16))")
                case .unavailable:
                    print("\(row.name): na")
                }
            }
        } catch {
            print("IPMI error: \(error)")
        }
    }
}
```

### 读取传感器（ipmitool 风格文本）

```swift
import SwiftIPMI

func printSensorTable(client: IPMIClient) async throws {
    let text = try await client.sensorListFormatted()
    print(text)
}
```

### 发送 raw 命令

```swift
import SwiftIPMI

func runRaw(client: IPMIClient) async throws {
    // 等价：raw 0x30 0x30 0x01 0x01
    let rsp = try await client.raw(netFn: 0x30, command: 0x30, data: [0x01, 0x01])

    print(String(format: "ccode=0x%02X", rsp.completionCode))
    print("data:", rsp.data.map { String(format: "%02X", $0) }.joined(separator: " "))
}
```

## 输出示例

### `sensorList()`（结构化打印示例，含阈值）

```text
Fan1: 3360.000 RPM [ok], thresholds: lnr=nil lcr=nil lnc=nil unc=nil ucr=nil unr=nil
Inlet Temp: 27.000 degrees C [ok], thresholds: lnr=3.000 lcr=5.000 lnc=10.000 unc=42.000 ucr=45.000 unr=50.000
Pwr Consumption: 84.000 Watts [ok], thresholds: lnr=nil lcr=nil lnc=nil unc=nil ucr=nil unr=nil
Fan Redundancy: raw=0x0 state=0x0
PSU1 Status: na
```

### `sensorListFormatted()`（表格示例，末 6 列为阈值）

```text
Fan1             | 3360.000   | RPM        | ok    | na        | na        | na        | na        | na        | na
Inlet Temp       | 27.000     | degrees C  | ok    | 3.000     | 5.000     | 10.000    | 42.000    | 45.000    | 50.000
Pwr Consumption  | 84.000     | Watts      | ok    | na        | na        | na        | na        | na        | na
```

### `raw()` 示例输出

```text
ccode=0x00
data: 20 81 02 15 02 BF 57 01
```

## 公开 API（核心）
- `IPMIClient.connect()`
- `IPMIClient.close()`
- `IPMIClient.sensorList()`
- `IPMIClient.sensorListFormatted()`
- `IPMIClient.raw(netFn:command:data:)`

详细定义可参考源码：`Sources/SwiftIPMI/IPMIClient.swift`。`sensorList()` 返回的 `SensorRow` 内含 `thresholds` 字段，`sensorListFormatted()` 会把阈值渲染到末尾 6 列（LNR/LCR/LNC/UNC/UCR/UNR）。

## 感谢 
[ipmitool](https://codeberg.org/IPMITool/ipmitool)
