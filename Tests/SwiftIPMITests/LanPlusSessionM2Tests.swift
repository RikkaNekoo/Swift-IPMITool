import Testing
@testable import SwiftIPMI

@Suite struct LanPlusSessionM2Tests {
    @Test func sendBeforeOpenThrowsNotConnected() async {
        let session = LanPlusSession(
            host: "127.0.0.1",
            port: 623,
            username: "root",
            password: "calvin",
            privilege: .administrator,
            cipherSuiteID: nil,
            loggingEnabled: false
        )

        await #expect(throws: IPMIError.self) {
            _ = try await session.send(IPMIRequest(netFn: NetFn.app.rawValue, command: 0x01))
        }
    }

    @Test func openEnablesM2CommandsAndCloseDisablesSession() async throws {
        let session = LanPlusSession(
            host: "127.0.0.1",
            port: 623,
            username: "root",
            password: "calvin",
            privilege: .administrator,
            cipherSuiteID: nil,
            loggingEnabled: false
        )

        try await session.open()

        let setPrivilege = try await session.send(IPMIRequest(
            netFn: NetFn.app.rawValue,
            command: 0x3B,
            data: [PrivilegeLevel.administrator.rawValue]
        ))
        #expect(setPrivilege.completionCode == 0x00)
        #expect(setPrivilege.data == [PrivilegeLevel.administrator.rawValue])

        let deviceID = try await session.send(IPMIRequest(netFn: NetFn.app.rawValue, command: 0x01))
        #expect(deviceID.completionCode == 0x00)
        #expect(deviceID.data.count >= 5)

        await session.close()

        await #expect(throws: IPMIError.self) {
            _ = try await session.send(IPMIRequest(netFn: NetFn.app.rawValue, command: 0x01))
        }
    }

}
