import Foundation
import Network

public protocol RMCPSocketProtocol: Sendable {
    func send(_ data: [UInt8]) async throws
    func receive(timeout: TimeInterval?) async throws -> [UInt8]
}

public enum RMCPSocketError: Error, Sendable {
    case invalidHost(String)
    case connectionFailed(String)
    case sendFailed(String)
    case receiveFailed(String)
    case noData
}

public actor RMCPSocket: RMCPSocketProtocol {
    private let connection: NWConnection

    public init(host: String, port: UInt16) throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw RMCPSocketError.connectionFailed("invalid port: \(port)")
        }

        let endpointHost: NWEndpoint.Host
        if let ipv4 = IPv4Address(host) {
            endpointHost = .ipv4(ipv4)
        } else if let ipv6 = IPv6Address(host) {
            endpointHost = .ipv6(ipv6)
        } else {
            endpointHost = .name(host, nil)
        }

        let parameters = NWParameters.udp
        parameters.allowLocalEndpointReuse = true
        self.connection = NWConnection(host: endpointHost, port: nwPort, using: parameters)
        self.connection.start(queue: .global(qos: .userInitiated))
    }

    public func send(_ data: [UInt8]) async throws {
        let conn = connection
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await Self.sendOnce(data, via: conn)
            }

            group.addTask {
                try await Task.sleep(nanoseconds: 3_000_000_000)
                throw RMCPSocketError.sendFailed("timeout after 3.0s")
            }

            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    public func receive(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        let conn = connection

        if let timeout, timeout > 0 {
            return try await withThrowingTaskGroup(of: [UInt8].self) { group in
                group.addTask {
                    try await Self.receiveOnce(from: conn)
                }

                group.addTask {
                    try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                    throw RMCPSocketError.receiveFailed("timeout after \(timeout)s")
                }

                let result: [UInt8] = try await group.next()!
                group.cancelAll()
                return result
            }
        }

        return try await Self.receiveOnce(from: conn)
    }

    private nonisolated static func sendOnce(_ data: [UInt8], via connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: Data(data), completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: RMCPSocketError.sendFailed(String(describing: error)))
                    return
                }
                continuation.resume(returning: ())
            })
        }
    }

    private nonisolated static func receiveOnce(from connection: NWConnection) async throws -> [UInt8] {
        try await withCheckedThrowingContinuation { continuation in
            connection.receiveMessage { data, _, _, error in
                if let error {
                    continuation.resume(throwing: RMCPSocketError.receiveFailed(String(describing: error)))
                    return
                }
                guard let data, !data.isEmpty else {
                    continuation.resume(throwing: RMCPSocketError.noData)
                    return
                }
                continuation.resume(returning: Array(data))
            }
        }
    }
}
