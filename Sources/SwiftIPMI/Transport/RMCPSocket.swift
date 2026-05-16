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

    private let defaultTimeout: TimeInterval

    public init(host: String, port: UInt16, defaultTimeout: TimeInterval = 3.0) throws {
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
        self.defaultTimeout = defaultTimeout
        self.connection.start(queue: .global(qos: .userInitiated))
    }

    public func send(_ data: [UInt8]) async throws {
        let conn = connection
        try await Self.sendOnce(data, via: conn, timeout: defaultTimeout)
    }

    public func receive(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        let conn = connection
        return try await Self.receiveOnce(from: conn, timeout: timeout ?? defaultTimeout)
    }

    private nonisolated static func sendOnce(_ data: [UInt8], via connection: NWConnection, timeout: TimeInterval) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let lock = NSLock()
            var isResolved = false

            func resolve(_ result: Result<Void, Error>) {
                lock.lock()
                defer { lock.unlock() }
                guard !isResolved else { return }
                isResolved = true
                continuation.resume(with: result)
            }

            connection.send(content: Data(data), completion: .contentProcessed { error in
                if let error {
                    resolve(.failure(RMCPSocketError.sendFailed(String(describing: error))))
                } else {
                    resolve(.success(()))
                }
            })

            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + timeout) {
                resolve(.failure(RMCPSocketError.sendFailed("timeout after \(timeout)s")))
            }
        }
    }

    private nonisolated static func receiveOnce(from connection: NWConnection, timeout: TimeInterval?) async throws -> [UInt8] {
        try await withCheckedThrowingContinuation { continuation in
            let lock = NSLock()
            var isResolved = false

            func resolve(_ result: Result<[UInt8], Error>) {
                lock.lock()
                defer { lock.unlock() }
                guard !isResolved else { return }
                isResolved = true
                continuation.resume(with: result)
            }

            connection.receiveMessage { data, _, _, error in
                if let error {
                    resolve(.failure(RMCPSocketError.receiveFailed(String(describing: error))))
                    return
                }
                guard let data, !data.isEmpty else {
                    resolve(.failure(RMCPSocketError.noData))
                    return
                }
                resolve(.success(Array(data)))
            }

            if let timeout, timeout > 0 {
                DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + timeout) {
                    resolve(.failure(RMCPSocketError.receiveFailed("timeout after \(timeout)s")))
                }
            }
        }
    }
}
