import Foundation

enum MobileFFICode {
    static let statusOK = or_ios_status_value(OR_STATUS_OK)
    static let statusEmpty = or_ios_status_value(OR_STATUS_EMPTY)
    static let statusBackpressure = or_ios_status_value(OR_STATUS_BACKPRESSURE)
    static let statusUnavailable = or_ios_status_value(OR_STATUS_UNAVAILABLE)
    static let statusBufferTooSmall = or_ios_status_value(OR_STATUS_BUFFER_TOO_SMALL)
    static let packetProtocolIPv4 = or_ios_packet_protocol_value(OR_PACKET_PROTOCOL_IPV4)
    static let packetProtocolIPv6 = or_ios_packet_protocol_value(OR_PACKET_PROTOCOL_IPV6)
    static let rotationSoft = or_ios_rotation_kind_value(OR_ROTATION_SOFT)
    static let rotationHard = or_ios_rotation_kind_value(OR_ROTATION_HARD)
}

final class RustCore: @unchecked Sendable {
    struct Packet: Sendable {
        let data: Data
        let protocolVersion: UInt32
    }

    struct Event: Sendable {
        let kind: UInt32
        let sequence: UInt64
        let operationID: UInt64
        let code: Int32
        let value: UInt64
        let data: Data
    }

    private let lock = NSLock()
    private var handle: or_client_handle_t = 0

    init(eventCapacity: UInt32, memoryBudgetBytes: UInt64) throws {
        var options = or_create_options_t()
        options.struct_size = UInt32(MemoryLayout<or_create_options_t>.size)
        options.abi_min_major = UInt16(OR_ABI_MAJOR)
        options.abi_min_minor = UInt16(OR_ABI_MINOR)
        options.abi_max_major = UInt16(OR_ABI_MAJOR)
        options.abi_max_minor = UInt16(OR_ABI_MINOR)
        options.event_capacity = eventCapacity
        options.memory_budget_bytes = memoryBudgetBytes
        var created: or_client_handle_t = 0
        try check(or_client_create(&options, &created))
        guard created != 0 else { throw RustCoreError.invalidHandle }
        handle = created
    }

    deinit { shutdown() }

    func connect() throws {
        try withHandle { handle in
            var operation: UInt64 = 0
            try check(or_client_connect(handle, &operation))
        }
    }

    @discardableResult
    func tunnelReady(_ ready: Bool) throws -> Int32 {
        try withHandle { handle in
            let status = or_client_set_tunnel_ready(handle, ready ? 1 : 0)
            if status != MobileFFICode.statusUnavailable { try check(status) }
            return status
        }
    }

    func setCountry(_ country: String) throws {
        let bytes = Array(country.utf8)
        guard bytes.count == 2 else { throw RustCoreError.invalidArgument }
        try bytes.withUnsafeBytes { raw in
            try withHandle { try check(or_client_set_country($0, raw.bindMemory(to: UInt8.self).baseAddress)) }
        }
    }

    func setMode(_ mode: UInt32) throws {
        try withHandle { try check(or_client_set_anonymity_mode($0, mode)) }
    }

    func setNetwork(available: Bool, expensive: Bool, constrained: Bool, captive: Bool) throws {
        try withHandle {
            try check(or_client_set_network(
                $0,
                available ? 1 : 0,
                expensive ? 1 : 0,
                constrained ? 1 : 0,
                captive ? 1 : 0
            ))
        }
    }

    func rotate(hard: Bool) throws {
        try withHandle { handle in
            var operation: UInt64 = 0
            try check(or_client_rotate(
                handle,
                hard ? MobileFFICode.rotationHard : MobileFFICode.rotationSoft,
                &operation
            ))
        }
    }

    func requestTokenRefresh() throws {
        try withHandle { handle in
            var operation: UInt64 = 0
            try check(or_client_request_token_refresh(handle, &operation))
        }
    }

    func requestConfigRefresh() throws {
        try withHandle { handle in
            var operation: UInt64 = 0
            try check(or_client_request_config_refresh(handle, &operation))
        }
    }

    func suspend(_ monotonicMilliseconds: UInt64) throws {
        try withHandle { try check(or_client_suspend($0, monotonicMilliseconds)) }
    }

    func resume(_ monotonicMilliseconds: UInt64, protectedPathHealthy: Bool) throws {
        try withHandle {
            try check(or_client_resume($0, monotonicMilliseconds, protectedPathHealthy ? 1 : 0))
        }
    }

    @discardableResult
    func submit(packet: Data) throws -> Int32 {
        guard !packet.isEmpty && packet.count <= 128 * 1024 else {
            throw RustCoreError.invalidArgument
        }
        return try packet.withUnsafeBytes { raw in
            try withHandle { handle in
                let status = or_client_submit_packet(
                    handle,
                    raw.bindMemory(to: UInt8.self).baseAddress,
                    raw.count
                )
                if status != MobileFFICode.statusUnavailable
                    && status != MobileFFICode.statusBackpressure
                {
                    try check(status)
                }
                return status
            }
        }
    }

    func pollPacket() throws -> Packet? {
        try withHandle { handle in
            var packetLength = 0
            var protocolVersion: UInt32 = 0
            let probeStatus = or_client_poll_packet(
                handle,
                nil,
                0,
                &packetLength,
                &protocolVersion
            )
            if probeStatus == MobileFFICode.statusEmpty { return nil }
            guard
                probeStatus == MobileFFICode.statusBufferTooSmall,
                packetLength > 0,
                packetLength <= 128 * 1024
            else {
                try check(probeStatus)
                throw RustCoreError.invalidArgument
            }

            var data = Data(count: packetLength)
            let status = data.withUnsafeMutableBytes { raw in
                or_client_poll_packet(
                    handle,
                    raw.bindMemory(to: UInt8.self).baseAddress,
                    raw.count,
                    &packetLength,
                    &protocolVersion
                )
            }
            try check(status)
            guard
                packetLength > 0,
                packetLength <= data.count,
                protocolVersion == MobileFFICode.packetProtocolIPv4 ||
                    protocolVersion == MobileFFICode.packetProtocolIPv6
            else { throw RustCoreError.invalidArgument }
            data.removeSubrange(packetLength..<data.endIndex)
            return Packet(data: data, protocolVersion: protocolVersion)
        }
    }

    func pollEvent() throws -> Event? {
        try withHandle { handle in
            var raw = or_event_t()
            raw.struct_size = UInt32(MemoryLayout<or_event_t>.size)
            let status = or_client_poll_event(handle, &raw)
            if status == MobileFFICode.statusEmpty { return nil }
            try check(status)
            let data = withUnsafeBytes(of: &raw.data) { bytes in
                Data(bytes.prefix(Int(raw.data_len)))
            }
            return Event(
                kind: raw.kind,
                sequence: raw.sequence,
                operationID: raw.operation_id,
                code: raw.code,
                value: raw.value,
                data: data
            )
        }
    }

    func shutdown() {
        lock.lock()
        let oldHandle = handle
        handle = 0
        lock.unlock()
        guard oldHandle != 0 else { return }
        var operation: UInt64 = 0
        _ = or_client_disconnect(oldHandle, &operation)
        _ = or_client_destroy(oldHandle)
    }

    private func withHandle<T>(_ body: (or_client_handle_t) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard handle != 0 else { throw RustCoreError.invalidHandle }
        return try body(handle)
    }
}

enum RustCoreError: Error, Equatable {
    case invalidArgument
    case invalidHandle
    case native(Int32)
}

private func check(_ status: Int32) throws {
    guard status == MobileFFICode.statusOK else { throw RustCoreError.native(status) }
}
