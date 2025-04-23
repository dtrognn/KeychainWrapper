//
//  KeychainWrapperProtocol.swift
//  DigoAuthentication
//
//  Created by dtrognn on 22/4/25.
//

import Foundation

public protocol KeychainStoreQueryable {
    var query: [CFString: Any] { get }
}

public struct GenericPasswordQueryable {
    let service: String
    let accessGroup: String?

    public init(service: String, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }
}

extension GenericPasswordQueryable: KeychainStoreQueryable {
    public var query: [CFString: Any] {
        var query: [CFString: Any] = [:]

        query[kSecClass] = kSecClassGenericPassword
        query[kSecAttrService] = service

        // Access group if target environment is not simulator
        #if !targetEnvironment(simulator)
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup] = accessGroup
        }
        #endif

        return query
    }
}

public struct KeychainOptions {
    /// Accessibility attribute (default: when unlock)
    public let accessible: CFString
    /// Synchronizable with iCloud Keychain (default: false)
    public let synchronizable: Bool

    public init(
        accessible: CFString = kSecAttrAccessibleWhenUnlocked,
        synchronizable: Bool = false
    ) {
        self.accessible = accessible
        self.synchronizable = synchronizable
    }
}
