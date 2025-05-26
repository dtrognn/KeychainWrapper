//
//  KeychainWrapper.swift
//  DigoAuthentication
//
//  Created by dtrognn on 22/4/25.
//

import Foundation

public struct KeychainWrapper {
    private let keychainQuery: KeychainStoreQueryable
    private let options: KeychainOptions

    public init(
        keychainQuery: GenericPasswordQueryable = GenericPasswordQueryable(service: Bundle.main.bundleIdentifier ?? "YourBundleIdentifier"),
        options: KeychainOptions = KeychainOptions())
    {
        self.keychainQuery = keychainQuery
        self.options = options
    }

    // MARK: - Write

    public func write<T: Codable>(_ object: T, forKey key: String) throws {
        let encoder = JSONEncoder()
        do {
            let data = try encoder.encode(object)
            try writeData(data, forKey: key)
        } catch let error as KeychainError {
            throw error
        } catch {
            throw KeychainError.encodingError(error)
        }
    }

    public func write(_ string: String, forKey key: String) throws {
        guard let data = string.data(using: .utf8) else {
            throw KeychainError.stringConversionError
        }
        try writeData(data, forKey: key)
    }

    public func writeData(_ data: Data, forKey key: String) throws {
        var query = baseQuery(forKey: key)
        if options.synchronizable {
            query[kSecAttrSynchronizable] = kCFBooleanTrue
        }

        let status = SecItemCopyMatching(query as CFDictionary, nil)

        switch status {
        case errSecSuccess:
            /// existing
            let updateQuery: [CFString: Any] = [kSecValueData: data]
            let updateStatus = SecItemUpdate(query as CFDictionary, updateQuery as CFDictionary)
            guard updateStatus == errSecSuccess else {
                throw mapError(updateStatus)
            }
        case errSecItemNotFound:
            /// not existing -> add new
            query[kSecAttrAccessible] = options.accessible
            query[kSecValueData] = data
            let addStatus = SecItemAdd(query as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw mapError(addStatus)
            }
        default:
            throw mapError(status)
        }
    }

    // MARK: - Read

    public func read<T: Codable>(_ type: T.Type, forKey key: String) throws -> T? {
        guard let data = try readData(forKey: key) else { return nil }
        let decoder = JSONDecoder()
        do {
            return try decoder.decode(type, from: data)
        } catch {
            throw KeychainError.decodingError(error)
        }
    }

    public func readString(forKey key: String) throws -> String? {
        guard let data = try readData(forKey: key) else { return nil }
        guard let str = String(data: data, encoding: .utf8) else {
            throw KeychainError.stringConversionError
        }
        return str
    }

    public func readData(forKey key: String) throws -> Data? {
        var query = baseQuery(forKey: key)
        query[kSecReturnData] = kCFBooleanTrue
        query[kSecMatchLimit] = kSecMatchLimitOne
        if options.synchronizable {
            query[kSecAttrSynchronizable] = kCFBooleanTrue
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw KeychainError.unexpectedStatus(status)
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw mapError(status)
        }
    }

    // MARK: - Remove

    public func remove(forKey key: String) throws {
        let query = baseQuery(forKey: key)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw mapError(status)
        }
    }

    public func removeAll() throws {
        let query = keychainQuery.query
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw mapError(status)
        }
    }

    // MARK: - Helpers

    private func baseQuery(forKey key: String) -> [CFString: Any] {
        var query = keychainQuery.query
        query[kSecAttrAccount] = key
        return query
    }

    private func mapError(_ status: OSStatus) -> KeychainError {
        if status == errSecItemNotFound {
            return .itemNotFound
        }
        if #available(iOS 11.3, *) {
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            return .unhandledError(message: message)
        } else {
            return .unexpectedStatus(status)
        }
    }
}
