//
//  KeychainError.swift
//  DigoAuthentication
//
//  Created by dtrognn on 22/4/25.
//

import Foundation

public enum KeychainError: Error {
    case unexpectedStatus(OSStatus)
    case itemNotFound
    case encodingError(Error)
    case decodingError(Error)
    case stringConversionError
    case unhandledError(message: String)
}
