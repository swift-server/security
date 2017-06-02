// This source file is part of the Swift.org Server APIs open source project
//
// Copyright (c) 2017 Swift Server API project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See http://swift.org/LICENSE.txt for license information
//

import Foundation

///
/// TLS Service Delegate Protocol
///
public protocol TLSServiceDelegate {
    
    ///
    /// Initialize TLS Service for Client
    ///
    func didClientCreate() throws
    
    ///
    /// Initialize TLS Service for Server
    ///
    func didServerCreate() throws
    
    ///
    /// willDestroy TLS Service
    ///
    func willDestroy()
    
    ///
    /// Processing on acceptance from a listening socket
    ///
    /// - Parameter connection:	The connected ConnectionDelegate instance.
    ///
    func didAccept(connection: ConnectionDelegate) throws
    
    ///
    /// Processing on connection to a listening socket
    ///
    /// - Parameter connection:	The connected ConnectionDelegate instance.
    ///
    func didConnect(connection: ConnectionDelegate) throws
    
    ///
    /// Low level writer
    ///
    /// - Parameters:
    ///		- buffer:		Buffer pointer.
    ///		- bufSize:		Size of the buffer.
    ///
    ///	- Returns the number of bytes written. Zero indicates TLS shutdown, less than zero indicates error.
    ///
    func willSend(buffer: UnsafeRawPointer, bufSize: Int) throws -> Int
    
    ///
    /// Low level reader
    ///
    /// - Parameters:
    ///		- buffer:		Buffer pointer.
    ///		- bufSize:		Size of the buffer.
    ///
    ///	- Returns the number of bytes read. Zero indicates TLS shutdown, less than zero indicates error.
    ///
    func willReceive(buffer: UnsafeMutableRawPointer, bufSize: Int) throws -> Int
    
}

// MARK: TLSError

///
/// TLS Service Error
///
public enum TLSError: Swift.Error, CustomStringConvertible {
    
    /// Success
    case success
    
    /// Retry needed
    case retryNeeded
    
    /// Failure with error code and reason
    case fail(Int, String)
    
    /// The error code itself
    public var code: Int {
        
        switch self {
            
        case .success:
            return 0
            
        case .retryNeeded:
            return -1
            
        case .fail(let (code, _)):
            return Int(code)
        }
    }
    
    /// Error description
    public var description: String {
        
        switch self {
            
        case .success:
            return "Success"
            
        case .retryNeeded:
            return "Retry operation"
            
        case .fail(let (_, reason)):
            return reason
        }
    }
}
