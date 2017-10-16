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
    func didCreateClient() throws
    
    ///
    /// Initialize TLS Service for Server
    ///
    func didCreateServer() throws
    
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
    func didConnect(to connection: ConnectionDelegate) throws
    
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
    /// Low level writer
    ///
    /// - Parameters: data:		Buffer pointer.
    ///
    ///	- Returns the number of bytes written. Zero indicates TLS shutdown, less than zero indicates error.
    ///
    func willSend(data: Data) throws -> Int

    ///
    /// Low level reader
    ///
    /// - Parameters:
    ///		- buffer:		Buffer pointer.
    ///		- bufSize:		Size of the buffer.
    ///
    ///	- Returns the number of bytes read. Zero indicates TLS shutdown, less than zero indicates error.
    ///
    func willReceive(into buffer: UnsafeMutableRawPointer, bufSize: Int) throws -> Int

    ///
    /// Low level reader
    ///
    /// - Parameters: data: The buffer to return the data in.
    ///
    ///	- Returns the number of bytes read. Zero indicates TLS shutdown, less than zero indicates error.
    ///
    func willReceive(into data: inout Data) throws -> Int

}
