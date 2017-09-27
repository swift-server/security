// This source file is part of the Swift.org Server APIs open source project
//
// Copyright (c) 2017 Swift Server API project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See http://swift.org/LICENSE.txt for license information
//

// MARK: Connection Delegate

///
/// Connection Delegate Protocol
///
public protocol ConnectionDelegate:class {
    
    ///
    /// Connection endpoint (such as socket file descriptor)
    ///
    var endpoint: ConnectionType { get }
    
    ///
    /// The delegate that provides the TLS Service implementation.
    /// Delegate can be nil which indicates an insecure communication channel.
    ///
    var TLSdelegate: TLSServiceDelegate? { get set }
}


// MARK: ConnectionType

///
/// Connection Type
///
public enum ConnectionType: Equatable {
    case socket(Int32)
    case unknown
    
}

public func ==(lhs: ConnectionType, rhs: ConnectionType) -> Bool {
    switch (lhs, rhs) {
    case let (.socket(a), .socket(b)):
        return a == b
    default:
        return false
    }
}
