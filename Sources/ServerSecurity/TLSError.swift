// This source file is part of the Swift.org Server APIs open source project
//
// Copyright (c) 2017 Swift Server API project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See http://swift.org/LICENSE.txt for license information
//


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
