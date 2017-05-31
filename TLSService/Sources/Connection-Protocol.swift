// This source file is part of the Swift.org Server APIs open source project
//
// Copyright (c) 2017 Swift Server API project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See http://swift.org/LICENSE.txt for license information
//

///
/// Connection Delegate Protocol
///
public protocol ConnectionDelegate:class {
    
    var endpoint: ConnectionType { get set }
    var TLSdelegate: TLSServiceDelegate? { get set}
}


public enum ConnectionType {
    case socket(Int32)
}
