// This source file is part of the Swift.org Server APIs open source project
//
// Copyright (c) 2017 Swift Server API project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See http://swift.org/LICENSE.txt for license information
//

import Foundation

// MARK: TLSConstants

///
/// A structure for storing TLS related constants
///
public struct TLSConstants {
    
    // Max size of TLS record in Bytes
    public static var maxTLSRecordLength: Int = 16384
}

// MARK: TLSConfiguration

///
/// A structure representing the configuration of an SSL/TLS connection
///
public struct TLSConfiguration {
    
    // MARK: Properties
    
    /// Certificates and keys are configured using a subset of the following properties
    /// File name of CA certificate to be used.
    public private(set) var caCertificateFilePath: String? = nil
    
    /// Path to directory containing hashed CA's to be used.
    ///    *Note:* `caCertificateDirPath` - All certificates in the specified directory **must** be hashed.
    public private(set) var caCertificateDirPath: String? = nil
    
    /// Path to the certificate file to be used.
    public private(set) var certificateFilePath: String? = nil
    
    /// Path to the key file to be used.
    public private(set) var keyFilePath: String? = nil
    
    /// Path to the certificate chain file (optional).
    public private(set) var certificateChainFilePath: String? = nil
    
    /// Path to PEM formatted certificate string.
    public private(set) var certificateString: String? = nil
    
    /// True if server is using `self-signed` certificates.
    public private(set) var certsAreSelfSigned = false
    
    /// True if isServer == false and the client accepts self-signed certificates. Defaults to false, be careful to not leave as true in production
    public private(set) var clientAllowsSelfSignedCertificates = false
    
    #if os(Linux)
    /// Cipher suites to use. Defaults to `DEFAULT`
    public var cipherSuite: String = "DEFAULT"
    #else
    /// Cipher suites to use. Defaults to `14,13,2B,2F,2C,30,9E,9F,23,27,09,28,13,24,0A,14,67,33,6B,39,08,12,16,9C,9D,3C,3D,2F,35,0A`
    // @FIXME: This isn't quite right, needs to be revisited.
    public var cipherSuite: String = "14,13,2B,2F,2C,30,9E,9F,23,27,09,28,13,24,0A,14,67,33,6B,39,08,12,16,9C,9D,3C,3D,2F,35,0A"
    
    /// `True` to use default cipher list, false otherwise.
    public var useDefaultCiphers: Bool = true
    
    /// Cached array of previously imported PKCS12.
    public var pkcs12Certs: CFArray? = nil
    #endif
    
    /// Password (if needed) typically used for PKCS12 files.
    public var password: String? = nil
    
    /// True if no backing certificates provided (Readonly).
    public private(set) var noBackingCertificates = false
    
    // MARK: Lifecycle
    
    ///
    /// Initialize a configuration using a `CA Certificate` file.
    ///
    /// - Parameters:
    ///        - caCertificateFilePath:    Path to the PEM formatted CA certificate file.
    ///        - certificateFilePath:        Path to the PEM formatted certificate file.
    ///        - keyFilePath:                Path to the PEM formatted key file. If nil, `certificateFilePath` will be used.
    ///        - selfSigned:                True if certs are `self-signed`, false otherwise. Defaults to true.
    ///        - cipherSuite:                Optional String containing the cipher suite to use.
    ///
    ///    - Returns:    New Configuration instance.
    ///
    public init(withCACertificateFilePath caCertificateFilePath: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true, cipherSuite: String? = nil) {
        
        self.certificateFilePath = certificateFilePath
        self.keyFilePath = keyFilePath ?? certificateFilePath
        self.certsAreSelfSigned = selfSigned
        self.caCertificateFilePath = caCertificateFilePath
        if cipherSuite != nil {
            self.cipherSuite = cipherSuite!
        }
    }
    
    ///
    /// Initialize a configuration using a `CA Certificate` directory.
    ///
    ///    *Note:* `caCertificateDirPath` - All certificates in the specified directory **must** be hashed using the `OpenSSL Certificate Tool`.
    ///
    /// - Parameters:
    ///        - caCertificateDirPath:        Path to a directory containing CA certificates. *(see note above)*
    ///        - certificateFilePath:        Path to the PEM formatted certificate file. If nil, `certificateFilePath` will be used.
    ///        - keyFilePath:                Path to the PEM formatted key file (optional). If nil, `certificateFilePath` is used.
    ///        - selfSigned:                True if certs are `self-signed`, false otherwise. Defaults to true.
    ///        - cipherSuite:                Optional String containing the cipher suite to use.
    ///
    ///    - Returns:    New Configuration instance.
    ///
    public init(withCACertificateDirectory caCertificateDirPath: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true, cipherSuite: String? = nil) {
        
        self.certificateFilePath = certificateFilePath
        self.keyFilePath = keyFilePath ?? certificateFilePath
        self.certsAreSelfSigned = selfSigned
        self.caCertificateDirPath = caCertificateDirPath
        if cipherSuite != nil {
            self.cipherSuite = cipherSuite!
        }
    }
    
    ///
    /// Initialize a configuration using a `Certificate Chain File`.
    ///
    /// *Note:* If using a certificate chain file, the certificates must be in PEM format and must be sorted starting with the subject's certificate (actual client or server certificate), followed by intermediate CA certificates if applicable, and ending at the highest level (root) CA.
    ///
    /// - Parameters:
    ///        - chainFilePath:                        Path to the certificate chain file (optional). *(see note above)*
    ///        - password:                             Password for the chain file (optional).
    ///        - selfSigned:                           True if certs are `self-signed`, false otherwise. Defaults to true.
    ///        - clientAllowsSelfSignedCertificates:   True if, as a client, connections to self-signed servers are allowed
    ///        - cipherSuite:                          Optional String containing the cipher suite to use.
    ///
    ///    - Returns:    New Configuration instance.
    ///
    public init(withChainFilePath chainFilePath: String? = nil, withPassword password: String? = nil, usingSelfSignedCerts selfSigned: Bool = true, clientAllowsSelfSignedCertificates: Bool = false, cipherSuite: String? = nil) {
        
        self.certificateChainFilePath = chainFilePath
        self.password = password
        self.certsAreSelfSigned = selfSigned
        self.clientAllowsSelfSignedCertificates = clientAllowsSelfSignedCertificates
        if cipherSuite != nil {
            self.cipherSuite = cipherSuite!
        }
    }
    
    #if os(Linux)
    ///
    /// Initialize a configuration using a `PEM formatted certificate in String form`.
    ///
    /// - Parameters:
    ///        - certificateString:        PEM formatted certificate in String form.
    ///        - selfSigned:                True if certs are `self-signed`, false otherwise. Defaults to true.
    ///        - cipherSuite:                Optional String containing the cipher suite to use.
    ///
    ///    - Returns:    New Configuration instance.
    ///
    public init(withPEMCertificateString certificateString: String, usingSelfSignedCerts selfSigned: Bool = true, cipherSuite: String? = nil) {
    
        self.certificateString = certificateString
        self.certsAreSelfSigned = selfSigned
        if cipherSuite != nil {
        self.cipherSuite = cipherSuite!
        }
    }
    #endif
    
    ///
    /// Initialize a configuration with no backing certificates.
    ///
    /// - Parameters:
    ///     - clientAllowsSelfSignedCertificates:   True if, as a client, connections to self-signed servers are allowed
    ///        - cipherSuite:                          Optional String containing the cipher suite to use.
    ///
    ///    - Returns:    New Configuration instance.
    ///
    public init(clientAllowsSelfSignedCertificates: Bool = false, withCipherSuite cipherSuite: String?) {
        
        self.noBackingCertificates = true
        self.clientAllowsSelfSignedCertificates = clientAllowsSelfSignedCertificates
        if cipherSuite != nil {
            self.cipherSuite = cipherSuite!
        }
    }
}
