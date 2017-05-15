// swift-tools-version:3.1

import PackageDescription

let package = Package(
    name: "TLSService",
    targets:  [Target(name: "TLSService")],
    dependencies: [])

#if os(Linux)
// module map for OpenSSL libSSL and libcrypto
package.dependencies.append(
    .Package(url: "https://github.com/IBM-Swift/OpenSSL.git", majorVersion: 0, minor: 3))
    
#endif
