// swift-tools-version:4.0

import PackageDescription

let package = Package(
    name: "ServerSecurity",
    products: [
        .library( name: "ServerSecurity",
                  targets: ["ServerSecurity"])
    ],
    
    targets: [ .target( name: "ServerSecurity", dependencies: []) ]
)
