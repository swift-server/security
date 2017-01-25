# Introduction

Currently there is no standard Swift security library that is compatible with all of the current Swift platforms (Apple and Linux). This lack of standardization has resulted in multiple projects which either write their own Swift security functionality or use their security library of choice (be it OpenSSL, LibreSSL, etc.).  This is not desirable because it can lead to:
- incompatibility of dependencies if more that one security package is needed by different modules (a project cannot have both OpenSSL and LibreSSL in its dependency graph)
- insecurity (using an unpatched or insecure library)
- unmaintainability (using non-standard or non-native libraries)
- more complex code (using different APIs for each platform).

This proposal outlines a set of design goals as well as an approach to be adopted by the Swift Server APIs project's Security Working Group for the creation of a single Swift security component that is cross-compatible on Apple and Linux (Ubuntu) platforms. The Security APIs will consist of both lower level crypto APIs (including hashing, symmetric and asymmetric crypto) as well as higher level APIs (including key/certificate management and secure communication such as TLS).

# Motivation

Having a consistent development experience for Swift across Apple and Linux helps drive higher developer productivity, safer code as well as better reuse of Swift assets/libraries across these platforms. 

At the same time, leveraging a platform's native libraries is advantageous because of improved maintainability and potentially better overall security. This is driven by the lack of control and consistency over the non-native library's version and build/installation methodology.

# Proposed Solution

We propose the following set of design goals for the Swift security component:

- Support both Apple and Linux (currently Ubuntu 14.04 and 16.04)
- Integrate with native security libraries on supported platforms so that the user is not responsible for installing and maintaining any other libraries;
- Native libraries should be dynamically linked to, in order to allow timely security patching; 
- Avoid re-implementing security functionality, using existing functions in underlying libraries where it is available;
- Provide a consistent and unified Swift interface across operating systems, so that the developer can write simple, cross-platform applications;

Using these goals, we would use the following native libraries on each platform:
 - On Linux, we would use OpenSSL which is not only the most prevalent open source security library but it is also FIPS 104 conformance verified. OpenSSL is made up of two primary (sub)libraries: libssl and libcrypto. libcrypto is a comprehensive and full-featured cryptographic library that provides the fundamental cryptographic routines used by libssl, which implements the SSL and TLS protocols.
 - On Apple, we would use CommonCrypto and Secure Transport which respectively map to OpenSSL's libcrypto and libssl.

The proposed solution then would consist of a thin Swift layer that defines a common API surface which are implemented using OpenSSL on Linux and CommonCrypto and Secure Transport on Apple.

# Implementation Experience

A similar approach to this proposal has been taken by two existing project:
- BlueSSLService [https://github.com/IBM-Swift/BlueSSLService] which is a TLS library and is used as an add-in framework for Sockets using a delegate/protocol model. It uses Apple Secure Transport on Apple and OpenSSL on Linux.
- BlueCryptor [https://github.com/IBM-Swift/BlueCryptor] which is a crypto library and uses Common Crypto on Apple and OpenSSL on Linux.  Currently BlueCryptor does not include asymmetric key functionality because Apple does not expose asymmetric crypto APIs at the CommonCrypto level, and instead exposes them at the SecKey and KeyChain level APIs.
 
For further information, we refer the reader to [https://developer.ibm.com/swift/2016/12/13/securing-kitura-cross-platform-challenges/] where the authors discuss how the differences in the underlying frameworks of BlueSSLService results in slightly different cross-platform behavior.

# Alternatives Considered

## Native vs Non-native Framework

A straightforward solution to providing unified, cross-platform APIs is by using the same underlying security library. Below we show why it is not desirable to use user-installed or non-native libraries in our solution. 

Consider OpenSSL which is a cross-platform library that works both on macOS and Linux. Apple deprecated OpenSSL as of OS X v10.7 because of lack of API compatibility across versions. Since its deprecation, users are responsible for installing and upgrading OpenSSL themselves. Users can obtain OpenSSL source code and compile it themselves (and use their own custom flags) or use third party package management tools such as homebrew or macport or download the binary themselves. The range of ways that OpenSSL can be installed on macOS results in an even larger range of OpenSSL binaries which can cause incompatibility with the calling APIs and applications. This in turn makes maintainability and correctness of the APIs much harder.

This problem is further exacerbated when we consider the lack of API compatibility of OpenSSL across versions and the fact that users are now wholey responsible for upgrades of their libraries. The timeliness of the upgrades can also affect the security of the library and any linked applications.

Native frameworks in contrast, are shipped and maintained by the OS and often tie API changes to OS versions which greatly improves maintainability of linked application. 

A final motivation in using native libraries is that vendors often go through security certification processes for their own modules and therefore users can get this certification for free. In particular, many use cases that involve government or enterprise data or users, require FIPS 104 compliance or validation. FIPS is a US Government (NIST) cryptographic standard and is a requirement by most government agencies and many enterprises. The process of getting certified  is hard, expensive and time consuming and is only done by vendors and large organizations. 

On Linux, OpenSSL contains the OpenSSL FIPS Object Module, which is FIPS 140-2 conformance validated (not just compliant). However since OpenSSL was depracated on macOS, Apple no longer submits OpenSSL on macOS for FIPS 104 validation and therefore OpenSSL on macOS is no longer FIPS compliant. Apple submits its own CoreCrypto and CoreCrypto Kernel for validation.


## Other Security Libraries on Linux

While there are a number of alternative crypto and security libraries on Linux including LibreSSL, BoringSSL, etc., their open sourced versions are not FIPS compliant. LibreSSL for example, deliberately removed the FIPS Object Module of OpenSSL to make the library more lean and thus improve both security and performance. 
