import XCTest
@testable import TLSService
import Foundation

class TLSServiceTests: XCTestCase {
    func test1() {
        //XCTAssertEqual(Country(code: "AT").emojiFlag, "\u{1f1e6}\u{1f1f9}")
        print("test1")
    }
    
}

extension TLSServiceTests {
    static var allTests : [(String, (TLSServiceTests) -> () throws -> Void)] {
        return [
            ("test1", test1)
        ]
    }
}
