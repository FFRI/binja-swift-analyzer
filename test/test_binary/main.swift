//
// (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
//
// swiftc -O main.swift -o main
//
import Foundation

protocol Greeter {
    func greet()
}

extension Greeter {
    func greet() {
        print("[PWT-default] Hello from Greeter extension")
    }
}

// Foundation extension - Make String conform to Greeter protocol
extension String: Greeter {
    func greet() {
        print("[PWT-Foundation-String] Hello from String: \(self)")
    }
}

// Foundation extension - Make Array conform to Greeter protocol
extension Array: Greeter where Element == String {
    func greet() {
        print("[PWT-Foundation-Array] Hello from Array: \(self)")
    }
}

// Basic enum
enum Color {
    case red
    case green
    case blue
    
    func getColorName() -> String {
        switch self {
        case .red:
            return "Red"
        case .green:
            return "Green"
        case .blue:
            return "Blue"
        }
    }
}

// Value enum (Associated values)
enum NetworkResponse {
    case success(data: Data, statusCode: Int)
    case failure(error: String, statusCode: Int)
    case loading
    
    func processResponse() {
        switch self {
        case .success(let data, let statusCode):
            print("[ValueEnum] Success: data size = \(data.count), status = \(statusCode)")
        case .failure(let error, let statusCode):
            print("[ValueEnum] Failure: error = \(error), status = \(statusCode)")
        case .loading:
            print("[ValueEnum] Loading...")
        }
    }
}

// Make Color enum conform to Greeter protocol
extension Color: Greeter {
    func greet() {
        print("[PWT-enum] Hello from Color: \(self.getColorName())")
    }
}

struct StructGreeter: Greeter {
    func greet() {
        print("[PWT-struct] Hello from StructGreeter")
    }
}

class BaseGreeter: Greeter {
    @inline(never)
    func greet() {
        print("[VTable-base] Hello from BaseGreeter")
    }

    static func staticMethod() {
        print("[static] BaseGreeter.staticMethod()")
    }

    class func classMethod() {
        print("[dynamic-class] BaseGreeter.classMethod()")
    }
}

class SubGreeter: BaseGreeter {
    override func greet() {
        print("[VTable-sub] Hello from SubGreeter")
    }

    override class func classMethod() {
        print("[dynamic-class] SubGreeter.classMethod()")
    }
}

@inline(never)
func callClassGreet(_ g: BaseGreeter) {
    g.greet()
}

@inline(never)
func callProtocolGreet(_ g: Greeter) {
    g.greet()
}

@inline(never)
func testEnums() {
    print("\n=== Enum Tests ===")
    
    // Basic enum test
    let color = Color.red
    print("Color name: \(color.getColorName())")
    callProtocolGreet(color)  // Call via PWT (Protocol Witness Table)
    
    // Value enum test
    let successResponse = NetworkResponse.success(data: Data("Hello".utf8), statusCode: 200)
    let failureResponse = NetworkResponse.failure(error: "Network timeout", statusCode: 404)
    let loadingResponse = NetworkResponse.loading
    
    successResponse.processResponse()
    failureResponse.processResponse()
    loadingResponse.processResponse()
}

@inline(never)
func testClassInheritance() {
    print("=== Class Tests ===")
    
    // Create instances of base and derived classes
    let base = BaseGreeter()
    let sub = SubGreeter()
    
    // Test virtual method calls through VTable
    callClassGreet(base)   // [VTable-base]
    callClassGreet(sub)    // [VTable-sub]

    // Test static method calls
    BaseGreeter.staticMethod()  // [static]
    SubGreeter.staticMethod()   // [static]
    
    // Test class method calls (dynamic dispatch)
    BaseGreeter.classMethod()   // [dynamic-class-base]
    SubGreeter.classMethod()    // [dynamic-class-sub]
}

@inline(never)
func testProtocolConformance() {
    print("\n=== Protocol Tests ===")
    
    // Test protocol witness table dispatch with heterogeneous array
    let conformingTypes: [any Greeter] = [StructGreeter(), SubGreeter()]
    for greeter in conformingTypes {
        callProtocolGreet(greeter)  // Call via PWT (Protocol Witness Table)
    }
}

@inline(never)
func testFoundationExtensions() {
    print("\n=== Foundation Extension Tests ===")
    
    // String extension test
    let greeting = "Swift"
    callProtocolGreet(greeting)  // Call via PWT (Protocol Witness Table)
    
    // Array extension test
    let messages = ["Hello", "World", "Swift"]
    callProtocolGreet(messages)  // Call via PWT (Protocol Witness Table)
}

func main() {
    // Execute all test functions to demonstrate different Swift features
    testClassInheritance()
    testProtocolConformance()
    testFoundationExtensions()
    testEnums()
}

main()