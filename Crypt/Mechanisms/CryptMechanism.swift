/*
 Crypt

 Copyright 2017 The Crypt Project.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

import os.log

class CryptMechanism: NSObject {
  // Log for the CryptMechanism functions
  private static let log = OSLog(subsystem: "com.grahamgilbert.crypt", category: "Mechanism")

  // Key for hint data
  private let needsEncryptionHintKey = "com.grahamgilbert.crypt.needsEncryption"

  // Define a pointer to the MechanismRecord. This will be used to get and set
  // all the inter-mechanism data. It is also used to allow or deny the login.
  var mechanism: UnsafePointer<MechanismRecord>

  // init the class with a MechanismRecord
  init(mechanism: UnsafePointer<MechanismRecord>) {
    self.mechanism = mechanism
  }

  // Allow the login. End of the mechanism
  func allowLogin() {
    os_log("allow login", log: CryptMechanism.log, type: .debug)
    _ = self.mechanism.pointee.fPlugin.pointee.fCallbacks.pointee.SetResult(
      mechanism.pointee.fEngine, AuthorizationResult.allow)
  }

  private func getContextData(key: AuthorizationString) -> Data? {
    os_log("getContextData called", log: CryptMechanism.log, type: .debug)
    var value: UnsafePointer<AuthorizationValue>?
    let data = withUnsafeMutablePointer(to: &value) { (ptr: UnsafeMutablePointer) -> Data? in
      var flags = AuthorizationContextFlags()
      if (self.mechanism.pointee.fPlugin.pointee.fCallbacks.pointee.GetContextValue(
        self.mechanism.pointee.fEngine, key, &flags, ptr) != errAuthorizationSuccess) {
        os_log("GetContextValue failed", log: CryptMechanism.log, type: .error)
        return nil;
      }
      guard let length = ptr.pointee?.pointee.length else {
        os_log("length failed to unwrap", log: CryptMechanism.log, type: .error)
        return nil
      }
      guard let buffer = ptr.pointee?.pointee.data else {
        os_log("data failed to unwrap", log: CryptMechanism.log, type: .error)
        return nil
      }
      if (length == 0) {
        os_log("length is 0", log: CryptMechanism.log, type: .error)
        return nil
      }
      return Data.init(bytes: buffer, count: length)
    }
    os_log("getContextData success", log: CryptMechanism.log, type: .debug)
    return data
  }

  private func getHintData(key: AuthorizationString) -> Data? {
    os_log("getHintData called", log: CryptMechanism.log, type: .debug)
    var value: UnsafePointer<AuthorizationValue>?
    let data = withUnsafeMutablePointer(to: &value) { (ptr: UnsafeMutablePointer) -> Data? in
      if (self.mechanism.pointee.fPlugin.pointee.fCallbacks.pointee.GetHintValue(
        self.mechanism.pointee.fEngine, key, ptr) != errAuthorizationSuccess) {
        os_log("GetHintValue failed", log: CryptMechanism.log, type: .error)
        return nil;
      }
      guard let length = ptr.pointee?.pointee.length else {
        os_log("length failed to unwrap", log: CryptMechanism.log, type: .error)
        return nil
      }
      guard let buffer = ptr.pointee?.pointee.data else {
        os_log("data failed to unwrap", log: CryptMechanism.log, type: .error)
        return nil
      }
      if (length == 0) {
        os_log("length is 0", log: CryptMechanism.log, type: .error)
        return nil
      }
      return Data.init(bytes: buffer, count: length)
    }
    os_log("getHintData success", log: CryptMechanism.log, type: .debug)
    return data
  }

  private func setHintData(key: AuthorizationString, data: NSData) -> Bool {
    os_log("setHintData called", log: CryptMechanism.log, type: .debug)
    var value = AuthorizationValue(length: data.length ,
                                   data: UnsafeMutableRawPointer(mutating: data.bytes))
    return (self.mechanism.pointee.fPlugin.pointee.fCallbacks.pointee.SetHintValue(
      self.mechanism.pointee.fEngine, key, &value) != errAuthorizationSuccess)
  }

  var username: String? {
    get {
      os_log("username requested", log: CryptMechanism.log, type: .debug)
      guard let data = getContextData(key: kAuthorizationEnvironmentUsername) else {
        return nil
      }
      return String.init(data: data, encoding: String.Encoding.utf8)
    }
  }

  var password: String? {
    get {
      os_log("password requested", log: CryptMechanism.log, type: .debug)
      guard let data = getContextData(key: kAuthorizationEnvironmentPassword) else {
        return nil
      }
      return String.init(data: data, encoding: String.Encoding.utf8)
    }
  }

  var uid: UInt32 {
    get {
      os_log("uid requested", log: CryptMechanism.log, type: .debug)
      var uid: UInt32 = UInt32.max - 1 // nobody
      guard let data = getContextData(key: kAuthorizationEnvironmentUID) else {
        return uid
      }
      (data as NSData).getBytes(&uid, length: MemoryLayout<UInt32>.size)
      return uid
    }
  }

  var gid: UInt32 {
    get {
      os_log("gid requested", log: CryptMechanism.log, type: .debug)
      var gid: UInt32 = UInt32.max - 1 // nobody
      guard let data = getContextData(key: kAuthorizationEnvironmentGID) else {
        return gid
      }
      (data as NSData).getBytes(&gid, length: MemoryLayout<UInt32>.size)
      return gid
    }
  }

  var needsEncryption: Bool {
    set {
      os_log("needsEncryption set to %@", log: CryptMechanism.log, type: .debug, newValue as CVarArg)
      let data = NSKeyedArchiver.archivedData(withRootObject: NSNumber.init(value: newValue))
      _ = setHintData(key: needsEncryptionHintKey, data: data as NSData)
    }

    get {
      os_log("needsEncryption requested", log: CryptMechanism.log, type: .debug)
      guard let data = getHintData(key: needsEncryptionHintKey) else {
        return false
      }
      guard let value = NSKeyedUnarchiver.unarchiveObject(with: data) else {
        return false
      }
      return (value as! NSNumber).boolValue
    }
  }
}
