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

import Foundation

class CryptMechanism: NSObject {
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
    _ = self.mechanism.pointee.fPlugin.pointee.fCallbacks.pointee.SetResult(
      mechanism.pointee.fEngine, AuthorizationResult.allow)
  }

  private func getContextData(key: AuthorizationString) -> Data? {
    var value: UnsafePointer<AuthorizationValue>?
    let data = withUnsafeMutablePointer(to: &value) { (ptr: UnsafeMutablePointer) -> Data? in
      var flags = AuthorizationContextFlags()
      if (self.mechanism.pointee.fPlugin.pointee.fCallbacks.pointee.GetContextValue(
        self.mechanism.pointee.fEngine, key, &flags, ptr) != errAuthorizationSuccess) {
        return nil;
      }
      guard let length = ptr.pointee?.pointee.length else {
        return nil
      }
      guard let buffer = ptr.pointee?.pointee.data else {
        return nil
      }
      if (length == 0) {
        return nil
      }
      return Data.init(bytes: buffer, count: length)
    }
    return data
  }

  private func getHintData(key: AuthorizationString) -> Data? {
    var value: UnsafePointer<AuthorizationValue>?
    let data = withUnsafeMutablePointer(to: &value) { (ptr: UnsafeMutablePointer) -> Data? in
      if (self.mechanism.pointee.fPlugin.pointee.fCallbacks.pointee.GetHintValue(
        self.mechanism.pointee.fEngine, key, ptr) != errAuthorizationSuccess) {
        return nil;
      }
      guard let length = ptr.pointee?.pointee.length else {
        return nil
      }
      guard let buffer = ptr.pointee?.pointee.data else {
        return nil
      }
      if (length == 0) {
        return nil
      }
      return Data.init(bytes: buffer, count: length)
    }
    return data
  }

  private func setHintData(key: AuthorizationString, data: NSData) -> Bool {
    var value = AuthorizationValue(length: data.length ,
                                   data: UnsafeMutableRawPointer(mutating: data.bytes))
    return (self.mechanism.pointee.fPlugin.pointee.fCallbacks.pointee.SetHintValue(
      self.mechanism.pointee.fEngine, key, &value) != errAuthorizationSuccess)
  }

  var username: String? {
    get {
      guard let data = getContextData(key: kAuthorizationEnvironmentUsername) else {
        return nil
      }
      return String.init(data: data, encoding: String.Encoding.utf8)
    }
  }

  var password: String? {
    get {
      guard let data = getContextData(key: kAuthorizationEnvironmentPassword) else {
        return nil
      }
      return String.init(data: data, encoding: String.Encoding.utf8)
    }
  }

  var uid: UInt32 {
    get {
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
      let data = NSKeyedArchiver.archivedData(withRootObject: NSNumber.init(value: newValue))
      _ = setHintData(key: needsEncryptionHintKey, data: data as NSData)
    }

    get {
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
