/*
  Crypt

  Copyright 2016 The Crypt Project.

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
import Security

class CryptMechanism: NSObject {  
  // This NSString will be used as the domain for the inter-mechanism context data
  let contextCryptDomain : NSString = "com.grahamgilbert.crypt"
  
  // Define a pointer to the MechanismRecord. This will be used to get and set
  // all the inter-mechanism data. It is also used to allow or deny the login.
  var mechanism:UnsafePointer<MechanismRecord>
  
  // init the class with a MechanismRecord
  init(mechanism:UnsafePointer<MechanismRecord>) {
    NSLog("Crypt:MechanismInvoke:Check:[+] initWithMechanismRecord");
    self.mechanism = mechanism
  }
  
  var username: NSString? {
    get {
      var value : UnsafePointer<AuthorizationValue> = nil
      var flags = AuthorizationContextFlags()
      var err: OSStatus = noErr
      err = self.mechanism.memory.fPlugin.memory.fCallbacks.memory.GetContextValue(
        mechanism.memory.fEngine, kAuthorizationEnvironmentUsername, &flags, &value)
      if err != errSecSuccess {
        return nil
      }
      guard let username = NSString.init(bytes: value.memory.data,
        length: value.memory.length, encoding: NSUTF8StringEncoding)
        else { return nil }
      
      return username.stringByReplacingOccurrencesOfString("\0", withString: "")
    }
  }
  
  var password: NSString? {
    get {
      var value : UnsafePointer<AuthorizationValue> = nil
      var flags = AuthorizationContextFlags()
      var err: OSStatus = noErr
      err = self.mechanism.memory.fPlugin.memory.fCallbacks.memory.GetContextValue(
        mechanism.memory.fEngine, kAuthorizationEnvironmentPassword, &flags, &value)
      if err != errSecSuccess {
        return nil
      }
      guard let pass = NSString.init(bytes: value.memory.data,
        length: value.memory.length, encoding: NSUTF8StringEncoding)
        else { return nil }
      
      return pass.stringByReplacingOccurrencesOfString("\0", withString: "")
    }
  }
  
  var uid: uid_t {
    get {
      var value : UnsafePointer<AuthorizationValue> = nil
      var flags = AuthorizationContextFlags()
      var uid : uid_t = 0
      if (self.mechanism.memory.fPlugin.memory.fCallbacks.memory.GetContextValue(
              mechanism.memory.fEngine, ("uid" as NSString).UTF8String, &flags, &value)
              == errSecSuccess) {
          let uidData = NSData.init(bytes: value.memory.data, length: sizeof(uid_t))
          uidData.getBytes(&uid, length: sizeof(uid_t))
      }
      return uid
    }
  }
  
  func setBoolHintValue(encryptionWasEnabled : NSNumber) -> Bool {
    // Try and unwrap the optional NSData returned from archivedDataWithRootObject
    // This can be decoded on the other side with unarchiveObjectWithData
    guard let data : NSData = NSKeyedArchiver.archivedDataWithRootObject(encryptionWasEnabled)
      else {
        NSLog("Crypt:MechanismInvoke:Check:setHintValue:[+] Failed to unwrap data");
        return false
    }
    
    // Fill the AuthorizationValue struct with our data
    var value = AuthorizationValue(length: data.length,
      data: UnsafeMutablePointer<Void>(data.bytes))
    
    // Use the MechanismRecord SetHintValue callback to set the
    // inter-mechanism context data
    let err : OSStatus = self.mechanism.memory.fPlugin.memory.fCallbacks.memory.SetHintValue(
      self.mechanism.memory.fEngine, contextCryptDomain.UTF8String, &value)
    
    return (err == errSecSuccess)
  }
  
  // This is how we get the inter-mechanism context data
  func getBoolHintValue() -> Bool {
    var value : UnsafePointer<AuthorizationValue> = nil
    var err: OSStatus = noErr
    err = self.mechanism.memory.fPlugin.memory.fCallbacks.memory.GetHintValue(mechanism.memory.fEngine, contextCryptDomain.UTF8String, &value)
    if err != errSecSuccess {
      NSLog("%@","couldn't retrieve hint value")
      return false
    }
    let outputdata = NSData.init(bytes: value.memory.data, length: value.memory.length)
    guard let boolHint = NSKeyedUnarchiver.unarchiveObjectWithData(outputdata)
      else {
        NSLog("couldn't unpack hint value")
        return false
    }
    
    return boolHint.boolValue
  }
  
  // Allow the login. End of the mechanism
  func allowLogin() -> OSStatus {
    NSLog("Crypt:MechanismInvoke:Check:[+] Done. Thanks and have a lovely day.");
    var err: OSStatus = noErr
    err = self.mechanism.memory.fPlugin.memory.fCallbacks.memory.SetResult(
      mechanism.memory.fEngine, AuthorizationResult.Allow)
    NSLog("Crypt:MechanismInvoke:Check:[+] [%d]", Int(err));
    return err
  }
}
