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
import os.log

class CryptMechanism: NSObject {  
  // This NSString will be used as the domain for the inter-mechanism context data
  let contextCryptDomain : NSString = "com.grahamgilbert.crypt"

  // Key for hint data
  private let needsEncryptionHintKey = "com.grahamgilbert.crypt.needsEncryption"
  
  // Log Crypt Mechanism
  private static let log = OSLog(subsystem: "com.grahamgilbert.crypt", category: "CryptMechanism")
  // Define a pointer to the MechanismRecord. This will be used to get and set
  // all the inter-mechanism data. It is also used to allow or deny the login.
  var mechanism:UnsafePointer<MechanismRecord>
  
  // init the class with a MechanismRecord
  init(mechanism:UnsafePointer<MechanismRecord>) {
    os_log("initWithMechanismRecord", log: CryptMechanism.log, type: .default)
    self.mechanism = mechanism
  }

  // Allow the login. End of the mechanism
  func allowLogin() {
    os_log("called allowLogin", log: CryptMechanism.log, type: .default)
    _ = self.mechanism.pointee.fPlugin.pointee.fCallbacks.pointee.SetResult(
      mechanism.pointee.fEngine, AuthorizationResult.allow)
  }

  private func getContextData(key: AuthorizationString) -> NSData? {
    os_log("getContextData called", log: CryptMechanism.log, type: .default)
    var value: UnsafePointer<AuthorizationValue>?
    let data = withUnsafeMutablePointer(to: &value) { (ptr: UnsafeMutablePointer) -> NSData? in
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
      return NSData.init(bytes: buffer, length: length)
    }
    os_log("getContextData success", log: CryptMechanism.log, type: .default)
    return data
  }

  private func getHintData(key: AuthorizationString) -> NSData? {
    os_log("getHintData called", log: CryptMechanism.log, type: .default)
    var value: UnsafePointer<AuthorizationValue>?
    let data = withUnsafeMutablePointer(to: &value) { (ptr: UnsafeMutablePointer) -> NSData? in
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
      return NSData.init(bytes: buffer, length: length)
    }
    os_log("getHintData success", log: CryptMechanism.log, type: .default)
    return data
  }

  private func setHintData(key: AuthorizationString, data: NSData) -> Bool {
    os_log("setHintData called", log: CryptMechanism.log, type: .default)
    var value = AuthorizationValue(length: data.length ,
                                   data: UnsafeMutableRawPointer(mutating: data.bytes))
    return (self.mechanism.pointee.fPlugin.pointee.fCallbacks.pointee.SetHintValue(
      self.mechanism.pointee.fEngine, key, &value) != errAuthorizationSuccess)
  }
  
  var username: NSString? {
    get {
      os_log("Requesting username...", log: CryptMechanism.log, type: .default)
      guard let data = getContextData(key: kAuthorizationEnvironmentUsername) else {
        return nil
      }
      guard let s = NSString.init(bytes: data.bytes,
                                  length: data.length,
                                  encoding: String.Encoding.utf8.rawValue)
        else { return nil }
      return s.replacingOccurrences(of: "\0", with: "") as NSString
    }
  }
  
  var password: NSString? {
    get {
      os_log("Requesting password...", log: CryptMechanism.log, type: .default)
      guard let data = getContextData(key: kAuthorizationEnvironmentPassword) else {
        return nil
      }
      guard let s = NSString.init(bytes: data.bytes,
                                  length: data.length,
                                  encoding: String.Encoding.utf8.rawValue)
        else { return nil }
      return s.replacingOccurrences(of: "\0", with: "") as NSString
    }
  }
  
  var uid: uid_t {
    get {
      os_log("Requesting uid...", log: CryptMechanism.log, type: .default)
      var uid: UInt32 = UInt32.max - 1 // nobody
      guard let data = getContextData(key: kAuthorizationEnvironmentUID) else {
        return uid
      }
      data.getBytes(&uid, length: MemoryLayout<UInt32>.size)
      return uid
    }
  }
  
  var needsEncryption: Bool {
    set {
      os_log("needsEncryption set to %@", log: CryptMechanism.log, type: .default, newValue as CVarArg)
      let data = NSKeyedArchiver.archivedData(withRootObject: NSNumber.init(value: newValue))
      _ = setHintData(key: needsEncryptionHintKey, data: data as NSData)
    }

    get {
      os_log("Requesting needsEncryption...", log: CryptMechanism.log, type: .default)
      guard let data = getHintData(key: needsEncryptionHintKey) else {
        return false
      }
      guard let value = NSKeyedUnarchiver.unarchiveObject(with: data as Data) else {
        return false
      }
      return (value as! NSNumber).boolValue
    }
  }

  func needToRestart() -> Bool {
    os_log("Checking to see if we need to restart now because we may not be on APFS", log: CryptMechanism.log, type: .default)
    let task = Process();
    task.launchPath = "/usr/bin/fdesetup"
    task.arguments = ["status"]
    let pipe = Pipe()
    task.standardOutput = pipe
    task.launch()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    guard let output: String = String(data: data, encoding: String.Encoding.utf8)
      else { return true }
    if ((output.range(of: "restart")) != nil) {
      os_log("Looks like we need to restart...", log: CryptMechanism.log, type: .default)
      return true
    } else {
      os_log("No restart needed.", log: CryptMechanism.log, type: .default)
      return false
    }
  }
  
  // check if on 10.13+
  func onHighSierraOrNewer() -> Bool {
    os_log("Checking to see if on 10.13+", log: CryptMechanism.log, type: .default)
    return ProcessInfo().isOperatingSystemAtLeast(OperatingSystemVersion.init(majorVersion: 10, minorVersion: 13, patchVersion: 0))
  }
  
  // check authrestart capability
  func checkAuthRestart() -> Bool {
    let outPipe = Pipe.init()
    let authRestartCheck = Process.init()
    authRestartCheck.launchPath = "/usr/bin/fdesetup"
    authRestartCheck.arguments = ["supportsauthrestart"]
    authRestartCheck.standardOutput = outPipe
    authRestartCheck.launch()
    let outputData = outPipe.fileHandleForReading.availableData
    let outputString = String(data: outputData, encoding: String.Encoding.utf8) ?? ""
    if (outputString.range(of: "true") != nil) {
      os_log("Authrestart capability is 'true', will authrestart as appropriate", log: CryptMechanism.log, type: .default)
      return true
    }
    else {
      os_log("Authrestart capability is 'false', reverting to standard reboot", log: CryptMechanism.log, type: .default)
      return false
    }
  }
  
  // fdesetup Errors
  private enum FileVaultError: Error {
    case fdeSetupFailed(retCode: Int32)
    case outputPlistNull
    case outputPlistMalformed
  }
  
  // Check if some information on filevault whether it's encrypted and if decrypting.
  func getFVEnabled() -> (encrypted: Bool, decrypting: Bool) {
    os_log("Checking the current status of FileVault..", log: CryptMechanism.log, type: .default)
    let task = Process();
    task.launchPath = "/usr/bin/fdesetup"
    task.arguments = ["status"]
    let pipe = Pipe()
    task.standardOutput = pipe
    task.launch()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    guard let output: String = String(data: data, encoding: String.Encoding.utf8)
      else { return (false, false) }
    if ((output.range(of: "FileVault is On.")) != nil) {
      os_log("Filevault is On...", log: CryptMechanism.log, type: .default)
      return (true, false)
    } else if (output.range(of: "Decryption in progress:") != nil) {
      os_log("FileVault Decryption in progress...", log: CryptMechanism.log, type: .error)
      return (true, true)
    } else {
      os_log("FileVault is not enabled...", log: CryptMechanism.log, type: .error)
      return (false, false)
    }
  }

  func enableFileVault(_ theSettings : NSDictionary, filepath : String) throws -> Bool {
    os_log("Attempting to enable FileVault", log: CryptMechanism.log, type: .default)
    let inputPlist = try PropertyListSerialization.data(fromPropertyList: theSettings,
                                                        format: PropertyListSerialization.PropertyListFormat.xml, options: 0)
    
    let inPipe = Pipe.init()
    let outPipe = Pipe.init()
    let errorPipe = Pipe.init()
    
    let task = Process.init()
    task.launchPath = "/usr/bin/fdesetup"
    task.arguments = ["enable", "-outputplist", "-inputplist"]
    
    // check if we should do an authrestart on enablement
    if checkAuthRestart() && !onAPFS(){
      os_log("adding -authrestart flag at index 1 of our task arguments...", log: CryptMechanism.log, type: .default)
      task.arguments?.insert("-authrestart", at: 1)
    }
    
    // if there's an IRK, need to add the -keychain argument to keep us from failing.
    let instKeyPath = "/Library/Keychains/FileVaultMaster.keychain"
    if checkFileExists(path: instKeyPath) {
      os_log("Appending -keychain to the end of our task arguments...", log: CryptMechanism.log, type: .default)
      task.arguments?.append("-keychain")
    }
    
    os_log("Running /usr/bin/fdesetup %{public}@", log: CryptMechanism.log, type: .default, String(describing: task.arguments))
    
    task.standardInput = inPipe
    task.standardOutput = outPipe
    task.standardError = errorPipe
    task.launch()
    inPipe.fileHandleForWriting.write(inputPlist)
    inPipe.fileHandleForWriting.closeFile()
    task.waitUntilExit()
    
    os_log("Trying to get output data", log: CryptMechanism.log, type: .default)
    let outputData = outPipe.fileHandleForReading.readDataToEndOfFile()
    outPipe.fileHandleForReading.closeFile()
    
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
    let errorMessage = String(data: errorData, encoding: .utf8)
    errorPipe.fileHandleForReading.closeFile()
    
    if task.terminationStatus != 0 {
      let termstatus = String(describing: task.terminationStatus)
      os_log("fdesetup terminated with a NON-Zero exit status: %{public}@", log: CryptMechanism.log, type: .error, termstatus)
      os_log("fdesetup Standard Error: %{public}@", log: CryptMechanism.log, type: .error, String(describing: errorMessage))
      throw FileVaultError.fdeSetupFailed(retCode: task.terminationStatus)
    }
    
    if outputData.count == 0 {
      os_log("Found nothing in output data", log: CryptMechanism.log, type: .error)
      throw FileVaultError.outputPlistNull
    }
    
    var format : PropertyListSerialization.PropertyListFormat = PropertyListSerialization.PropertyListFormat.xml
    let outputPlist = try PropertyListSerialization.propertyList(from: outputData,
                                                                 options: PropertyListSerialization.MutabilityOptions(), format: &format)
    
    if (format == PropertyListSerialization.PropertyListFormat.xml) {
      if outputPlist is NSDictionary {
        os_log("Attempting to write key to: %{public}@", log: CryptMechanism.log, type: .default, String(describing: filepath))
        _ = (outputPlist as! NSDictionary).write(toFile: filepath, atomically: true)
      }
      os_log("Successfully wrote key to: %{public}@", log: CryptMechanism.log, type: .default, String(describing: filepath))
      return true
    } else {
      os_log("rotateRecoveryKey() Error. Format does not equal 'PropertyListSerialization.PropertyListFormat.xml'", log: CryptMechanism.log, type: .error)
      throw FileVaultError.outputPlistMalformed
    }
  }
  
  func onAPFS() -> Bool {
    // checks to see if our boot drive is APFS
    let ws = NSWorkspace.shared
    
    var myDes: NSString? = nil
    var myType: NSString? = nil
    
    ws().getFileSystemInfo(forPath: "/", isRemovable: nil, isWritable: nil, isUnmountable: nil, description: &myDes, type: &myType)
    
    if myType == "apfs" {
      os_log("Machine appears to be APFS", log: CryptMechanism.log, type: .default)
      return true
    } else {
      os_log("Machine is not APFS we appear to be: %{public}@", log: CryptMechanism.log, type: .default, String(describing: myType))
      return false
    }
  }
  
  func checkFileExists(path: String) -> Bool {
    os_log("Checking to see if %{public}@ exists...", log: Check.log, type: .default, String(describing: path))
    let fm = FileManager.default
    if fm.fileExists(atPath: path) {
      os_log("%{public}@ exists...", log: Check.log, type: .default, String(describing: path))
      return true
    } else {
      os_log("%{public}@ does NOT exist...", log: Check.log, type: .default, String(describing: path))
      return false
    }
  }
}
