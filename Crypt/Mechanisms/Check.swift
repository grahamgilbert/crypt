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
import CoreFoundation
import os.log

class Check: CryptMechanism {
  // Log for the Check functions
  private static let log = OSLog(subsystem: "com.grahamgilbert.crypt", category: "Check")

  // Preference bundle id
  fileprivate let bundleid = "com.grahamgilbert.crypt"
  
  // XPC service name
  fileprivate let fdeAddUserService = "com.grahamgilbert.FDEAddUserService"

  func run() {
    os_log("executing run() in Crypt.Check", log: Check.log, type: .info)
    
    let filepath = CFPreferencesCopyAppValue(Preferences.outputPath as CFString, bundleid as CFString) as? String ?? "/private/var/root/crypt_output.plist"
    os_log("OutPutPlist Prefences is set to %@", log: Check.log, type: .info, filepath)
    let serverURL : NSString? = getServerURL()
    if let url = serverURL {
      os_log("ServerURL Prefences is set to %@", log: Check.log, type: .info, url)
    } else {
      os_log("ServerURL is not set", log: Check.log, type: .info)
    }
    let fvEnabled : Bool = getFVEnabled()
    let skipUsers : Bool = getSkipUsers()
    let addUser : Bool = getAddUserPreference()
    let rotateKey: Bool = getRotateUsedKeyPreference()
    let removePlist: Bool = getRemovePlistKeyPreference()
    let recoveryKeyExists: Bool = checkFileExists(path: filepath)
    let decrypting: Bool = getDecryptionStatus()
    //let usedKey: Bool = getUsedKey()
    //let onPatchedVersion: Bool = ProcessInfo().isOperatingSystemAtLeast(OperatingSystemVersion.init(majorVersion: 10, minorVersion: 12, patchVersion: 4))

    skipUsers ? os_log("Found users to skip", log: Check.log, type: .info) : os_log("No Users to Skip", log: Check.log, type: .info)
    rotateKey ? os_log("Set to rotate key", log: Check.log, type: .info) : os_log("Not set to rotate key", log: Check.log, type: .info)
    recoveryKeyExists ? os_log("Recovery Key was found on disk...", log: Check.log, type: .info) : os_log("Recovery Key was found on disk...", log: Check.log, type: .info)
    removePlist ? os_log("RemovePlist Pref is set to True...", log: Check.log, type: .info) : os_log("RemovePlist Pref is set to False..", log: Check.log, type: .info)

    guard let username = self.username
      else { _ = allowLogin(); return }
    guard let password = self.password
      else { _ = allowLogin(); return }

    let the_settings = NSDictionary.init(dictionary: ["Username" : username, "Password" : password])
    
    if fvEnabled {
      os_log("FileVault is On.", log: Check.log, type: .info)
      
      // If we are decrypting we can't do anything
      if decrypting {
        // If we are decrypting we can't do anything so we can just log in
        os_log("We are Decrypting! We are not wanted here...", log: Check.log, type: .info)
        _ = allowLogin()
        _ = setBoolHintValue(false)
        return;
      }
      
      os_log("Not Decrypting", log: Check.log, type: .info)
      
      if !recoveryKeyExists && !removePlist {
        // If key is missing from disk and we aren't supposed to remove it we should generate a new key...
        os_log("Key is missing when its not supposed to present. Attempting to generate a new one...", log: Check.log, type: .info)
        do {
          try _ = rotateRecoveryKey(the_settings, filepath: filepath)
        } catch let error as NSError {
          os_log("Caught error trying to rotate recovery key: %@", log: Check.log, type: .info, error)
          _ = allowLogin()
          _ = setBoolHintValue(false)
          return;
        }
      }

//      // Feature was supposed to be fixed here "support.apple.com/en-us/HT207536" but it wasn't
//      // Leaving code incase it gets fixed eventually
//      // Check to see if we used the key to unlock the disk, rotate if configured to.
//      if rotateKey && usedKey && onPatchedVersion {
//        os_log("Used key to unlock, need to rotate", log: Check.log, type: .info)
//        do {
//          try _ = rotateRecoveryKey(the_settings, filepath: filepath)
//        } catch let error as NSError {
//          os_log("Caught error trying to rotate recovery key: %@", log: Check.log, type: .info, error)
//          _ = allowLogin()
//        }
//      }

      

//      if let keyRotateDays = CFPreferencesCopyAppValue(Preferences.keyRotateDays as CFString, bundleid as CFString) {
//
//        let prefs = try! Data.init(contentsOf: URL(fileURLWithPath: filepath))
//
//        let prefsDict = prefs as! Dictionary<String, Any>
//
//        let lastDate = prefsDict["EnabledDate"] as! Date
//
//        if (Double(keyRotateDays as! NSNumber) * 24 * 60 * 60 ) < lastDate.timeIntervalSince(lastDate) {
//          do {
//            _ = try rotateRecoveryKey(the_settings, filepath: filepath)
//          }
//          catch let error as NSError {
//            NSLog("%@", error)
//            _ = allowLogin()
//          }
//        }
//      }

      if addUser && !skipUsers {
        os_log("Adding new User to FileVault", log: Check.log, type: .info)
        fdeAddUser(self.username, password: self.password)
      }
      
      os_log("All checks for an encypted machine have passed, Allowing Login...", log: Check.log, type: .info)
      _ = setBoolHintValue(false)
      _ = allowLogin()
    }
    else if skipUsers {
      os_log("Logged in User is in the Skip List... Not enforcing FileVault...", log: Check.log, type: .info)
      _ = setBoolHintValue(false)
      _ = allowLogin()
    }
    else if (serverURL == nil) {
      //Should we acutally do this?
      os_log("Couldn't find ServerURL Pref choosing not to do enable FileVault", log: Check.log, type: .info)
      _ = setBoolHintValue(false)
      _ = allowLogin()
    }
    else {
      os_log("FileVault is not enabled, Setting to enable...", log: Check.log, type: .info)
      _ = setBoolHintValue(true)
    }
  }

  // fdesetup Errors
  enum FileVaultError: Error {
    case fdeSetupFailed(retCode: Int32)
    case outputPlistNull
    case outputPlistMalformed
  }

  fileprivate func getFVEnabled() -> Bool {
    os_log("Checking to see if FileVault is enabled..", log: Check.log, type: .info)
    let task = Process();
    task.launchPath = "/usr/bin/fdesetup"
    task.arguments = ["status"]
    let pipe = Pipe()
    task.standardOutput = pipe
    task.launch()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    guard let output: String = String(data: data, encoding: String.Encoding.utf8)
      else { return false }
    if ((output.range(of: "FileVault is On.")) != nil) {
      return true
    } else if (output.range(of: "Decryption in progress:") != nil) {
      return true
    } else {
      return false
    }
  }
  
  fileprivate func getDecryptionStatus() -> Bool {
    os_log("Checking to see if Decrypting", log: Check.log, type: .info)
    let task = Process();
    task.launchPath = "/usr/bin/fdesetup"
    task.arguments = ["status"]
    let pipe = Pipe()
    task.standardOutput = pipe
    task.launch()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    guard let output: String = String(data: data, encoding: String.Encoding.utf8)
      else { return false }
    return (output.range(of: "Decryption in progress:") != nil)
  }

  fileprivate func getUsedKey() -> Bool {
    let task = Process();
    task.launchPath = "/usr/bin/fdesetup"
    task.arguments = ["usingrecoverykey"]
    let pipe = Pipe()
    task.standardOutput = pipe
    task.launch()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    guard let output: String = String(data: data, encoding: String.Encoding.utf8)
      else { return false }
    return (output.range(of: "true") != nil)
  }

  func trim_string(_ the_string:String) -> String {
    let output = the_string.trimmingCharacters(
                     in: CharacterSet.whitespacesAndNewlines)
    NSLog("Trimming %@ to %@", the_string, output)
    return output
  }

  fileprivate func getSkipUsers() -> Bool {
    let uid : uid_t = self.uid
    NSLog("%u", uid)
    if (uid < 501) {
      return true
    }
    guard let prefValue = CFPreferencesCopyAppValue("SkipUsers" as CFString, bundleid as CFString) as? [String]
      else { return false }
    guard let username = self.username
      else { return false }
    for s in prefValue {
      if trim_string(s) == username as String {
        return true
      }
    }
    return false
  }

  fileprivate func getServerURL() -> NSString? {
    let preference = CFPreferencesCopyAppValue("ServerURL" as CFString, bundleid as CFString) as? NSString
    return (preference != nil) ? preference : nil
  }

  fileprivate func getAddUserPreference() -> Bool {
    guard let addUser : Bool = CFPreferencesCopyAppValue("FDEAddUser" as CFString, bundleid as CFString) as? Bool
      else { return false }
    return addUser
  }

  fileprivate func getRotateUsedKeyPreference() -> Bool {
    guard let rotatekey : Bool = CFPreferencesCopyAppValue("RotateUsedKey" as CFString, bundleid as CFString) as? Bool
      else { return false }
    return rotatekey
  }

  fileprivate func getRemovePlistKeyPreference() -> Bool {
    guard let removeplist : Bool = CFPreferencesCopyAppValue(Preferences.removePlist as CFString, bundleid as CFString) as? Bool
      else { return true }
    return removeplist
  }
  
  fileprivate func fdeAddUser(_ username: NSString?, password: NSString?) {
    guard let username = username as String?
      else { return }
    guard let password = password as String?
      else { return }
    let connection = NSXPCConnection.init(serviceName: fdeAddUserService)
    connection.remoteObjectInterface = NSXPCInterface(with: FDEAddUserServiceProtocol.self)
    connection.resume()
    let service = connection.remoteObjectProxyWithErrorHandler {  error in
      NSLog("Crypt:MechanismInvoke: %@ Connection Error", self.fdeAddUserService);
    } as! FDEAddUserServiceProtocol
    
    service.odfdeAddUser(username, withPassword: password, withReply: { ret in
      NSLog("Crypt:MechanismInvoke: FDEAddUser %@", ret ? "Success" : "Fail")
    })
  }

  func rotateRecoveryKey(_ theSettings : NSDictionary, filepath : String) throws -> Bool {
    os_log("called rotateRecoveryKey()", log: Check.log, type: .info)
    let inputPlist = try PropertyListSerialization.data(fromPropertyList: theSettings,
                                                        format: PropertyListSerialization.PropertyListFormat.xml, options: 0)

    let inPipe = Pipe.init()
    let outPipe = Pipe.init()

    let task = Process.init()
    task.launchPath = "/usr/bin/fdesetup"
    task.arguments = ["changerecovery", "-personal", "-outputplist", "-inputplist"]
    task.standardInput = inPipe
    task.standardOutput = outPipe
    task.launch()
    inPipe.fileHandleForWriting.write(inputPlist)
    inPipe.fileHandleForWriting.closeFile()
    task.waitUntilExit()
    
    if task.terminationStatus != 0 {
       os_log("rotate terminationStatus wasn't 0", log: Check.log, type: .info)
      throw FileVaultError.fdeSetupFailed(retCode: task.terminationStatus)
    }
    
    os_log("Trying to get output data", log: Check.log, type: .info)
    let outputData = outPipe.fileHandleForReading.readDataToEndOfFile()
    outPipe.fileHandleForReading.closeFile()
    
    if outputData.count == 0 {
      os_log("Found nothing in output data", log: Check.log, type: .error)
      throw FileVaultError.outputPlistNull
    }
    
    var format : PropertyListSerialization.PropertyListFormat = PropertyListSerialization.PropertyListFormat.xml
    let outputPlist = try PropertyListSerialization.propertyList(from: outputData,
                                                                 options: PropertyListSerialization.MutabilityOptions(), format: &format)
    
    if (format == PropertyListSerialization.PropertyListFormat.xml) {
      if outputPlist is NSDictionary {
        os_log("Attempting to write key to: %@", log: Check.log, type: .info, filepath)
        _ = (outputPlist as! NSDictionary).write(toFile: filepath, atomically: true)
      }
      
      return true
    } else {
      os_log("format does not equal 'PropertyListSerialization.PropertyListFormat.xml'", log: Check.log, type: .info)
      throw FileVaultError.outputPlistMalformed
    }
  }
  
  func checkFileExists(path: String) -> Bool {
    os_log("running checkFileExists()", log: Check.log, type: .info)
    let fm = FileManager.default
    if fm.fileExists(atPath: path) {
      return true
    } else {
      return false
    }
  }
}
