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
    os_log("Starting run of Crypt.Check...", log: Check.log, type: .default)
    
    // check for ServerUrl
    let serverURL : NSString? = getServerURL()
 
    // check for SkipUsers Preference
    let skipUsers : Bool = getSkipUsers()
    
    // check for users to add that might not be enabled. Will probably no longer work on 10.13 APFS.
    let addUser : Bool = getAddUserPreference()
    
    guard let username = self.username
      else { _ = allowLogin(); return }
    guard let password = self.password
      else { _ = allowLogin(); return }
    
    let the_settings = NSDictionary.init(dictionary: ["Username" : username, "Password" : password])
    
    //Get status on encryption.
    let fdestatus = getFVEnabled()
    let fvEnabled : Bool = fdestatus.encrypted
    let decrypting : Bool = fdestatus.decrypting
    let filepath = CFPreferencesCopyAppValue(Preferences.outputPath as CFString, bundleid as CFString) as? String ?? "/private/var/root/crypt_output.plist"
    os_log("OutPutPlist Prefences is set to %{public}@", log: Check.log, type: .default, String(describing: filepath))
    
    if decrypting {
      // If we are decrypting we can't do anything so we can just log in
      os_log("We are Decrypting! Not much we can do, exiting for safety...", log: Check.log, type: .error)
      _ = setBoolHintValue(false)
      _ = allowLogin()
      return;
    }
    
    if fvEnabled {
      //FileVault is enabled, checks for things to do if FileVault is enabled should be done here.
      
      // Check for RotateUsedKey Preference
      let rotateKey: Bool = getRotateUsedKeyPreference()
      os_log("RotateUsedKey Prefences is set to %{public}@", log: Check.log, type: .default, String(describing: rotateKey))
      
      // Check for RemovePlist Preferences
      let removePlist: Bool = getRemovePlistKeyPreference()
      os_log("RemovePlist Prefences is set to %{public}@", log: Check.log, type: .default, String(describing: removePlist))
      
      // Check to see if our recovery key exists at the OutputPath Preference.
      let recoveryKeyExists: Bool = checkFileExists(path: filepath)
      
      if !recoveryKeyExists && !removePlist && rotateKey {
        // If key is missing from disk and we aren't supposed to remove it we should generate a new key...
        os_log("Key is missing at %{public}@, and RemovePlist is False. And RotateKey is True, Attempting to generate a new key...", log: Check.log, type: .error, String(describing: filepath))
        do {
          try _ = rotateRecoveryKey(the_settings, filepath: filepath)
        } catch let error as NSError {
          os_log("Caught error trying to rotate recovery key: %{public}@", log: Check.log, type: .error, error.localizedDescription)
        }
        _ = setBoolHintValue(false)
        _ = allowLogin()
        return;
      }

      //let usedKey: Bool = getUsedKey()
      //let onPatchedVersion: Bool = ProcessInfo().isOperatingSystemAtLeast(OperatingSystemVersion.init(majorVersion: 10, minorVersion: 12, patchVersion: 4))


//      // Feature was supposed to be fixed here "support.apple.com/en-us/HT207536" but it wasn't
//      // Leaving code incase it gets fixed eventually
//      // Check to see if we used the key to unlock the disk, rotate if configured to.
//      if rotateKey && usedKey && onPatchedVersion {
//        os_log("Used key to unlock, need to rotate", log: Check.log, type: .default)
//        do {
//          try _ = rotateRecoveryKey(the_settings, filepath: filepath)
//        } catch let error as NSError {
//          os_log("Caught error trying to rotate recovery key: %@", log: Check.log, type: .default, error)
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
        os_log("Attempting to add user %{public}@ to FileVault...", log: Check.log, type: .default, String(describing: username))
        fdeAddUser(username: self.username! as String, password: self.password! as String)
      }
      
      os_log("All checks for an encypted machine have passed, Allowing Login...", log: Check.log, type: .default)
      _ = setBoolHintValue(false)
      _ = allowLogin()
      return;
    // end of fvEnabled
    }
    else if skipUsers {
      os_log("Logged in User is in the Skip List... Not enforcing FileVault...", log: Check.log, type: .error)
      _ = setBoolHintValue(false)
      _ = allowLogin()
      return;
    }
    else if (serverURL == nil) {
      //Should we acutally do this?
      os_log("Couldn't find ServerURL Pref choosing not to enable FileVault...", log: Check.log, type: .error)
      _ = setBoolHintValue(false)
      _ = allowLogin()
      return;
    }
    else if onHighSierraOrNewer() && onAPFS() {
      // we're on high sierra we can just enable
      os_log("On High Sierra and not enabled. Starting Enablement...", log: Check.log, type: .default)
      do {
        try _ = enableFileVault(the_settings, filepath: filepath)
      } catch let error as NSError {
        os_log("Caught error trying to Enable FileVault on High Sierra: %{public}@", log: Check.log, type: .error, String(describing: error.localizedDescription))
      }
      if needToRestart() {
        _ = setBoolHintValue(true)
        return
      }
      _ = setBoolHintValue(false)
      _ = allowLogin()
      return;
    }
    else {
      os_log("FileVault is not enabled, Setting to enable...", log: Check.log, type: .error)
      _ = setBoolHintValue(true)
    }
  }

  // fdesetup Errors
  enum FileVaultError: Error {
    case fdeSetupFailed(retCode: Int32)
    case outputPlistNull
    case outputPlistMalformed
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
    os_log("Trimming %{public}@ to %{public}@", log: Check.log, type: .default,  String(describing: the_string), String(describing: output))
    return output
  }

  fileprivate func getSkipUsers() -> Bool {
    os_log("Checking for any SkipUsers...", log: Check.log, type: .default)
    guard let username = self.username
      else { return false }
    guard let prefValue = CFPreferencesCopyAppValue("SkipUsers" as CFString, bundleid as CFString) as? [String]
      else { return false }
    for s in prefValue {
      if trim_string(s) == username as String {
        os_log("Found %{public}@ in SkipUsers list...", log: Check.log, type: .error, String(describing: username))
        return true
      }
    }
    if username as String == "_mbsetupuser" {
      os_log("User is _mbsetupuser... Need to Skip...", log: Check.log, type: .error)
      return true
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
  
  private func fdeAddUser(username: String?, password: String?) {
    guard let username = username
      else { return }
    guard let password = password
      else { return }
    let connection = NSXPCConnection.init(serviceName: fdeAddUserService)
    connection.remoteObjectInterface = NSXPCInterface(with: FDEAddUserServiceProtocol.self)
    connection.resume()
    let service = connection.remoteObjectProxyWithErrorHandler { (error: Error) -> Void in
      os_log("Can not connect to FDEAddUserService", log: Check.log, type: .error)
      } as! FDEAddUserServiceProtocol
    service.odfdeAddUser(username, withPassword: password) { (ret: Bool) -> Void in
      os_log("FDEAddUser %{public}@", log: Check.log, type: .error, ret ? "Success" : "Fail")
      }
  }

  func rotateRecoveryKey(_ theSettings : NSDictionary, filepath : String) throws -> Bool {
    os_log("Attempting to Rotate Recovery Key...", log: Check.log, type: .default)
    let inputPlist = try PropertyListSerialization.data(fromPropertyList: theSettings,
                                                        format: PropertyListSerialization.PropertyListFormat.xml, options: 0)

    let inPipe = Pipe.init()
    let outPipe = Pipe.init()
    let errorPipe = Pipe.init()

    let task = Process.init()
    task.launchPath = "/usr/bin/fdesetup"
    task.arguments = ["changerecovery", "-personal", "-outputplist", "-inputplist"]
    task.standardInput = inPipe
    task.standardOutput = outPipe
    task.standardError = errorPipe
    task.launch()
    inPipe.fileHandleForWriting.write(inputPlist)
    inPipe.fileHandleForWriting.closeFile()
    task.waitUntilExit()
    
    let errorOut = errorPipe.fileHandleForReading.readDataToEndOfFile()
    let errorMessage = String(data: errorOut, encoding: .utf8)
    errorPipe.fileHandleForReading.closeFile()
    
    if task.terminationStatus != 0 {
      let termstatus = String(describing: task.terminationStatus)
      os_log("Error: fdesetup terminated with a NON-Zero exit status: %{public}@", log: Check.log, type: .error, termstatus)
      os_log("fdesetup Standard Error: %{public}@", log: Check.log, type: .error, String(describing: errorMessage))
      throw FileVaultError.fdeSetupFailed(retCode: task.terminationStatus)
    }
    
    os_log("Trying to get output data", log: Check.log, type: .default)
    let outputData = outPipe.fileHandleForReading.readDataToEndOfFile()
    outPipe.fileHandleForReading.closeFile()
    
    if outputData.count == 0 {
      os_log("Error: Found nothing in output data", log: Check.log, type: .error)
      throw FileVaultError.outputPlistNull
    }
    
    var format : PropertyListSerialization.PropertyListFormat = PropertyListSerialization.PropertyListFormat.xml
    let outputPlist = try PropertyListSerialization.propertyList(from: outputData,
                                                                 options: PropertyListSerialization.MutabilityOptions(), format: &format)
    
    if (format == PropertyListSerialization.PropertyListFormat.xml) {
      if outputPlist is NSDictionary {
        os_log("Attempting to write key to: %{public}@", log: Check.log, type: .default, String(describing: filepath))
        _ = (outputPlist as! NSDictionary).write(toFile: filepath, atomically: true)
      }
      os_log("Successfully wrote key to: %{public}@", log: Check.log, type: .default, String(describing: filepath))
      return true
    } else {
      os_log("rotateRecoveryKey() Error. Format does not equal 'PropertyListSerialization.PropertyListFormat.xml'", log: Check.log, type: .error)
      throw FileVaultError.outputPlistMalformed
    }
  }
}
