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

class Enablement: CryptMechanism {
  
  fileprivate let bundleid = "com.grahamgilbert.crypt"
  
  private static let log = OSLog(subsystem: "com.grahamgilbert.crypt", category: "Enablement")
  // This is the only public function. It will be called from the
  // ObjC AuthorizationPlugin class
  func run() {
    
    if getBoolHintValue() {
      
      os_log("Attempting to enable FileVault", log: Enablement.log, type: .default)
      
      guard let username = self.username
        else { allowLogin(); return }
      guard let password = self.password
        else { allowLogin(); return }
      
      let the_settings = NSDictionary.init(dictionary: ["Username" : username, "Password" : password])
      
      do {
        let outputPlist = try enableFileVault(the_settings)
        let filepath = CFPreferencesCopyAppValue(Preferences.outputPath as CFString, bundleid as CFString) as? String ?? "/private/var/root/crypt_output.plist"
        outputPlist.write(toFile: filepath, atomically: true)
        _ = restartMac()
      }
      catch let error as NSError {
        os_log("Failed to Enable FileVault %{public}@", log: Enablement.log, type: .error, error.localizedDescription)
        _ = allowLogin()
      }
      
    } else {
      // Allow to login. End of mechanism
      os_log("Hint Value not set Allowing Login...", log: Enablement.log, type: .default)
      _ = allowLogin()
    }
  }
  
  // Restart
  fileprivate func restartMac() -> Bool {
    // Wait a couple of seconds for everything to finish
    os_log("called restartMac()...", log: Enablement.log, type: .default)
    sleep(3)
    let task = Process();
    os_log("Restarting Mac after enabling FileVault...", log: Enablement.log, type: .default)
    task.launchPath = "/sbin/shutdown"
    task.arguments = ["-r", "now"]
    task.launch()
    return true
  }
  
  // fdesetup Errors
  enum FileVaultError: Error {
    case fdeSetupFailed(retCode: Int32)
    case outputPlistNull
    case outputPlistMalformed
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
      os_log("Authrestart capability is 'true', will authrestart as appropriate", log: Enablement.log, type: .default)
      return true
    }
    else {
      os_log("Authrestart capability is 'false', reverting to standard reboot", log: Enablement.log, type: .default)
      return false
    }
  }
  
  // check for Institutional Master keychain
  func checkInstitutionalRecoveryKey() -> Bool {
    os_log("Checking for Institutional key...", log: Enablement.log, type: .default)
    let fileManager = FileManager.default
    if fileManager.fileExists(atPath: "/Library/Keychains/FileVaultMaster.keychain") {
      os_log("Institutional key was found...", log: Enablement.log, type: .default)
      return true
    } else {
      os_log("Institutional key NOT found...", log: Enablement.log, type: .default)
      return false
    }
  }
  
  // fdesetup wrapper
  func enableFileVault(_ theSettings : NSDictionary) throws -> NSDictionary {
    let inputPlist = try PropertyListSerialization.data(fromPropertyList: theSettings,
      format: PropertyListSerialization.PropertyListFormat.xml, options: 0)
    
    let inPipe = Pipe.init()
    let outPipe = Pipe.init()
    
    let task = Process.init()
    task.launchPath = "/usr/bin/fdesetup"
    if checkAuthRestart() {
      os_log("Adding -authrestart to fdesetup arguments...", log: Enablement.log, type: .default)
      task.arguments = ["enable", "-authrestart", "-outputplist", "-inputplist"]
    }
    else {
      os_log("Using normal arguments for fdesetup...", log: Enablement.log, type: .default)
      task.arguments = ["enable", "-outputplist", "-inputplist"]
    }
    
    // if there's an IRK, need to add the -keychain argument
    if checkInstitutionalRecoveryKey() {
      os_log("Adding -keychain to list of fdesetup arguements since we found an Institutional key...", log: Enablement.log, type: .default)
      task.arguments?.append("-keychain")
    }
    
    task.standardInput = inPipe
    task.standardOutput = outPipe
    task.launch()
    inPipe.fileHandleForWriting.write(inputPlist)
    inPipe.fileHandleForWriting.closeFile()
    task.waitUntilExit()
    
    if task.terminationStatus != 0 {
      let termstatus = String(describing: task.terminationStatus)
      let termreason = String(describing: task.terminationReason)
      os_log("fdesetup terminated with a NON-Zero exit status: %{public}@", log: Enablement.log, type: .error, termstatus)
      os_log("Termreason is: %{public}@", log: Enablement.log, type: .error, termreason)
      throw FileVaultError.fdeSetupFailed(retCode: task.terminationStatus)
    }
    
    os_log("Trying to get output data", log: Enablement.log, type: .default)
    let outputData = outPipe.fileHandleForReading.readDataToEndOfFile()
    outPipe.fileHandleForReading.closeFile()
    
    if outputData.count == 0 {
      os_log("Found nothing in output data", log: Enablement.log, type: .error)
      throw FileVaultError.outputPlistNull
    }
    
    var format : PropertyListSerialization.PropertyListFormat = PropertyListSerialization.PropertyListFormat.xml
    let outputPlist = try PropertyListSerialization.propertyList(from: outputData,
      options: PropertyListSerialization.MutabilityOptions(), format: &format)
    
    if (format == PropertyListSerialization.PropertyListFormat.xml) {
      return outputPlist as! NSDictionary
    } else {
      throw FileVaultError.outputPlistMalformed
    }
  }
}
