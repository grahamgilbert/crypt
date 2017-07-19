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
    os_log("executing run() in Crypt.Enablement", log: Enablement.log, type: .info)
    guard let username = self.username
      else { _ = allowLogin(); return }
    guard let password = self.password
      else { _ = allowLogin(); return }
    
    let the_settings = NSDictionary.init(dictionary: ["Username" : username, "Password" : password])
    
    if getBoolHintValue() {
      
      
      do {
        let outputPlist = try enableFileVault(the_settings)
        let filepath = CFPreferencesCopyAppValue(Preferences.outputPath as CFString, bundleid as CFString) as? String ?? "/private/var/root/crypt_output.plist"
        outputPlist.write(toFile: filepath, atomically: true)
        _ = restartMac()
      }
      catch let error as NSError {
        NSLog("%@", error)
        _ = allowLogin()
      }
      
    } else {
      os_log("Hint value wasn't set...", log: Enablement.log, type: .error)
      // Allow to login. End of mechanism
      os_log("Allowing Login...", log: Enablement.log, type: .info)
      _ = allowLogin()
    }
  }
  
  // Restart
  fileprivate func restartMac() -> Bool {
    // Wait a couple of seconds for everything to finish
    os_log("Restarting in 3 seconds... Waiting for processes to finish...", log: Enablement.log, type: .info)
    sleep(3)
    os_log("Restarting Now... Bye...", log: Enablement.log, type: .info)
    let task = Process();
    task.launchPath = "/sbin/reboot"
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
    os_log("Checking if we can perform an AuthRestart...", log: Enablement.log, type: .info)
    let outPipe = Pipe.init()
    let authRestartCheck = Process.init()
    authRestartCheck.launchPath = "/usr/bin/fdesetup"
    authRestartCheck.arguments = ["supportsauthrestart"]
    authRestartCheck.standardOutput = outPipe
    authRestartCheck.launch()
    let outputData = outPipe.fileHandleForReading.availableData
    let outputString = String(data: outputData, encoding: String.Encoding.utf8) ?? ""
    if (outputString.range(of: "true") != nil) {
      os_log("We can perform AuthRestarts...", log: Enablement.log, type: .info)
      return true
    }
    else {
      os_log("We can NOT perform AuthRestarts...", log: Enablement.log, type: .error)
      return false
    }
  }
  
  // check for Institutional Master keychain
  func checkInstitutionalRecoveryKey() -> Bool {
    os_log("Checking for Institutional Recovery Key...", log: Enablement.log, type: .info)
    let fileManager = FileManager.default
    if fileManager.fileExists(atPath: "/Library/Keychains/FileVaultMaster.keychain") {
      os_log("Found Institutional Revoery Key...", log: Enablement.log, type: .info)
      return true
    } else {
      os_log("Did NOT find Institutional Revoery Key...", log: Enablement.log, type: .info)
      return false
    }
  }
  
  // fdesetup wrapper
  func enableFileVault(_ theSettings : NSDictionary) throws -> NSDictionary {
    let inputPlist = try PropertyListSerialization.data(fromPropertyList: theSettings,
      format: PropertyListSerialization.PropertyListFormat.xml, options: 0)
    
    os_log("Starting FileVault Enablement...", log: Enablement.log, type: .info)
    let inPipe = Pipe.init()
    let outPipe = Pipe.init()
    let task = Process.init()
    task.launchPath = "/usr/bin/fdesetup"
    if checkAuthRestart() {
      os_log("Performing enablement with the '-authrestart' flag...", log: Enablement.log, type: .info)
      task.arguments = ["enable", "-authrestart", "-outputplist", "-inputplist"]
    }
    else {
      os_log("Performing enablement WITHOUT the '-authrestart' flag...", log: Enablement.log, type: .info)
      task.arguments = ["enable", "-outputplist", "-inputplist"]
    }
    
    // if there's an IRK, need to add the -keychain argument
    if checkInstitutionalRecoveryKey() {
      os_log("Appending '-keychain' to enablement...", log: Enablement.log, type: .info)
      task.arguments?.append("-keychain")
    }
    
    task.standardInput = inPipe
    task.standardOutput = outPipe
    os_log("Launching Enablement Task...", log: Enablement.log, type: .info)
    task.launch()
    inPipe.fileHandleForWriting.write(inputPlist)
    inPipe.fileHandleForWriting.closeFile()
    task.waitUntilExit()
    
    if task.terminationStatus != 0 {
      os_log("fdesetup terminated with a NON-Zero exit status", log: Enablement.log, type: .error)
      throw FileVaultError.fdeSetupFailed(retCode: task.terminationStatus)
    }
    os_log("fdesetup terminated with a zero exit status", log: Enablement.log, type: .error)
    let outputData = outPipe.fileHandleForReading.readDataToEndOfFile()
    outPipe.fileHandleForReading.closeFile()
    
    if outputData.count == 0 {
      os_log("fdesetup output was empty...", log: Enablement.log, type: .error)
      throw FileVaultError.outputPlistNull
    }
    os_log("fdesetup output contains something... Thats good...", log: Enablement.log, type: .error)
    
    var format : PropertyListSerialization.PropertyListFormat = PropertyListSerialization.PropertyListFormat.xml
    let outputPlist = try PropertyListSerialization.propertyList(from: outputData,
      options: PropertyListSerialization.MutabilityOptions(), format: &format)
    
    if (format == PropertyListSerialization.PropertyListFormat.xml) {
      os_log("Returning outputPlist for writing...", log: Enablement.log, type: .info)
      return outputPlist as! NSDictionary
    } else {
      os_log("Capturing fdesetup output FAILED...", log: Enablement.log, type: .error)
      throw FileVaultError.outputPlistMalformed
    }
  }
}
