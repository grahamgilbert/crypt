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

class Enablement: CryptMechanism {
  
  fileprivate let bundleid = "com.grahamgilbert.crypt"
  
  // This is the only public function. It will be called from the
  // ObjC AuthorizationPlugin class
  func run() {
    guard let username = self.username
      else { allowLogin(); return }
    guard let password = self.password
      else { allowLogin(); return }
    
    let the_settings = NSDictionary.init(dictionary: ["Username" : username, "Password" : password])
    
    if getBoolHintValue() {
      
      NSLog("Attempting to Enable FileVault 2")
      
      do {
        let outputPlist = try enableFileVault(the_settings)
        let filepath = CFPreferencesCopyAppValue(Preferences.outputPath as CFString, bundleid as CFString) as? String ?? "/private/var/root/crypt_output.plist"
        outputPlist.write(toFile: filepath, atomically: true)
        restartMac()
      }
      catch let error as NSError {
        NSLog("%@", error)
        allowLogin()
      }
      
    } else {
      NSLog("Hint value wasn't set")
      // Allow to login. End of mechanism
      NSLog("Crypt:MechanismInvoke:Enablement:run:[+] allowLogin");
      allowLogin()
    }
  }
  
  // Restart
  fileprivate func restartMac() -> Bool {
    // Wait a couple of seconds for everything to finish
    sleep(3)
    let task = Process();
    NSLog("%@", "Restarting after enabling encryption")
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
    let outPipe = Pipe.init()
    let authRestartCheck = Process.init()
    authRestartCheck.launchPath = "/usr/bin/fdesetup"
    authRestartCheck.arguments = ["supportsauthrestart"]
    authRestartCheck.standardOutput = outPipe
    authRestartCheck.launch()
    let outputData = outPipe.fileHandleForReading.availableData
    let outputString = String(data: outputData, encoding: String.Encoding.utf8) ?? ""
    if (outputString.range(of: "true") != nil) {
      NSLog("Crypt:MechanismInvoke:Enablement:checkAuthRestart:[+] Authrestart capability is 'true', will authrestart as appropriate")
      return true
    }
    else {
      NSLog("Crypt:MechanismInvoke:Enablement:checkAuthRestart:[+] Authrestart capability is 'false', reverting to standard reboot")
      return false
    }
  }
  
  // check for Institutional Master keychain
  func checkInstitutionalRecoveryKey() -> Bool {
    let fileManager = FileManager.default
    if fileManager.fileExists(atPath: "/Library/Keychains/FileVaultMaster.keychain") {
      NSLog("Found institutional recovery key")
      return true
    } else {
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
      task.arguments = ["enable", "-authrestart", "-outputplist", "-inputplist"]
    }
    else {
      task.arguments = ["enable", "-outputplist", "-inputplist"]
    }
    
    // if there's an IRK, need to add the -keychain argument
    if checkInstitutionalRecoveryKey() {
      task.arguments?.append("-keychain")
    }
    
    task.standardInput = inPipe
    task.standardOutput = outPipe
    task.launch()
    inPipe.fileHandleForWriting.write(inputPlist)
    inPipe.fileHandleForWriting.closeFile()
    task.waitUntilExit()
    
    if task.terminationStatus != 0 {
      throw FileVaultError.fdeSetupFailed(retCode: task.terminationStatus)
    }
    
    let outputData = outPipe.fileHandleForReading.readDataToEndOfFile()
    outPipe.fileHandleForReading.closeFile()
    
    if outputData.count == 0 {
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
