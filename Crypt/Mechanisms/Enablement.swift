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
        outputPlist.writeToFile("/private/var/root/crypt_output.plist", atomically: true)
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
  private func restartMac() -> Bool {
    // Wait a couple of seconds for everything to finish
    sleep(3)
    let task = NSTask();
    NSLog("%@", "Restarting after enabling encryption")
    task.launchPath = "/sbin/reboot"
    task.launch()
    return true
  }
  
  // fdesetup Errors
  enum FileVaultError: ErrorType {
    case FDESetupFailed(retCode: Int32)
    case OutputPlistNull
    case OutputPlistMalformed
  }
  
  // check authrestart capability
  func checkAuthRestart() -> Bool {
    let outPipe = NSPipe.init()
    let authRestartCheck = NSTask.init()
    authRestartCheck.launchPath = "/usr/bin/fdesetup"
    authRestartCheck.arguments = ["supportsauthrestart"]
    authRestartCheck.standardOutput = outPipe
    authRestartCheck.launch()
    let outputData = outPipe.fileHandleForReading.availableData
    let outputString = String(data: outputData, encoding: NSUTF8StringEncoding) ?? ""
    if (outputString.rangeOfString("true") != nil) {
      NSLog("Crypt:MechanismInvoke:Enablement:checkAuthRestart:[+] Authrestart capability is 'true', will authrestart as appropriate")
      return true
    }
    else {
      NSLog("Crypt:MechanismInvoke:Enablement:checkAuthRestart:[+] Authrestart capability is 'false', reverting to standard reboot")
      return false
    }
  }
  
  
  // fdesetup wrapper
  func enableFileVault(theSettings : NSDictionary) throws -> NSDictionary {
    let inputPlist = try NSPropertyListSerialization.dataWithPropertyList(theSettings,
      format: NSPropertyListFormat.XMLFormat_v1_0, options: 0)
    
    let inPipe = NSPipe.init()
    let outPipe = NSPipe.init()
    
    let task = NSTask.init()
    task.launchPath = "/usr/bin/fdesetup"
    if checkAuthRestart() {
      task.arguments = ["enable", "-authrestart", "-outputplist", "-inputplist"]
    }
    else {
      task.arguments = ["enable", "-outputplist", "-inputplist"]
    }
    task.standardInput = inPipe
    task.standardOutput = outPipe
    task.launch()
    inPipe.fileHandleForWriting.writeData(inputPlist)
    inPipe.fileHandleForWriting.closeFile()
    task.waitUntilExit()
    
    if task.terminationStatus != 0 {
      throw FileVaultError.FDESetupFailed(retCode: task.terminationStatus)
    }
    
    let outputData = outPipe.fileHandleForReading.readDataToEndOfFile()
    outPipe.fileHandleForReading.closeFile()
    
    if outputData.length == 0 {
      throw FileVaultError.OutputPlistNull
    }
    
    var format : NSPropertyListFormat = NSPropertyListFormat.XMLFormat_v1_0
    let outputPlist = try NSPropertyListSerialization.propertyListWithData(outputData,
      options: NSPropertyListReadOptions.Immutable, format: &format)
    
    if (format == NSPropertyListFormat.XMLFormat_v1_0) {
      return outputPlist as! NSDictionary
    } else {
      throw FileVaultError.OutputPlistMalformed
    }
  }
}
