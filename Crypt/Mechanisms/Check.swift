/*
  Check.swift
  Crypt

  Copyright 2015 The Crypt Project.

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

class Check: CryptMechanism {
  // Preference bundle id
  private let bundleid = "com.grahamgilbert.crypt"
  
  // XPC service name
  private let fdeAddUserService = "com.grahamgilbert.FDEAddUserService"
  
  func run(){
    NSLog("Crypt:MechanismInvoke:Check:run:[+]");
    
    let serverURL : NSString? = getServerURL()
    let fvEnabled : Bool = getFVEnabled()
    let skipUsers : Bool = getSkipUsers()
    let addUser : Bool = getAddUserPreference()
    
    if fvEnabled {
      NSLog("%@","Crypt:MechanismInvoke:Check:getFVEnabled:[+] Filevault is enabled, encrypting" +
          "or decrypting")
      if addUser && !skipUsers {
        NSLog("%@","Crypt:MechanismInvoke: Adding user to FV2")
        fdeAddUser(self.username, password: self.password)
      }
      setBoolHintValue(false)
      allowLogin()
    }
    else if skipUsers {
      NSLog("%@","Crypt:MechanismInvoke:Check:getSkipUsers:[+] The user logging in is in the skip" +
          "list. Not enforcing filevault")
      setBoolHintValue(false)
      allowLogin()
    }
    else if (serverURL == nil) {
      NSLog("%@","Crypt:MechanismInvoke:Check:getServerURL:[+] Failed to get Server URL for key" +
          "escrow. Allowing login normally.")
      setBoolHintValue(false)
      allowLogin()
    }
    else {
      setBoolHintValue(true)
    }
  }
  
  private func getFVEnabled() -> Bool {
    let task = NSTask();
    task.launchPath = "/usr/bin/fdesetup"
    task.arguments = ["status"]
    let pipe = NSPipe()
    task.standardOutput = pipe
    task.launch()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    guard let output: String = String(data: data, encoding: NSUTF8StringEncoding)
      else { return false }
    return (output.rangeOfString("FileVault is Off.") != nil) ? false : true
  }
  
  func trim_string(the_string:String) -> String {
    let output = the_string.stringByTrimmingCharactersInSet(
                     NSCharacterSet.whitespaceAndNewlineCharacterSet())
    NSLog("Trimming %@ to %@", the_string, output)
    return output
  }
  
  private func getSkipUsers() -> Bool {
    let uid : uid_t = self.uid
    NSLog("%u", uid)
    if (uid < 501) {
      return true
    }
    guard let prefValue = CFPreferencesCopyAppValue("SkipUsers", bundleid) as? [String]
      else { return false }
    guard let username = self.username
      else { return false }
    for s in prefValue {
      if trim_string(s) == username {
        return true
      }
    }
    return false
  }
  
  private func getServerURL() -> NSString? {
    let preference = CFPreferencesCopyAppValue("ServerURL", bundleid) as? NSString
    return (preference != nil) ? preference : nil
  }
  
  private func getAddUserPreference() -> Bool {
    guard let addUser : Bool = CFPreferencesCopyAppValue("FDEAddUser", bundleid) as? Bool
      else { return false }
    return addUser
  }
  
  private func fdeAddUser(username: NSString?, password: NSString?) {
    guard let username = username as? String
      else { return }
    guard let password = password as? String
      else { return }
    let connection = NSXPCConnection.init(serviceName: fdeAddUserService)
    connection.remoteObjectInterface = NSXPCInterface(withProtocol: FDEAddUserServiceProtocol.self)
    connection.resume()
    let service = connection.remoteObjectProxyWithErrorHandler { (error: NSError) -> Void in
      NSLog("Crypt:MechanismInvoke: %@ Connection Error", self.fdeAddUserService);
    } as! FDEAddUserServiceProtocol
    service.ODFDEAddUser(username, withPassword: password) { (ret: Bool) -> Void in
      NSLog("Crypt:MechanismInvoke: FDEAddUser %@", ret ? "Success" : "Fail")
    }
  }
}
