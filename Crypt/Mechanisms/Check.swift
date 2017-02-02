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

class Check: CryptMechanism {
  // Preference bundle id
  private let bundleid = "com.grahamgilbert.crypt"
  
  // XPC service name
  private let fdeAddUserService = "com.grahamgilbert.FDEAddUserService"
  
  func run(){
    NSLog("Crypt:Check running");
    
    let serverURL: String? = getServerURL()
    let fvEnabled: Bool = getFVEnabled()
    let skipUsers: Bool = getSkipUsers()
    let addUser: Bool = getAddUserPreference()
    
    if fvEnabled {
      NSLog("%@","Crypt:Check Filevault is enabled, encrypting or decrypting")
      if addUser && !skipUsers {
        NSLog("%@","Crypt:Check Adding user to FV2")
        fdeAddUser(username: self.username, password: self.password)
      }
      self.needsEncryption = false
    } else if skipUsers {
      NSLog("%@","Crypt:Check The user logging in is in the skip list. Not enforcing filevault")
      self.needsEncryption = false
    } else if (serverURL == nil) {
      NSLog("%@","Crypt:Check Failed to get Server URL for key escrow. Allowing login normally.")
      self.needsEncryption = false
    } else {
      self.needsEncryption = true
    }

    allowLogin()
  }
  
  private func getFVEnabled() -> Bool {
    let task = Process();
    task.launchPath = "/usr/bin/fdesetup"
    task.arguments = ["status"]
    let pipe = Pipe()
    task.standardOutput = pipe
    task.launch()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    guard let output = String(data: data, encoding: String.Encoding.utf8) else {
      return false
    }
    return !output.contains("FileVault is Off.")
  }

  private func getSkipUsers() -> Bool {
    let uid: uid_t = self.uid
    if (uid < 501 || uid == (UInt32.max - 1)) {
      return true
    }
    guard let prefValue =
      CFPreferencesCopyAppValue("SkipUsers" as CFString, bundleid as CFString) as? [String] else {
      return false
    }
    guard let username = self.username else {
      return false
    }
    if prefValue.contains(username) {
      return true
    }
    return false
  }
  
  private func getServerURL() -> String? {
    guard let s =
      CFPreferencesCopyAppValue("ServerURL" as CFString, bundleid as CFString) as? String? else {
      return nil
    }
    return s
  }
  
  private func getAddUserPreference() -> Bool {
    guard let addUser =
      CFPreferencesCopyAppValue("FDEAddUser" as CFString, bundleid as CFString) as? Bool else {
      return false
    }
    return addUser
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
      NSLog("Crypt:Check %@ Connection Error", self.fdeAddUserService);
    } as! FDEAddUserServiceProtocol
    service.odfdeAddUser(username, withPassword: password) { (ret: Bool) -> Void in
      NSLog("Crypt:Check FDEAddUser %@", ret ? "Success" : "Fail")
    }
  }
}
