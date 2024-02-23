/*
  Crypt

  Copyright 2024 The Crypt Project.

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
  @objc func run() {

    if self.needsEncryption {

      os_log("Attempting to enable FileVault", log: Enablement.log, type: .default)

      guard let username = self.username
        else { allowLogin(); return }
      guard let password = self.password
        else { allowLogin(); return }

      if getFVEnabled().encrypted && needToRestart() {
        // This is a catch for if we are on 10.13+ but on HFS.
        os_log("FileVault is enabled already and `fdesetup status` requests a restart", log: Enablement.log, type: .default)
        _ = restartMac()
      }
      let the_settings = NSDictionary.init(dictionary: ["Username" : username, "Password" : password])
      let filepath = CFPreferencesCopyAppValue(Preferences.outputPath as CFString, bundleid as CFString) as? String ?? "/private/var/root/crypt_output.plist"
      do {
        _ = try enableFileVault(the_settings, filepath: filepath)
        _ = restartMac()
      }
      catch let error as NSError {
        os_log("Failed to Enable FileVault %{public}@", log: Enablement.log, type: .error, error.localizedDescription)
        allowLogin()
      }
    } else {
      // Allow to login. End of mechanism
      os_log("Hint Value not set Allowing Login...", log: Enablement.log, type: .default)
      allowLogin()
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
}
