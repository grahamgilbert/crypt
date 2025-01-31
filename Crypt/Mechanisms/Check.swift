/*
  Crypt

  Copyright 2025 The Crypt Project.

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

class Check: Crypt {

  @objc func run() {
    os_log("Starting run of Crypt.Check...", log: checkLog, type: .default)

    // check for ServerUrl
    let serverURL = (getPref(key: .ServerURL) as? NSString) ?? nil

    guard let username = self.username
      else { allowLogin(); return }
    guard let password = self.password
      else { allowLogin(); return }
    let the_settings = NSDictionary.init(dictionary: ["Username": username, "Password": password])
    // check for SkipUsers Preference
    let skipUsers: Bool = getSkipUsers(username: username as String)
    // Get status on encryption.
    let fdestatus = getFVEnabled()
    let fvEnabled: Bool = fdestatus.encrypted
    let decrypting: Bool = fdestatus.decrypting
    let filepath = getPref(key: .OutputPath) as! String
    os_log("OutPutPlist Preferences is set to %{public}@", log: checkLog, type: .default, String(describing: filepath))

    if decrypting {
      // If we are decrypting we can't do anything so we can just log in
      os_log("We are Decrypting! Not much we can do, exiting for safety...", log: checkLog, type: .error)
      allowLogin()
      return
    }

    if fvEnabled {
      // FileVault is enabled, checks for things to do if FileVault is enabled should be done here.

      // Check for RotateUsedKey Preference
      let rotateKey = getPref(key: .RotateUsedKey) as! Bool
      os_log("RotateUsedKey Preferences is set to %{public}@", log: checkLog, type: .default, String(describing: rotateKey))

      // Check for RemovePlist Preferences
      let removePlist = getPref(key: .RemovePlist) as! Bool
      os_log("RemovePlist Preferences is set to %{public}@", log: checkLog, type: .default, String(describing: removePlist))

      let useKeychain = getPref(key: .StoreRecoveryKeyInKeychain) as! Bool

      // Check to see if we have a recovery key somewhere
      let recoveryKeyExists: Bool = hasRecoveryKey(path: filepath, useKeychain: useKeychain)
      let generateKey = getPref(key: .GenerateNewKey) as! Bool
      let alreadyGeneratedKey = getPref(key: .RotatedKey) as! Bool

      if (!recoveryKeyExists && !removePlist && rotateKey) || generateKey {
        if alreadyGeneratedKey {
          os_log("We've already generated a new key. If you wish to generate another key please remove RotatedKey from preferences...", log: checkLog, type: .default)
          allowLogin()
          return
        }
        // If key is missing from disk and we aren't supposed to remove it we should generate a new key...
        os_log("Conditions for making a new key have been met. Attempting to generate a new key...", log: checkLog, type: .default)
        do {
          try _ = rotateRecoveryKey(the_settings, filepath: filepath)
        } catch let error as NSError {
          os_log("Caught error trying to rotate recovery key: %{public}@", log: checkLog, type: .error, error.localizedDescription)
          allowLogin()
          return
        }

        if generateKey {
          os_log("We've rotated the key and GenerateNewKey was True, setting to RotatedKey to avoid multiple generations", log: checkLog, type: .default)
          // set to false for house keeping, setPref will also sync to disk
          _ = setPref(key: .RotatedKey, value: true)
        }
        allowLogin()
        return
      }

      os_log("All checks for an encrypted machine have passed, Allowing Login...", log: checkLog, type: .default)
      allowLogin()
      return
    // end of fvEnabled
    } else if skipUsers {
      os_log("Logged in User is in the Skip List... Not enforcing FileVault...", log: checkLog, type: .error)

      allowLogin()
      return
    } else if serverURL == nil {
      // Should we acutally do this?
      os_log("Couldn't find ServerURL Pref choosing not to enable FileVault...", log: checkLog, type: .error)
      allowLogin()
      return
    }
    os_log("FileVault is not enabled, attempting to enable...", log: checkLog, type: .default)
    do {
      try _ = enableFileVault(the_settings, filepath: filepath)
    } catch let error as NSError {
      os_log("Caught error trying to Enable FileVault: %{public}@", log: checkLog, type: .error, String(describing: error.localizedDescription))
    }

    allowLogin()
    return
  }
}
