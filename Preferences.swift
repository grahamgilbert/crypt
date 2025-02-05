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
import os.log

let cryptBundleID = "com.grahamgilbert.crypt"

enum Preference: String {
  case AppsAllowedToChangeKey
  case AppsAllowedToReadKey
  case GenerateNewKey
  case InvisibleInKeychain
  case KeychainUIPromptDescription
  case LastEscrow
  case OutputPath
  case RemovePlist
  case RotatedKey
  case RotateUsedKey
  case ServerURL
  case SkipUsers
  case StoreRecoveryKeyInKeychain
  case ValidateKey

  // Default preferences as a computed property
  static var defaultPreferences: [Preference: Any] {
    return [
      .AppsAllowedToChangeKey: [],
      .AppsAllowedToReadKey: ["/Library/Crypt/checkin"],
      .GenerateNewKey: false,
      .InvisibleInKeychain: false,
      .KeychainUIPromptDescription: "Crypt FileVault Recovery Key",
      .LastEscrow: Date(timeIntervalSince1970: 0),
      .OutputPath: "/var/root/crypt_output.plist",
      .RemovePlist: true,
      .RotateUsedKey: true,
      .RotatedKey: false,
      .SkipUsers: [],
      .StoreRecoveryKeyInKeychain: true,
      .ValidateKey: true
    ]
  }
}

/**
 Retrieves a preference value.
 
 This function first attempts to retrieve the value from the application preferences.
 If no value is found, it checks if the key exists in the default preferences dictionary.
 
 - Parameter key: The preference key to retrieve the value for.
 - Returns: The preference value, or nil if the key does not exist in either the application or default preferences.
 */
func getPref(key: Preference) -> Any? {

  os_log("Attempting to retrieve value for key: %{public}@", log: prefLog, type: .info, key.rawValue)

  // Get the value from the application preferences
  if let value = CFPreferencesCopyAppValue(key.rawValue as CFString, cryptBundleID as CFString) {
    os_log("Value found in application preferences for key: %{public}@", log: prefLog, type: .info, key.rawValue)
    return value
  }

  // If value is nil, check if the key exists in the default preferences dictionary
  if let defaultValue = Preference.defaultPreferences[key] {
    os_log("Value found in default preferences for key: %{public}@", log: prefLog, type: .info, key.rawValue)
    return defaultValue
  }
  os_log("Did not find a default for key: %{public}@, returning nil", log: prefLog, type: .info, key.rawValue)
  return nil
}

/**
 Retrieves a managed preference.
 
 This function checks the specified preference domain for a managed preference.
 If a preference is found, it logs the preference and checks if it is enforced.
 
 - Parameter key: The preference key to check.
 - Returns: A tuple containing the preference value and a boolean indicating if it is enforced, or nil if no preference is found.
 */
func getManagedPref(key: Preference) -> (Any?, Bool?) {

  os_log("Checking %{public}@ preference domain for managed preference.", type: .info, cryptBundleID)

  if let preference = getPref(key: key) as Any? {
    os_log("Found preference: %{public}@ with value: %{public}@", log: prefLog, type: .info, key.rawValue, String(describing: preference))

    if CFPreferencesAppValueIsForced(key.rawValue as CFString, cryptBundleID as CFString) {
      os_log("Preference %{public}@ is enforced.", log: prefLog, type: .info, key.rawValue)
      return (preference, true)
    }

    os_log("Preference %{public}@ is not enforced.", log: prefLog, type: .info, key.rawValue)
    return (preference, false)
  }

  os_log("No preference found for key: %{public}@", log: prefLog, type: .info, key.rawValue)
  return (nil, nil)
}

/// Sets a preference in the com.grahamgilbert.crypt domain
///
///
/// - Parameters:
///   - key: The string name of the key you want to set
///   - value: The value in Any that you want to set
///
/// - Returns: A Boolean of success.
func setPref(key: Preference, value: Any) -> Bool {
  Foundation.CFPreferencesSetValue(key.rawValue as CFString, value as CFPropertyList, cryptBundleID as CFString, kCFPreferencesAnyUser, kCFPreferencesCurrentHost)

  let syncStatus = CFPreferencesAppSynchronize(cryptBundleID as CFString)

  return syncStatus
}
