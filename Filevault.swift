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
  if outputString.range(of: "true") != nil {
    os_log("Authrestart capability is 'true', will authrestart as appropriate", log: filevaultLog, type: .default)
    return true
  } else {
    os_log("Authrestart capability is 'false', reverting to standard reboot", log: filevaultLog, type: .default)
    return false
  }
}

// Check if some information on filevault whether it's encrypted and if decrypting.
func getFVEnabled() -> (encrypted: Bool, decrypting: Bool) {
  os_log("Checking the current status of FileVault..", log: filevaultLog, type: .default)
  let task = Process()
  task.launchPath = "/usr/bin/fdesetup"
  task.arguments = ["status"]
  let pipe = Pipe()
  task.standardOutput = pipe
  task.launch()
  let data = pipe.fileHandleForReading.readDataToEndOfFile()
  guard let output: String = String(data: data, encoding: String.Encoding.utf8)
  else { return (false, false) }
  if (output.range(of: "FileVault is On.")) != nil {
    os_log("Filevault is On...", log: filevaultLog, type: .default)
    return (true, false)
  } else if output.range(of: "Decryption in progress:") != nil {
    os_log("FileVault Decryption in progress...", log: filevaultLog, type: .error)
    return (true, true)
  } else {
    os_log("FileVault is not enabled...", log: filevaultLog, type: .error)
    return (false, false)
  }
}

func enableFileVault(_ theSettings: NSDictionary, filepath: String) throws -> Bool {
  os_log("Attempting to enable FileVault", log: filevaultLog, type: .default)
  let inputPlist = try PropertyListSerialization.data(fromPropertyList: theSettings,
                                                      format: PropertyListSerialization.PropertyListFormat.xml, options: 0)

  let inPipe = Pipe.init()
  let outPipe = Pipe.init()
  let errorPipe = Pipe.init()

  let task = Process.init()
  task.launchPath = "/usr/bin/fdesetup"
  task.arguments = ["enable", "-outputplist", "-inputplist"]

//  // check if we should do an authrestart on enablement
//  if checkAuthRestart() {
//    os_log("adding -authrestart flag at index 1 of our task arguments...", log: filevaultLog, type: .default)
//    task.arguments?.insert("-authrestart", at: 1)
//  }

  // if there's an IRK, need to add the -keychain argument to keep us from failing.
  let instKeyPath = "/Library/Keychains/FileVaultMaster.keychain"
  if checkFileExists(path: instKeyPath) {
    os_log("Appending -keychain to the end of our task arguments...", log: filevaultLog, type: .default)
    task.arguments?.append("-keychain")
  }

  os_log("Running /usr/bin/fdesetup %{public}@", log: filevaultLog, type: .default, String(describing: task.arguments))

  task.standardInput = inPipe
  task.standardOutput = outPipe
  task.standardError = errorPipe
  task.launch()
  inPipe.fileHandleForWriting.write(inputPlist)
  inPipe.fileHandleForWriting.closeFile()
  task.waitUntilExit()

  os_log("Trying to get output data", log: filevaultLog, type: .default)
  let outputData = outPipe.fileHandleForReading.readDataToEndOfFile()
  outPipe.fileHandleForReading.closeFile()

  let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
  let errorMessage = String(data: errorData, encoding: .utf8)
  errorPipe.fileHandleForReading.closeFile()

  if task.terminationStatus != 0 {
    let termstatus = String(describing: task.terminationStatus)
    os_log("fdesetup terminated with a NON-Zero exit status: %{public}@", log: filevaultLog, type: .error, termstatus)
    os_log("fdesetup Standard Error: %{public}@", log: filevaultLog, type: .error, String(describing: errorMessage))
    throw FileVaultError.fdeSetupFailed(retCode: task.terminationStatus)
  }

  if outputData.count == 0 {
    os_log("Found nothing in output data", log: filevaultLog, type: .error)
    throw FileVaultError.outputPlistNull
  }

  // try to write the output to disk or the in the keychain depending on preferences set on the machine.
  return try handleFileVaultOutput(outputData: outputData, filepath: filepath)
}

/**
 Rotates the FileVault recovery key.
 
 This function attempts to rotate the FileVault recovery key using the provided settings.
 It serializes the settings to a property list, executes the `fdesetup` command to change the recovery key,
 and writes the new key to the specified file path if successful.
 
 - Parameters:
 - theSettings: A dictionary containing the settings for the `fdesetup` command.
 - filepath: The file path where the new recovery key should be written.
 - useKeychain: A boolean indicating whether to use the keychain.
 - Returns: A boolean indicating whether the key rotation was successful.
 - Throws: An error of type `FileVaultError` if the process fails.
 */
func rotateRecoveryKey(_ theSettings: NSDictionary, filepath: String) throws -> Bool {
  os_log("Attempting to Rotate Recovery Key...", log: filevaultLog, type: .default)

  let inputPlist = try PropertyListSerialization.data(fromPropertyList: theSettings,
                                                      format: .xml, options: 0)

  let inPipe = Pipe()
  let outPipe = Pipe()
  let errorPipe = Pipe()

  let task = Process()
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
    os_log("Error: fdesetup terminated with a NON-Zero exit status: %{public}@", log: filevaultLog, type: .error, termstatus)
    os_log("fdesetup Standard Error: %{public}@", log: filevaultLog, type: .error, String(describing: errorMessage))
    throw FileVaultError.fdeSetupFailed(retCode: task.terminationStatus)
  }

  os_log("Trying to get output data", log: filevaultLog, type: .default)
  let outputData = outPipe.fileHandleForReading.readDataToEndOfFile()
  outPipe.fileHandleForReading.closeFile()

  if outputData.count == 0 {
    os_log("Error: Found nothing in output data", log: filevaultLog, type: .error)
    throw FileVaultError.outputPlistNull
  }

  return try handleFileVaultOutput(outputData: outputData, filepath: filepath)

}

func checkFileExists(path: String) -> Bool {
  os_log("Checking to see if %{public}@ exists...", log: filevaultLog, type: .default, String(describing: path))
  let fm = FileManager.default
  if fm.fileExists(atPath: path) {
    os_log("%{public}@ exists...", log: filevaultLog, type: .default, String(describing: path))
    return true
  } else {
    os_log("%{public}@ does NOT exist...", log: filevaultLog, type: .default, String(describing: path))
    return false
  }
}

func hasRecoveryKey(path: String, useKeychain: Bool) -> Bool {
  if !useKeychain {
    return checkFileExists(path: path)
  }

  let label = "com.grahamgilbert.crypt.recovery"
  guard let recoveryKey = getPasswordFromKeychain(label: label) else {
    os_log("Recovery Key NOT found in keychain...", log: filevaultLog, type: .default)
    return false
  }

  os_log("Recovery Key found in keychain...", log: filevaultLog, type: .default)
  return true
}

/// Processes the output from a FileVault operation and handles the storage of recovery information
///
/// This function takes the output data from a FileVault operation and either stores the recovery key
/// in the system keychain or writes the entire output plist to disk, depending on preferences.
///
/// - Parameters:
///   - outputData: The data returned from the FileVault operation
///   - filepath: The path where the plist should be written if not using keychain storage
///
/// - Returns: A boolean indicating whether the operation was successful
///
/// - Throws: Errors that may occur during plist serialization or file writing operations
private func handleFileVaultOutput(outputData: Data, filepath: String) throws -> Bool {

  var format: PropertyListSerialization.PropertyListFormat = .xml

  // Deserialize the output data to a property list
  guard let outputPlist = try? PropertyListSerialization.propertyList(
    from: outputData,
    options: .mutableContainersAndLeaves,
    format: &format
  ) else {
    os_log("Error: Failed to deserialize output data", log: filevaultLog, type: .error)
    return false
  }

  // Cast the outputPlist to a dictionary
  guard let dictionary = outputPlist as? [String: Any] else {
    os_log("Error: Failed to cast the FileVault enablement output to a dictionary", log: filevaultLog, type: .error)
    return false
  }

  // Access the "RecoveryKey" from the dictionary we can use this to write to the keychain
  guard let recoveryKey = dictionary["RecoveryKey"] as? String else {
    os_log("Error: Could not find 'RecoveryKey' in the output", log: filevaultLog, type: .error)
    return false
  }

  // check if we are using the keychain if not we'll write it the the output file
  if getPref(key: .StoreRecoveryKeyInKeychain) as! Bool {
    let systemKeychainPath = "/Library/Keychains/System.keychain"
    var read_apps = getPref(key: .AppsAllowedToReadKey) as! [String]
    var change_apps = getPref(key: .AppsAllowedToChangeKey) as! [String]
    // we need to append empty strings into the arrays which will add the Authorization Framwork paths into lists so we can read and write the key later on.
    read_apps.append("")
    change_apps.append("")
    let invisible = getPref(key: .InvisibleInKeychain) as! Bool
    let label: String = "com.grahamgilbert.crypt.recovery"
    guard syncRecoveryKeyToKeychain(label: label, recoveryKey: recoveryKey, keychain: systemKeychainPath, apps: read_apps, owners: change_apps, makeInvisible: invisible) else {
      os_log("Error: Failed to sync recovery key to keychain.", log: filevaultLog, type: .error)
      return false
    }

    // We should clear the LastEscrow pref value so we queue up a sync at first run of checkin.
    _ = setPref(key: .LastEscrow, value: Date(timeIntervalSince1970: 0))
    return true
  }

  // if we aren't using the keychain write the data to disk.
  do {
    try (outputPlist as! NSDictionary).write(to: URL(filePath: filepath, directoryHint: .notDirectory))
    os_log("Successfully wrote output plist to %{public}@", log: filevaultLog, type: .default, filepath)
  } catch {
    os_log("Error writing output plist to disk: %{public}@", log: filevaultLog, type: .error, error.localizedDescription)
    return false
  }

  return true
}

private func getUsedKey() -> Bool {
  let task = Process()
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

func trim_string(_ the_string: String) -> String {
  let output = the_string.trimmingCharacters(
    in: CharacterSet.whitespacesAndNewlines)
  os_log("Trimming %{public}@ to %{public}@", log: checkLog, type: .default, String(describing: the_string), String(describing: output))
  return output
}

func getSkipUsers(username: String) -> Bool {
  os_log("Checking for any SkipUsers...", log: checkLog, type: .default)

  if username as String == "_mbsetupuser" {
    os_log("User is _mbsetupuser... Need to Skip...", log: checkLog, type: .error)
    return true
  }

  if username as String == "root" {
    os_log("User is root... Need to Skip...", log: checkLog, type: .error)
    return true
  }
  if let skipUsers = getPref(key: .SkipUsers) as? [String] {
    for user in skipUsers {
      if trim_string(user) == username as String {
        return true
      }
    }
  }
  return false
  }
