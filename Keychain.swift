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
import os.log

extension Data {

  init?(fromHexEncodedString string: String) {

    // Convert 0 ... 9, a ... f, A ...F to their decimal value,
    // return nil for all other input characters
    func decodeNibble(u: UInt16) -> UInt8? {
      switch u {
        case 0x30 ... 0x39:
          return UInt8(u - 0x30)
        case 0x41 ... 0x46:
          return UInt8(u - 0x41 + 10)
        case 0x61 ... 0x66:
          return UInt8(u - 0x61 + 10)
        default:
          return nil
      }
    }

    self.init(capacity: string.utf16.count/2)
    var even = true
    var byte: UInt8 = 0
    for c in string.utf16 {
      guard let val = decodeNibble(u: c) else { return nil }
      if even {
        byte = val << 4
      } else {
        byte += val
        self.append(byte)
      }
      even = !even
    }
    guard even else { return nil }
  }

  func hexEncodedString() -> String {
    return map { String(format: "%02hhx", $0) }.joined()
  }
}

/// Translates a keychain `OSStatus` error code into a human-readable string description.
///
/// This function attempts to convert an `OSStatus` error code, typically returned by
/// keychain operations, into a string that describes the error in an understandable format.
/// If the translation fails, it provides a default message with the error code.
///
/// - Parameter status: The `OSStatus` error code to be translated into a readable format.
/// - Returns: A `String` containing the human-readable description of the error code.
///            If translation is unsuccessful, a default message indicating "Unknown status" is returned.
///
/// - Note:
/// This function utilizes `SecCopyErrorMessageString` to perform the translation.
/// Logging is implemented to track the error code being translated for debugging purposes.
///
/// - Throws:
/// No Swift-level errors are thrown. Instead, the function logs the translation attempt
/// and provides a fallback message for unrecognized or non-translatable error codes.
public func translateErrCode(_ status: OSStatus) -> String {
  // converts a keychain OSStatus error code into human readable string.
  os_log("Attempting to translate Error Code: %{public}@",
         log: keychainLog, type: .default, String(describing: status))
  let message = SecCopyErrorMessageString(status, nil)
  return (message as? String) ?? "Unknown status: \(status)"
}

/// Adds a string to the specified keychain with an optional access control and visibility setting.
///
/// This function attempts to add a string as a generic password to a keychain item identified by
/// a label. It allows for optional invisibility and access control attributes to be specified.
///
/// - Parameters:
///   - item: The `String` data to be added to the keychain.
///   - label: A `String` that sets the label for the keychain item, used for identification.
///   - keychain: A `String` specifying the path of the keychain where the data should be stored.
///   - isInvisible: A `Bool` determining if the keychain item should be invisible in the interface. Defaults to `false`.
///   - withAccess: An optional `SecAccess` object for defining access control settings. Defaults to `nil` if no specific settings are required.
/// - Returns: A `Bool` indicating whether the operation was successful (`true`) or encountered an error (`false`).
///
/// - Note:
/// The function invokes `SecItemAdd` to add the string, and includes specific attributes like setting it
/// as invisible and adding custom access controls if provided. It logs operations and any errors, utilizing
/// utilities such as `getSecKeychain` to manage the keychain interactions.
///
/// - Throws:
/// This function does not throw Swift-level errors but logs messages for any issues encountered during
/// the process, including when it cannot open the keychain or fails to add the item due to error conditions.
func addStringToKeychain(stringToAdd item: String, withLabel label: String, keychain: String, isInvisible: Bool = false, withAccess: SecAccess? = nil) -> Bool {
  guard let secKeychain = getSecKeychain(path: keychain) else {
    return false
  }

  os_log("Attempting to add String to KeyChain with label: %{public}s", log: keychainLog, type: .default, label)
  let addition = item.data(using: String.Encoding.utf8)!
  var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                              kSecAttrLabel as String: label,
                              kSecValueData as String: addition,
                              kSecAttrComment as String: "FileVault recovery key generated by Crypt. Do NOT Delete!",
                              kSecAttrDescription as String: "recovery key",
                              kSecAttrIsInvisible as String: isInvisible,
                              kSecUseKeychain as String: secKeychain,
                              kSecAttrService as String: cryptBundleID,
                              kSecAttrAccount as String: cryptBundleID
  ]

  if withAccess != nil {
    query.updateValue(withAccess!, forKey: kSecAttrAccess as String)
  }

  let status = SecItemAdd(query as CFDictionary, nil)

  if status != errSecSuccess {
    os_log("Failed to add String to KeyChain with Error: %{public}s", log: keychainLog,
           type: .error, translateErrCode(status))
    return false
  }
  return true
}

/// Opens a keychain located at a given file path and returns a reference to it.
///
/// This function uses the provided path to fetch and open a keychain, returning
/// a `SecKeychain` reference if successful, or `nil` if the operation fails.
///
/// - Parameter path: A `String` representing the file system path to the keychain file.
/// - Returns: An optional `SecKeychain` reference to the opened keychain, or `nil` if
///            the opening operation fails.
///
/// - Note:
/// The function uses `SecKeychainOpen` to attempt to open keychain files, employing
/// detailed logging for both successful operations and failures, capturing any error
/// codes that arise during the process.
///
/// - Throws:
/// The function does not throw Swift-level errors but uses `os_log` for logging and
/// diagnostics, particularly when the keychain cannot be opened or when errors are encountered.
func getSecKeychain(path: String) -> SecKeychain? {
  os_log("Fetching keychain at path: [%{public}s], with getSecKeychain.", log: keychainLog, type: .default, path)

  var keychain: SecKeychain?

  let openStatus = SecKeychainOpen(path, &keychain)

  if openStatus != kOSReturnSuccess {
    os_log("Failed to open keychain with Error: %{public}s", log: keychainLog,
           type: .error, translateErrCode(openStatus))
    return nil
  }

  return keychain

}

/// Synchronizes a recovery key to the specified keychain with optional configurations for visibility and access control.
///
/// This function interacts with the macOS Keychain to add or update a recovery key, ensuring that the caller is also
/// added to the list of applications allowed to manage Access Control Lists (ACLs). It performs checks to avoid unnecessary updates and logs relevant details.
///
/// - Parameters:
///   - label: A unique label for the keychain item, used to identify the recovery key.
///   - recoveryKey: The recovery key string that needs to be synchronized with the keychain.
///   - keychain: Path to the specific keychain where the recovery key will be stored.
///   - apps: A list of file paths to applications that are permitted access to the recovery key.
///   - owners: A list of file paths to applications that are authorized to modify the item’s ACLs in the keychain.
///   - makeInvisible: A Boolean indicating if the keychain item should be made invisible to users. Defaults to `true`.
/// - Returns: A Boolean value indicating the success (`true`) or failure (`false`) of the operation.
///
/// - Note:
/// This function requires that the Keychain Services framework is properly initialized and accessible within the
/// app. It may fail if the provided keychain path is invalid, access permissions are insufficient, or other
/// keychain operations (such as deletion or addition) are unsuccessful.
///
/// - Throws: This function does not explicitly throw errors but may log failures via `os_log` for debugging purposes.
///
/// ### Example:
/// ```swift
/// let success = syncRecoveryKeyToKeychain(
///     label: "com.example.recoveryKey",
///     recoveryKey: "example-recovery-key",
///     keychain: "/Library/Keychains/login.keychain-db",
///     apps: ["/Applications/ExampleApp.app"],
///     owners: ["/Applications/ExampleOwnerApp.app"],
///     makeInvisible: true
/// )
/// print("Sync successful? \(success)")
/// ```
func syncRecoveryKeyToKeychain(label: String, recoveryKey: String, keychain: String, apps: [String], owners: [String], makeInvisible: Bool = true) -> Bool {

  os_log("Starting user info sync of item label: [%{public}s] to the keychain: [%{public}s].", log: keychainLog, type: .default, label, keychain)

  // get a SecKeychain reference so we know which keychain to put the info in.
  guard let secKeychain = getSecKeychain(path: keychain) else {
    return false
  }

  var needToSyncRecoveryKey: Bool = true
  var needToDeleteAndReaddKey: Bool = false

  // get the current info value so we can check if it is up to date.
  if let storedRecoveryKey = getPasswordFromKeychain(label: label, keyChain: secKeychain) {
    needToSyncRecoveryKey = false
    needToDeleteAndReaddKey = true

    // check to see if the stored key matches our current recovery key. It should almost never match.
    if storedRecoveryKey != recoveryKey {
      os_log("Stored recovery key does not match our recovery key. Need to update.", log: keychainLog, type: .default)

      needToSyncRecoveryKey = true
    }

    if !needToSyncRecoveryKey {
      os_log("Stored recovery key matches our recovery key. No need to update.", log: keychainLog, type: .default)
      return true
    }
  }

  //
  if needToDeleteAndReaddKey {
    os_log("Found stored recovery key. Need to delete and readd.", log: keychainLog, type: .default)
    let deleteStatus = deletePasswordByLabel(inKeychain: secKeychain, withLabel: label)

    if deleteStatus != true {
      os_log("Failed to delete our user info of item label: [%{public}s] from the keychain: [%{public}s].", log: keychainLog, type: .error, label, keychain)
      return false
    }
  }

  // greb the prompt description from the preferences
  let aclDescription = getPref(key: .KeychainUIPromptDescription) as! String

  // create a new access instance, this way we can easily update the ACLs if you generate a new key.
  let recoveryKeyAccess = createSecAccessWithAppACLAndOwner(aclOwnerApps: owners, appsWithAccess: apps, aclDescription: aclDescription)

  // add the recovery key to the keychain
  let addStringStatus = addStringToKeychain(stringToAdd: recoveryKey, withLabel: label, keychain: keychain, isInvisible: makeInvisible, withAccess: recoveryKeyAccess)

  if addStringStatus != true {
    os_log("Failed to add our user info of item label: [%{public}s] to the keychain: [%{public}s].", log: keychainLog, type: .error, label, keychain)
    return false
  }

  os_log("Successfully added recovery key with label: [%{public}s] to the keychain: [%{public}s].", log: keychainLog, type: .default, label, keychain)
  return true

}

/// Retrieves a password from the keychain using a specified label.
///
/// This function searches for a password item in the provided keychain using the given label.
/// If found, it returns the password as a `String`. The search operation includes returning
/// both the attributes and data of the matched item.
///
/// - Parameters:
///   - label: A `String` representing the label of the password item to search for in the keychain.
///   - keyChain: Optional `SecKeychain` instance for a keychain where the password item is stored.
/// - Returns: An optional `String` containing the password if found and properly decoded, or `nil` if the item is
///            not found or an error occurs.
///
/// - Note:
/// The function uses `SecItemCopyMatching` to perform the lookup and expects the data to be UTF-8 encoded.
/// Logs are created for both successful and unsuccessful operations, capturing details such as search failures
/// and any errors through error code translation.
///
/// - Throws:
/// The function does not throw Swift-level errors but logs any issues encountered using `os_log`, which includes
/// scenarios where the password item cannot be located or read from the keychain.
func getPasswordFromKeychain(label: String, keyChain: SecKeychain? = nil) -> String? {
  var query: [CFString: Any] = [
    kSecClass: kSecClassGenericPassword,
    kSecReturnAttributes: true,
    kSecReturnData: true,
    kSecAttrLabel: label
  ]

  // Only add kSecMatchSearchList if keyChain is provided
  if let keyChain = keyChain {
    query[kSecMatchSearchList] = [keyChain]
  }

  var item: CFTypeRef?

  os_log("Looking for password in keychain for label: [%{public}@].", log: keychainLog, type: .default, label)
  let queryStatus = SecItemCopyMatching(query as CFDictionary, &item)

  if queryStatus != errSecSuccess {
    let translatedCode = translateErrCode(queryStatus)
    os_log("Could not find password in keycahin for label: [%{public}@] with message: [%{public}@]", log: keychainLog, type: .default, label, translatedCode)
  }

  os_log("Found password item in keychain with label: [%{public}@], attempting to read password.", log: keychainLog, type: .default, label)
  guard let existingItem = item as? [String: Any],
        let passwordData = existingItem[kSecValueData as String] as? Data,
        let password = String(data: passwordData, encoding: String.Encoding.utf8)
  else {
    os_log("Error: Failed to get password item in keychain with label: [%{public}@].", log: keychainLog, type: .error, label)
    return nil
  }
  os_log("Was able to read password for item in keychain with label: [%{public}@].", log: keychainLog, type: .default, label)
  return password
}

/// Updates the password for a specified label in a given keychain, with optional access control settings.
///
/// This function attempts to find a password item in the keychain matching the provided label and updates its
/// stored password. An optional `SecAccess` parameter can be provided to set access controls on the updated
/// item.
///
/// - Parameters:
///   - label: A `String` representing the label of the keychain item whose password needs to be updated.
///   - password: The new password to be set for the keychain item, given as a `String`.
///   - keychain: The `SecKeychain` instance where the password item is stored.
///   - access: An optional `SecAccess` object specifying the access control settings for the password item;
///             defaults to `nil` if no such settings are to be applied.
/// - Returns: A `Bool` indicating success (`true`) if the password was successfully updated, or failure (`false`)
///            if the operation encountered an error.
///
/// - Note:
/// This function leverages `SecItemUpdate` to perform the update operation and optionally uses access control
/// settings if provided. Logging is utilized to track operations and capture errors encountered during the
/// update process.
///
/// - Throws:
/// No Swift-level errors are thrown, but issues are logged using `os_log`, capturing errors with details such as
/// failure in updating the keychain item, including error description through `translateErrCode`.
func updatePasswordForLabel(label: String, password: String, keychain: SecKeychain, access: SecAccess? = nil) -> Bool {
  // now we can search for the key using the ref we got back from the import to update the label.
  // this appears to prompt on update, need to investigate more.
  let addition = password.data(using: String.Encoding.utf8)!

  let searchQ: [CFString: Any] = [
    kSecClass: kSecClassGenericPassword,
    kSecAttrLabel: label,
    kSecUseKeychain: keychain
  ]

  var updateQuery: [CFString: Any] = [
    kSecValueData: addition
  ]

  // if acccess instance is passed in then lets use it to update the item.
  if access != nil {
    os_log("Adding access control to update query.", log: keychainLog, type: .default)
    updateQuery[kSecAttrAccessControl] = access
  }

  os_log("Attempting to update password for label %{pubic}@.", log: keychainLog, type: .default, label)
  let updateResult = SecItemUpdate(searchQ as CFDictionary, updateQuery as CFDictionary)

  if updateResult != kOSReturnSuccess {
    os_log("Failed to update item with error: %{pubic}@", log: keychainLog, type: .error, translateErrCode(updateResult))
    return false
  }

  os_log("Updating password for label %{pubic}@ was successful.", log: keychainLog, type: .default, label)
  return true
}

/// Creates a `SecAccess` instance configured with application access control lists (ACLs) and owner permissions.
///
/// This function generates a `SecAccess` object with a specified description and establishes ACLs for both
/// application access and owner management capabilities. It initially creates a basic access configuration from
/// application paths and then updates it with ACLs for applications permitted to manage access settings.
///
/// - Parameters:
///   - aclOwnerApps: An array of strings representing file paths to applications that are allowed to alter the ACLs.
///   - appsWithAccess: An array of strings representing file paths to applications that are granted access under the ACL.
///   - aclDescription: The name of the keychain item as it should appear in security dialogs, such as when an untrusted app tries to gain access to the item and the system prompts the user for permission. Use a name that gives users enough information to make a decision about this item. If you only store one item, a simple description like "Server password" might be sufficient. If you store many similar items, you might need to be more specific.
/// - Returns: An optional `SecAccess` object representing the access configuration with ACLs and owner specifications, or
///            `nil` if the creation or update process fails.
///
/// - Note:
/// This function utilizes `createAccess` to establish the initial access structure. It updates the access using
/// `bulkUpdateACLForExistingAccess`, configuring which applications have permission to change ACLs. Errors occurring
/// during these processes are logged.
///
/// - Throws:
/// This function does not throw Swift-level errors but logs any issues encountered using `os_log`, including failing
/// to create or update the `SecAccess` instance with detailed error descriptions.
func createSecAccessWithAppACLAndOwner(aclOwnerApps: [String], appsWithAccess: [String], aclDescription: String) -> SecAccess? {
  // creates a SecAccess Instance with Owner and App acls and the corresponding description.
  os_log("Creating SecAccess with description: %{public}@.", log: keychainLog, type: .default, aclDescription)
  guard let recoveryKeySecAccess = createAccess(withPaths: appsWithAccess, description: aclDescription) else {
    os_log("Failed to create SecAccess.", log: keychainLog, type: .error)
    return nil
  }

  // create a dictionary of ACLs we want to update
  let aclData: [String: [String]?] = [
    "kSecACLAuthorizationChangeACL": aclOwnerApps
  ]

  // update the access with the apps that can change ACLs
  os_log("Attempting to update ACLs for %{public}@.", log: keychainLog, type: .default, aclDescription)
  guard let updatedRecoveryKeyAccess = bulkUpdateACLForExistingAccess(access: recoveryKeySecAccess, aclData: aclData, acldescription: aclDescription) else {
    os_log("Failed to update ACL access for %{public}@.", log: keychainLog, type: .error, aclDescription)
    return nil
  }
  return updatedRecoveryKeyAccess
}

/// Creates a `SecAccess` instance using a description and a list of application paths.
///
/// This function generates a list of trusted applications from the provided paths and
/// constructs a `SecAccess` object that uses these applications to define access controls.
///
/// - Parameters:
///   - paths: An array of strings representing file paths to trusted applications. If empty,
///            the trusted applications list is set to `nil`, allowing access to all.
///   - description: The name of the keychain item as it should appear in security dialogs, such as when an untrusted app tries to gain access to the item and the system prompts the user for permission. Use a name that gives users enough information to make a decision about this item. If you only store one item, a simple description like "Server password" might be sufficient. If you store many similar items, you might need to be more specific.
/// - Returns: An optional `SecAccess` object representing the newly created access configuration, or
///            `nil` if the creation process fails.
///
/// - Note:
/// The function relies on the `SecAccessCreate` API to create access instances. If any error
/// occurs during the creation process, a log entry is recorded with the error code, and `nil`
/// is returned to indicate the failure.
///
/// - Throws:
/// This function does not throw Swift-level errors, but issues are logged using `os_log`,
/// including any encountered error codes when the `SecAccess` instance cannot be created.
func createAccess(withPaths paths: [String], description: String) -> SecAccess? {
  os_log("Called createAccess.", log: keychainLog, type: .default)
  var access: SecAccess?

  var trustedApplications: CFArray?
  // if the paths array we got is empty we will set the the access to nil. Otherwise we'll create the trusted app list.
  if paths.isEmpty {
    trustedApplications = nil
  } else {
    trustedApplications = getTrustedApplicationsFromPaths(appPaths: paths) as CFArray
  }

  os_log("Attempting to create a SecAccess instance with our app array.", log: keychainLog, type: .error)
  // create the access instance with the description and trusted applications
  let createStatus = SecAccessCreate(description as CFString, trustedApplications, &access)

  if createStatus != kOSReturnSuccess {
    os_log("Failed to create SecAccess in createAccess with error: %{public}@", log: keychainLog, type: .error, translateErrCode(createStatus))
    return nil
  }

  return access
}

/// Creates an array of `SecTrustedApplication` instances from an array of application path strings.
///
/// This function iterates through a list of application file paths, creating a corresponding
/// `SecTrustedApplication` object for each valid path. If a path is invalid or the creation fails, the
/// function logs a warning and skips the entry.
///
/// - Parameters:
///   - appPaths: An array of strings representing file paths to applications. Provide an empty item in the array
///   to indicate that the calling application should be trusted.
/// - Returns: An array of `SecTrustedApplication` objects created from the provided application paths.
///            Paths that could not be processed or resulted in errors are excluded from the result.
///
/// - Note:
/// Each `SecTrustedApplication` object is created using the `SecTrustedApplicationCreateFromPath` function.
/// Errors (e.g., invalid paths or inability to create trusted applications) are logged, and the associated
/// application is skipped during processing.
///
/// - Throws:
/// No Swift-level errors are thrown, but failures are logged using `os_log`. Each skipped entry is explicitly logged
/// with details on why the `SecTrustedApplication` was not created.
func getTrustedApplicationsFromPaths(appPaths: [String]) -> [SecTrustedApplication] {
  // creates an array of SecTrustedApplication from an array of application path strings

  var trustedAppPaths: [SecTrustedApplication] = []

  for app in appPaths {
    os_log("Creating SecTrustedApplication for [%{public}@]", log: keychainLog, type: .default, app)

    var trustedApplication: SecTrustedApplication?

    let pathToUse: String? = app.isEmpty ? nil : app

    let createResult = SecTrustedApplicationCreateFromPath(pathToUse, &trustedApplication)

    if createResult != kOSReturnSuccess {
      os_log("Warning: Failed to create Trusted App for [%{public}@].", log: keychainLog, type: .default, app)
      continue
    }

    if trustedApplication == nil {
      os_log("Warning: Failed to create Trusted App for [%{public}@], received a nil value.", log: keychainLog, type: .default, app)
      continue
    }

    os_log("Successfully created trusted app for [%{public}@]", log: keychainLog, type: .default, app)

    trustedAppPaths.append(trustedApplication!)

  }

  return trustedAppPaths
}

/// Updates the Access Control List (ACL) for an existing access instance with new application paths and descriptions.
///
/// This function iterates over provided ACL data, appending or modifying the ACL entries of a given `SecAccess`
/// instance. It expects that the authorizations to be updated already exist within the access instance, and updates
/// the descriptions and application lists to match the provided parameters.
///
/// - Parameters:
///   - access: The `SecAccess` instance representing the existing access control to be updated.
///   - aclData: A dictionary mapping authorization types (as `String`) to arrays of application paths (`[String]?`).
///              The application paths should be those that need access under the specified authorization.
///   - acldescription: A description for the ACL changes, typically providing context for the modifications.
/// - Returns: The potentially modified `SecAccess` instance, or `nil` if an error occurred during processing.
///
/// - Note:
/// This function assumes that the required authorizations are already present in the `SecAccess` instance.
/// If an authorization does not exist, the function will log the failure and return `nil`. The function
/// also handles updating the special "ACLAuthorizationPartitionID" differently by modifying the description directly.
///
/// - Throws:
/// Errors are not directly thrown in Swift but operations are logged using `os_log`. This includes handling
/// failures when copying or setting ACL contents and logging any encountered error codes.
func bulkUpdateACLForExistingAccess(access: SecAccess, aclData: [String: [String]?], acldescription: String) -> SecAccess? {
  // takes an existing access instance, and adds the given app paths with the provided description to the provided authorization attribute.

  // TODO: this assumes that the authorization acl you want to update already exists in the access instance, it will fail if it does not.

  for (authorization, apps) in aclData {
    // key is of type CFString and value is of type [String]?
    os_log("Called updateACLForExistingAccess", log: keychainLog, type: .default)

    if let unwrappedApps = apps {
      os_log("Unwrapped apps and got: %{public}@", log: keychainLog, type: .default, unwrappedApps)
    }

    guard let authorizationConstant = getACLAuthorizationConstant(from: authorization) else {
      os_log("Failed to get ACL Constant. Doesn't exist in our list.", log: keychainLog, type: .error)
      return nil
    }

    guard let ACLList = SecAccessCopyMatchingACLList(access, authorizationConstant) else {
      os_log("Failed to copy Matching ACL List", log: keychainLog, type: .error)
      return nil
    }

    os_log("Getting short auth form for %{public}@", log: keychainLog, type: .default, authorization)
    let shortAuth = authorization.replacingOccurrences(of: "kSec", with: "")

    os_log("Got short auth form of %{public}@", log: keychainLog, type: .default, shortAuth)
    let acls = ACLList as! [SecACL]

    var existingApplicationList: CFArray?
    var existingDescription: CFString?
    var promptSelector = SecKeychainPromptSelector()

    os_log("Looping through Existing ACLs", log: keychainLog, type: .default)
    for acl in acls {

      let authArray = SecACLCopyAuthorizations(acl)

      os_log("Checking if: %{public}@ is in %{public}@.", log: keychainLog, type: .default, shortAuth, authArray as! [String])

      if !(authArray as! [String]).contains(shortAuth) {continue}

      let copyContentsResult = SecACLCopyContents(acl, &existingApplicationList, &existingDescription, &promptSelector)

      if copyContentsResult != kOSReturnSuccess {
        os_log("Failed to Copy ACL Contents with error: %{public}@.", log: keychainLog, type: .error, translateErrCode(copyContentsResult))
      }

      var description = acldescription as CFString
      var appsToUpdate: CFArray?

      // if our apps are non-nil then will go ahead and update our appsToUpdate accordingly
      if let appList = apps {
        // to update the ACLAuthorizationPartitionID we need to update the description, we'll handle that differently
        if (authArray as! [String]).contains("ACLAuthorizationPartitionID") {
          os_log("Need to update ACLAuthorizationPartitionID.", log: keychainLog, type: .default)
          description = updatePartitionIDDescription(existingDescription: existingDescription!, teamIDs: appList)
          appsToUpdate = nil
        } else {
          os_log("Attempting to get Trusted Applications for: %{public}@", log: keychainLog, type: .default, appList)
          // convert our app paths to TrustedApplicationPaths to add to the keychain item.
          let trustedApps = getTrustedApplicationsFromPaths(appPaths: appList)

          // take our existing application list already on the item and add our new apps
          appsToUpdate = updateApplicationList(existing: existingApplicationList, applications: trustedApps)
        }
        // if we got here we passed nil to apps which means we want the ACLs to be for everyone.
      } else {
        appsToUpdate = nil
      }

      // set the changed apps back on the ACL.
      let setContentsStatus = SecACLSetContents(acl, appsToUpdate, description as CFString, promptSelector)

      if setContentsStatus != kOSReturnSuccess {
        os_log("Failed to set ACL Contents with error: %{public}@", log: keychainLog, type: .error, translateErrCode(setContentsStatus))
        return nil
      }
    }
  }

  // return our updated access instance.
  return access
}

/// Retrieves the ACL authorization constant corresponding to a configuration string representation.
///
/// This function maps a given configuration string, representing an ACL authorization,
/// to its corresponding Core Foundation string constant used in keychain access control lists.
/// It searches through a predefined dictionary of mappings between string representations and CFString constants.
///
/// - Parameter configString: A `String` representing the name of the ACL authorization.
/// - Returns: An optional `CFString` that corresponds to the provided configuration string.
///            Returns `nil` if the string does not match any known ACL authorization constant.
///
/// - Note:
/// The function uses a dictionary to map configuration strings to their respective `CFString` constants.
/// It logs the attempt to retrieve the ACL constant using `os_log`.
///
/// - Throws:
/// This function does not throw errors but returns `nil` if no corresponding constant is found
/// for the given configuration string.
func getACLAuthorizationConstant(from configString: String) -> CFString? {
  os_log("Called getACLAuthorizationConstant for: %{public}@", log: keychainLog, type: .default, configString)
  let aclAuthorizationMapping: [String: CFString] = [
    "kSecACLAuthorizationAny": kSecACLAuthorizationAny,
    "kSecACLAuthorizationLogin": kSecACLAuthorizationLogin,
    "kSecACLAuthorizationGenKey": kSecACLAuthorizationGenKey,
    "kSecACLAuthorizationDelete": kSecACLAuthorizationDelete,
    "kSecACLAuthorizationExportWrapped": kSecACLAuthorizationExportWrapped,
    "kSecACLAuthorizationExportClear": kSecACLAuthorizationExportClear,
    "kSecACLAuthorizationImportWrapped": kSecACLAuthorizationImportWrapped,
    "kSecACLAuthorizationImportClear": kSecACLAuthorizationImportClear,
    "kSecACLAuthorizationSign": kSecACLAuthorizationSign,
    "kSecACLAuthorizationEncrypt": kSecACLAuthorizationEncrypt,
    "kSecACLAuthorizationDecrypt": kSecACLAuthorizationDecrypt,
    "kSecACLAuthorizationMAC": kSecACLAuthorizationMAC,
    "kSecACLAuthorizationDerive": kSecACLAuthorizationDerive,
    "kSecACLAuthorizationKeychainCreate": kSecACLAuthorizationKeychainCreate,
    "kSecACLAuthorizationKeychainDelete": kSecACLAuthorizationKeychainDelete,
    "kSecACLAuthorizationKeychainItemRead": kSecACLAuthorizationKeychainItemRead,
    "kSecACLAuthorizationKeychainItemInsert": kSecACLAuthorizationKeychainItemInsert,
    "kSecACLAuthorizationKeychainItemModify": kSecACLAuthorizationKeychainItemModify,
    "kSecACLAuthorizationKeychainItemDelete": kSecACLAuthorizationKeychainItemDelete,
    "kSecACLAuthorizationChangeACL": kSecACLAuthorizationChangeACL,
    "kSecACLAuthorizationChangeOwner": kSecACLAuthorizationChangeOwner,
    "kSecACLAuthorizationIntegrity": kSecACLAuthorizationIntegrity,
    "kSecACLAuthorizationPartitionID": kSecACLAuthorizationPartitionID,
    "kSecClassKey": kSecClassKey,
    "kSecClassGenericPassword": kSecClassGenericPassword,
    "kSecClassCertificate": kSecClassCertificate,
    "kSecClassInternetPassword": kSecClassInternetPassword,
    "kSecClassIdentity": kSecClassIdentity
  ]

  return aclAuthorizationMapping[configString]
}

/// Updates a list of trusted applications by appending new applications that are not already included.
///
/// This method takes an existing list of trusted applications and a new list of applications to potentially add. It checks each application to ensure it is not already present based on its data representation, and adds it if necessary.
///
/// - Parameters:
///   - existing: An optional `CFArray` containing existing `SecTrustedApplication` instances. If `nil`, a new array is started.
///   - applications: An array of `SecTrustedApplication` instances intended for addition to the trusted list.
/// - Returns: A `CFArray` containing the updated list of `SecTrustedApplication` instances, or `nil` if errors occurred during processing.
///
/// - Note:
/// The function converts `SecTrustedApplication` objects to `Data` for comparison. It relies on the Keychain Services API, particularly `SecTrustedApplicationCopyData`, to perform these operations. Logging is used to track errors and operational flow.
///
/// - Throws:
/// Errors are not thrown to the caller but are logged using `os_log` in case data copying fails or other errors are encountered.
private func updateApplicationList(existing: CFArray?, applications: [ SecTrustedApplication ]) -> CFArray? {

  var applicationListArray = existing == nil ? [ SecTrustedApplication ]() : existing as! [ SecTrustedApplication ]

  let existingApplicationData = applicationListArray.map { (item) -> Data? in
    var data: CFData?

    let appCopyDataStatus = SecTrustedApplicationCopyData(item, &data)

    if appCopyDataStatus != kOSReturnSuccess {
      os_log("Couldn't get App Data Status.", log: keychainLog, type: .error)
      return nil
    }
    return data! as Data
  }

  for applicationToAdd in applications {
    var data: CFData?

    let appCopyDataStatus = SecTrustedApplicationCopyData(applicationToAdd, &data)

    if appCopyDataStatus != kOSReturnSuccess {
      os_log("Couldn't get data from SecTrustedApplication.", log: keychainLog, type: .error)
      return nil
    }

    let castData = data! as Data

    if existingApplicationData.contains(castData) == false {
      applicationListArray.append(applicationToAdd)
    }
  }

  return applicationListArray as CFArray
}

/// Updates the partition ID description by adding new team IDs, if they are not already present.
///
/// This function takes an existing partition ID description and a list of team IDs. It serializes the
/// existing description, checks if each of the provided team IDs is included, and adds any that are not.
/// It then serializes the updated list back into the appropriate format.
///
/// - Parameters:
///   - existingDescription: A `CFString` representing the current partition ID description in a hex-encoded string format.
///   - teamIDs: An array of `String` instances representing the team IDs to be added to the partition list if not already present.
/// - Returns: A `CFString` that represents the updated partition ID description in hex-encoded string format.
///   If no updates were necessary, the original description is returned.
///
/// - Note:
/// This function relies on `PropertyListSerialization` to handle the conversion of descriptions to and from a property list format.
/// It logs operations and issues encountered, such as deserialization failures or if no updates were necessary.
///
/// - Throws:
/// This function may internally handle errors related to property list serialization and log them, but it does not throw errors at the Swift level.
func updatePartitionIDDescription(existingDescription: CFString, teamIDs: [String]) -> CFString {
  // generates a plist hexencodedstring for the partionID description.
  os_log("Called updatePartitionIDDescription.", log: keychainLog, type: .default)
  let rawData = Data.init(fromHexEncodedString: existingDescription as String)
  var format: PropertyListSerialization.PropertyListFormat = .xml

  var propertyListObject = [String: [String]]()

  do {
    propertyListObject = try PropertyListSerialization.propertyList(from: rawData!, options: [], format: &format) as! [String: [String]]
  } catch {
    os_log("No teamid in ACLAuthorizationPartitionID.", log: keychainLog, type: .error)
  }

  var existingParitions = propertyListObject["Partitions"]

  os_log("Existing TeamID Description: [%{public}@]", log: keychainLog, type: .default, existingParitions!)

  var updatedIDs: Bool = false

  for id in teamIDs {
    os_log("Processing TeamID: [%{public}@].", log: keychainLog, type: .default, id)
    if existingParitions?.contains(id) == false {
      os_log("Did not find TeamID [%{public}@] in existing IDs, adding...", log: keychainLog, type: .default, id)
      existingParitions?.append(id)
      updatedIDs = true
    }
  }

  if updatedIDs == false {
    os_log("Did not update the TeamIDs returning original description.", log: keychainLog, type: .default)
    return existingDescription
  }

  propertyListObject["Partitions"] = existingParitions

  os_log("Need to serialize plist data of %{public}@.", log: keychainLog, type: .default, propertyListObject)

  // now serialize it back into a plist

  let xmlObject = try? PropertyListSerialization.data(fromPropertyList: propertyListObject as Any, format: format, options: 0)

  return xmlObject!.hexEncodedString() as CFString

}

/// Deletes a password from the specified keychain that matches the given label.
///
/// This function searches the provided keychain for a generic password item
/// with the specified label and deletes it if it exists. Logs are generated to
/// provide insights into the status of the operation.
///
/// - Parameters:
///   - inKeychain: A reference to the `SecKeychain` where the password item is stored.
///   - withLabel: The label of the password item to delete. This serves as a unique identifier
///     for the item within the keychain.
/// - Returns: A Boolean value indicating whether the password was successfully deleted (`true`)
///   or not (`false`).
///
/// - Note:
/// This method relies on the Keychain Services API. It may fail if the label does not exist
/// in the specified keychain or if the application lacks the necessary permissions.
///
/// - Throws:
/// This function does not throw Swift-level errors but logs failures via `os_log`,
/// including the translated error code for debugging purposes.
func deletePasswordByLabel(inKeychain: SecKeychain, withLabel: String) -> Bool {
  os_log("Called deletePasswordByLabel with label: %{public}@", log: keychainLog, type: .info, withLabel)
  let searchQ: [CFString: Any] = [
    kSecClass: kSecClassGenericPassword,
    kSecUseKeychain: inKeychain,
    kSecAttrLabel: withLabel
  ]
  os_log("Attempting to delete password with label: %{public}@", log: keychainLog, type: .info, withLabel)
  let status = SecItemDelete(searchQ as CFDictionary)

  if status != errSecSuccess {
    os_log("Failed to delete password with label: [%{public}@] with the Error: %{public}@", log: keychainLog, type: .error, withLabel, translateErrCode(status))
    return false
  }

  os_log("Successfully deleted password with label: %{public}@", log: keychainLog, type: .info, withLabel)
  return true
}
