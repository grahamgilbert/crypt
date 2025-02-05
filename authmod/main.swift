//
//  main.swift
//  authmod
//
//  Created by Wes Whetstone on 7/22/23.
//  Copyright © 2023 Graham Gilbert. All rights reserved.
//

import Foundation
import ArgumentParser
import Security.AuthorizationDB

struct authmod: ParsableCommand {

  static var configuration = CommandConfiguration(
    commandName: "authmod",
    abstract: "A command-line tool for modifying the Crypt Authorization Database."
  )

  @Flag(name: .shortAndLong, help: "Remove the Crypt Mechanisms from the Authorization Database instead of adding them.")
  var uninstall: Bool = false

  func run() throws {
    if uninstall {
      // Perform the uninstallation logic
      _ = setMechanisms(remove: true)
    } else {
      // Perform the default behavior
      _ = setMechanisms(remove: false)
    }
  }
}

func setMechanisms(remove: Bool) -> Bool {
  let kSystemRightConsole = "system.login.console"
  let kloginwindowDone = "loginwindow:done"
  let authBuddyMechs = ["Crypt:Check,privileged"]
  let kmechanisms = "mechanisms"

  var rights: CFDictionary?
  var err = OSStatus.init(0)
  var authRef: AuthorizationRef?

  // get an authorization context to save this back
  // need to be root, if we are this should return clean
  err = AuthorizationCreate(nil, nil, AuthorizationFlags(rawValue: 0), &authRef)

  // get the current rights for system.login.console
  err = AuthorizationRightGet(kSystemRightConsole, &rights)

  // Now to iterate through the list and add what we need
  if err != 0 {
    print("Encountered Error setting up Authorization Database with err \(String(describing: SecCopyErrorMessageString(err, nil)))")
    exit(err)
  }

  guard var rightsDict = rights as? [String: AnyObject] else {
    print("Failed to cast rights to [String: AnyObject]")
    exit(1)
  }

  guard var currentMechanisms: [String] = rightsDict[kmechanisms] as? [String] else {
    print("Failed to cast rightsDict[kmechanisms] to [String]")
    exit(1)
  }

  // remove any previous mechs before we add the new ones.
  for mech in authBuddyMechs {
    print("Working with \(mech)")
    if let rmindex = currentMechanisms.firstIndex(of: mech) {
      print("Removing: \(mech).")
      currentMechanisms.remove(at: rmindex)
    }
  }

  if remove == true {
    // we want to remove them so we can just set the mechanisms back now since we removed them prior to setting them.
    rightsDict[kmechanisms] = currentMechanisms as AnyObject

    print("Setting back removed mechanisms.")
    err = AuthorizationRightSet(authRef!, kSystemRightConsole, rightsDict as CFTypeRef, nil, nil, nil)

    if err != 0 {
      print("Failed to set mechanisms with err \(String(describing: SecCopyErrorMessageString(err, nil)))")
      exit(err)
    }

    print("Successfully removed Mechanisms \(authBuddyMechs) from Authorization Database.")
    exit(0)
  }

  // Now to iterate through the list and add what we need
  if let index = currentMechanisms.firstIndex(of: kloginwindowDone) {
    print("Found \(kloginwindowDone) at index \(index)")
    var ind: Int = 0
    for mech in authBuddyMechs {
      let indexToAddAt = (index + ind)
      print("Adding: \(mech) at index: \(indexToAddAt).")
      currentMechanisms.insert(mech, at: indexToAddAt)
      ind += 1
    }
    rightsDict[kmechanisms] = currentMechanisms as AnyObject

    // write out the new mechanism array
    err = AuthorizationRightSet(authRef!, kSystemRightConsole, rightsDict as CFTypeRef, nil, nil, nil)

    if err != 0 {
      print("Failed to set mechanisms with err \(String(describing: SecCopyErrorMessageString(err, nil)))")
      exit(err)
    }

    print("Successfully set Mechanisms \(authBuddyMechs) from Authorization Database.")
    exit(0)
  }

  print("Couldn't find \(kloginwindowDone) in mechanism list.")
  exit(1)
}

func main() {
  authmod.main()
}

main()
