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

import os.log

class Enablement: CryptMechanism {
  // Log for the Enablement functions
  private static let log = OSLog(subsystem: "com.grahamgilbert.crypt", category: "Enablement")

  func run() {
    os_log("running", log: Enablement.log, type: .debug)
    guard let username = self.username else {
      return allowLogin()
    }
    guard let password = self.password else {
      return allowLogin()
    }

    let settings: [String: String] = ["Username" : username, "Password" : password]

    if self.needsEncryption {
      os_log("attempting to enable FV2", log: Enablement.log, type: .debug)
      do {
        let outputPlist = try enableFileVault(settings: settings)
        outputPlist.write(toFile: "/private/var/root/crypt_output.plist", atomically: true)
        restartMac()
      }
      catch let error as NSError {
        os_log("%@", log: Enablement.log, type: .error, error)
        allowLogin()
      }

    } else {
      os_log("nothing to do", log: Enablement.log, type: .debug)
      allowLogin()
    }
  }

  // Restart
  private func restartMac() {
    // Wait a couple of seconds for everything to finish
    sleep(3)
    let task = Process();
    os_log("restarting after enabling FV2", log: Enablement.log, type: .debug)
    task.launchPath = "/sbin/reboot"
    task.launch()
  }

  // fdesetup Errors
  enum FileVaultError: Error {
    case FDESetupFailed(retCode: Int32)
    case OutputPlistNull
    case OutputPlistMalformed
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
    if (outputString.contains("true")) {
      os_log("supports authrestart", log: Enablement.log, type: .debug)
      return true
    } else {
      os_log("does not supports authrestart", log: Enablement.log, type: .debug)
      return false
    }
  }

  // fdesetup wrapper
  func enableFileVault(settings : Dictionary<String, String>) throws -> NSDictionary {
    let inputPlist =
      try PropertyListSerialization.data(fromPropertyList: settings,
                                         format: PropertyListSerialization.PropertyListFormat.xml,
                                         options: 0)
    let inPipe = Pipe.init()
    let outPipe = Pipe.init()
    let task = Process.init()
    task.launchPath = "/usr/bin/fdesetup"
    if checkAuthRestart() {
      task.arguments = ["enable", "-authrestart", "-outputplist", "-inputplist"]
    } else {
      task.arguments = ["enable", "-outputplist", "-inputplist"]
    }
    task.standardInput = inPipe
    task.standardOutput = outPipe
    task.launch()
    inPipe.fileHandleForWriting.write(inputPlist)
    inPipe.fileHandleForWriting.closeFile()
    task.waitUntilExit()

    if task.terminationStatus != 0 {
      throw FileVaultError.FDESetupFailed(retCode: task.terminationStatus)
    }

    let outputData = outPipe.fileHandleForReading.readDataToEndOfFile()
    outPipe.fileHandleForReading.closeFile()

    if outputData.count == 0 {
      throw FileVaultError.OutputPlistNull
    }

    var format: PropertyListSerialization.PropertyListFormat =
      PropertyListSerialization.PropertyListFormat.xml
    let outputPlist =
      try PropertyListSerialization.propertyList(from: outputData,
                                                 options: PropertyListSerialization.ReadOptions.mutableContainers,
                                                 format: &format)

    if (format == PropertyListSerialization.PropertyListFormat.xml) {
      return outputPlist as! NSDictionary
    } else {
      throw FileVaultError.OutputPlistMalformed
    }
  }
}
