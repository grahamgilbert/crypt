//
//  Enablement.swift
//  Crypt
//
//  Created by Graham Gilbert on 07/11/2015.
//  Copyright © 2015 Graham Gilbert. All rights reserved.
//

import Foundation
import Security
import CoreFoundation

class Enablement: NSObject {
    
    // Define a pointer to the MechanismRecord. This will be used to get and set
    // all the inter-mechanism data. It is also used to allow or deny the login.
    private var mechanism:UnsafePointer<MechanismRecord>
    
    // This NSString will be used as the domain for the inter-mechanism context data
    private let contextCryptDomain : NSString = "com.grahamgilbert.crypt"
    
    // init the class with a MechanismRecord
    init(mechanism:UnsafePointer<MechanismRecord>) {
        NSLog("Crypt:MechanismInvoke:Enablement:[+] initWithMechanismRecord");
        self.mechanism = mechanism
    }
    
    // This is the only public function. It will be called from the
    // ObjC AuthorizationPlugin class
    func run() {
        guard let username = getUsername()
            else { allowLogin(); return }
        guard let password = getPassword()
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
    
    // fdesetup wrapper
    func enableFileVault(theSettings : NSDictionary) throws -> NSDictionary {
        let inputPlist = try NSPropertyListSerialization.dataWithPropertyList(theSettings,
            format: NSPropertyListFormat.XMLFormat_v1_0, options: 0)
        
        let inPipe = NSPipe.init()
        let outPipe = NSPipe.init()
        
        let task = NSTask.init()
        task.launchPath = "/usr/bin/fdesetup"
        task.arguments = ["enable", "-outputplist", "-inputplist"]
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
    
    // This is how we get the inter-mechanism context data
    private func getBoolHintValue() -> Bool {
        var value : UnsafePointer<AuthorizationValue> = nil
        var err: OSStatus = noErr
        err = self.mechanism.memory.fPlugin.memory.fCallbacks.memory.GetHintValue(mechanism.memory.fEngine, contextCryptDomain.UTF8String, &value)
        if err != errSecSuccess {
            NSLog("%@","couldn't retrieve hint value")
            return false
        }
        let outputdata = NSData.init(bytes: value.memory.data, length: value.memory.length)
        guard let boolHint = NSKeyedUnarchiver.unarchiveObjectWithData(outputdata)
            else {
                NSLog("couldn't unpack hint value")
                return false
        }
        
        return boolHint.boolValue
    }
    
    // This is how we set the inter-mechanism context data
    private func setHintValue(encryptionToBeEnabled : Bool) -> Bool {
        var inputdata : String
        if encryptionToBeEnabled {
            inputdata = "true"
        } else {
            inputdata = "false"
        }
        
        // Try and unwrap the optional NSData returned from archivedDataWithRootObject
        // This can be decoded on the other side with unarchiveObjectWithData
        guard let data : NSData = NSKeyedArchiver.archivedDataWithRootObject(inputdata)
            else {
                NSLog("Crypt:MechanismInvoke:Enablement:setHintValue [+] Failed to unwrap archivedDataWithRootObject");
                return false
        }
        
        // Fill the AuthorizationValue struct with our data
        var value = AuthorizationValue(length: data.length,
            data: UnsafeMutablePointer<Void>(data.bytes))
        
        // Use the MechanismRecord SetHintValue callback to set the
        // inter-mechanism context data
        let err : OSStatus = self.mechanism.memory.fPlugin.memory.fCallbacks.memory.SetHintValue(
            mechanism.memory.fEngine, contextCryptDomain.UTF8String, &value)
        
        return (err == errSecSuccess) ? true : false
    }
    
    // Get the kAuthorizationEnvironmentPassword
    private func getPassword() -> NSString? {
        var value : UnsafePointer<AuthorizationValue> = nil
        var flags = AuthorizationContextFlags()
        var err: OSStatus = noErr
        err = self.mechanism.memory.fPlugin.memory.fCallbacks.memory.GetContextValue(mechanism.memory.fEngine, kAuthorizationEnvironmentPassword, &flags, &value)
        if err != errSecSuccess {
            return nil
        }
        guard let pass = NSString.init(bytes: value.memory.data, length: value.memory.length, encoding: NSUTF8StringEncoding)
            else { return nil }
        return pass.stringByReplacingOccurrencesOfString("\0", withString: "")
    }
    
    // Get the AuthorizationEnvironmentUsername
    private func getUsername() -> NSString? {
        var value : UnsafePointer<AuthorizationValue> = nil
        var flags = AuthorizationContextFlags()
        var err: OSStatus = noErr
        err = self.mechanism.memory.fPlugin.memory.fCallbacks.memory.GetContextValue(mechanism.memory.fEngine, kAuthorizationEnvironmentUsername, &flags, &value)
        if err != errSecSuccess {
            return nil
        }
        guard let username = NSString.init(bytes: value.memory.data, length: value.memory.length, encoding: NSUTF8StringEncoding)
            else { return nil }
        
        return username.stringByReplacingOccurrencesOfString("\0", withString: "")
    }
    
    // Allow the login. End of the mechanism
    private func allowLogin() -> OSStatus {
        NSLog("VerifyAuth:MechanismInvoke:MachinePIN:[+] Done. Thanks and have a lovely day.");
        var err: OSStatus = noErr
        err = self.mechanism
            .memory.fPlugin
            .memory.fCallbacks
            .memory.SetResult(mechanism.memory.fEngine, AuthorizationResult.Allow)
        NSLog("VerifyAuth:MechanismInvoke:MachinePIN:[+] [%d]", Int(err));
        return err
    }
}

