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
    
    let bundleid = "com.grahamgilbert.crypt"
    
    // Define a pointer to the MechanismRecord. This will be used to get and set
    // all the inter-mechanism data. It is also used to allow or deny the login.
    private var mechanism:UnsafePointer<MechanismRecord>
    
    // This NSString will be used as the domain for the inter-mechanism context data
    private let contextCryptDomain : NSString = "com.grahamgilbert.crypt"
    
    //
    // init the class with a MechanismRecord
    init(mechanism:UnsafePointer<MechanismRecord>) {
        NSLog("VerifyAuth:MechanismInvoke:MachinePIN:[+] initWithMechanismRecord");
        self.mechanism = mechanism
    }
    
    //
    // This is the only public function. It will be called from the
    // ObjC AuthorizationPlugin class
    func run() {
        
        NSLog("Crypt:MechanismInvoke:Enablement:run:[+]");
        
        let serverURL : NSString = getServerURL()
        let fvEnabled : Bool = getFVEnabled()
        
        
        if fvEnabled == true {
            NSLog("%@","filevault is enabled, encrypting or decrypting, allow login")
            setHintValue(false)
            allowLogin()
        } else if serverURL == "NOT SET" {
            NSLog("%@","Preference isn't set, let's just log in")
            setHintValue(false)
            allowLogin()
        }
        else {
            setHintValue(true)
            
            NSLog("Enabling filevault")
            let fvCompleted : Bool = enableFilevault()
            if fvCompleted == true {
                restart_mac()
            }
        }
        
        
        
        // Allow to login. End of mechanism
        NSLog("VerifyAuth:MechanismInvoke:MachinePIN:run:[+] allowLogin");
        allowLogin()
        
    }
    
    private func restart_mac() -> Bool {
        let task = NSTask();
        NSLog("%@", "Restarting after enabling encryption")
        task.launchPath = "/sbin/reboot"
        task.launch()
        return true
    }
    
    enum FileVaultError: ErrorType {
        case FDESetupFailed(retCode: Int32)
        case OutputPlistNull
    }
    
    func processFileVault(the_settings : NSDictionary) throws -> NSDictionary?{
        
        let input_plist = try NSPropertyListSerialization.dataWithPropertyList(the_settings,
            format: NSPropertyListFormat.XMLFormat_v1_0, options: 0)
        let inPipe = NSPipe.init()
        let outPipe = NSPipe.init()
        
        let task = NSTask.init()
        task.launchPath = "/usr/bin/fdesetup"
        task.arguments = ["enable", "-outputplist", "-inputplist"]
        task.standardInput = inPipe
        task.standardOutput = outPipe
        task.launch()
        inPipe.fileHandleForWriting.writeData(input_plist)
        inPipe.fileHandleForWriting.closeFile()
        task.waitUntilExit()
        
        if task.terminationStatus != 0 {
            throw FileVaultError.FDESetupFailed(retCode: task.terminationStatus)
        }
        
        let output_data = outPipe.fileHandleForReading.readDataToEndOfFile()
        
        if output_data.length == 0 {
            throw FileVaultError.OutputPlistNull
        }
        
        let output_plist = try NSPropertyListSerialization.propertyListWithData(output_data,
           options: NSPropertyListMutabilityOptions.Immutable, format: nil)
        
        let output: String = String(data: output_data, encoding: NSUTF8StringEncoding)!
        outPipe.fileHandleForReading.closeFile()
        
        let file = "crypt_output.plist" //this is the file. we will write to and read from it
        
        
        if let dir : NSString = "/var/root" {
            let path = dir.stringByAppendingPathComponent(file);
            
            //writing
            do {
                try output.writeToFile(path, atomically: false, encoding: NSUTF8StringEncoding)
            }
            catch {throw FileVaultError.OutputPlistNull}
            
        }

        
        return output_plist as? NSDictionary
    }
    
    
    private func enableFilevault() -> Bool {
        
        // build input plist with username and password
        //
        let username = getUsername() as! String
        let password = getPassword() as String
//        var output : NSDictionary
        
        let the_settings = NSDictionary.init(dictionary: ["Username" : username, "Password" : password])
        do {
            try processFileVault(the_settings)!
            return true
        }
            
        catch {
            //print("%@",error)
            return false
        }
        
    }

    private func getHintValue() -> Bool {
        
        let value : UnsafePointer<AuthorizationValue> = nil
        let flags = AuthorizationContextFlags()
        var err: OSStatus = noErr
        err = self.mechanism.memory.fPlugin.memory.fCallbacks.memory.SetContextValue(mechanism.memory.fEngine, kAuthorizationEnvironmentPassword, flags, value)
        if err != errSecSuccess {
            return false
        }
        guard let outputdata = NSString.init(bytes: value.memory.data, length: value.memory.length, encoding: NSUTF8StringEncoding)
            else { return false }
        
        if outputdata == "true" {
            return true
        } else {
            return false
        }
       
    }
    // This is how we set the inter-mechanism context data
    private func setHintValue(encryptionToBeEnabled : Bool) -> Bool {
        var inputdata : String
        if encryptionToBeEnabled == true{
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
    
    private func getFVEnabled() -> Bool {
        let task = NSTask();
        task.launchPath = "/usr/bin/fdesetup"
        task.arguments = ["status"]
        
        let pipe = NSPipe()
        task.standardOutput = pipe
        
        task.launch()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output: String = String(data: data, encoding: NSUTF8StringEncoding)!
        
        if output.rangeOfString("FileVault is Off.") != nil{
            return false
        } else {
            return true
        }
    }
    
    private func getServerURL() -> NSString {
        let prefValue = CFPreferencesCopyAppValue("ServerURL", bundleid) as? String
        
        if prefValue != nil {
            return prefValue!
        } else {
            return "NOT SET"
        }
        
        
    }
    
    private func getPassword() -> NSString {
        
        var value : UnsafePointer<AuthorizationValue> = nil
        var flags = AuthorizationContextFlags()
        var err: OSStatus = noErr
        err = self.mechanism.memory.fPlugin.memory.fCallbacks.memory.GetContextValue(mechanism.memory.fEngine, kAuthorizationEnvironmentPassword, &flags, &value)
        if err != errSecSuccess {
            return "None"
        }
        guard let pass = NSString.init(bytes: value.memory.data, length: value.memory.length, encoding: NSUTF8StringEncoding)
            else { return "None" }
        return pass
    }
    
    
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
        return username
    }
    
    
    //
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

