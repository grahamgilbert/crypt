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
        
        if serverURL == "NOT SET" {
            NSLog("%@","Preference isn't set, let's just log in")
            allowLogin()
        }
        
        if fvEnabled == true {
            NSLog("%@","filevault is enabled, encrypting or decrypting, allow login")
            setHintValue(false)
            allowLogin()
        } else {
            let fvCompleted : Bool = enableFilevault()
            NSLog("Enabling filevault")
            
            
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
    
    private func enableFilevault() -> Bool {
        
        // build input plist with username and password
        //
        let username = getUsername() as! String
        let password = getPassword() as! String
        
        let enableScript = "/Library/Security/SecurityAgentPlugins/Crypt.bundle/Contents/Resources/FDESetupEnable.py"
        NSLog("%@", enableScript)
        
        //let dict: NSDictionary = ["Username": getUsername()!, "Password": getPassword()!]
        //NSLog("%@", dict)
        //let inpipe = NSPipe()
        let outpipe = NSPipe()
        let task = NSTask();
        //task.standardInput = inpipe
        task.standardOutput = outpipe
        //task.launchPath = "/usr/bin/fdesetup"
        task.launchPath = "/usr/bin/python"
        task.arguments = [enableScript, "--username", username, "--password", password]
        //task.arguments = ["enable", "-inputplist", "-outputplist"]
        NSLog("Running fdesetup")
        task.launch()
        
        //let inputdata : NSData = NSKeyedArchiver.archivedDataWithRootObject(dict)
        
       // inpipe.fileHandleForWriting.writeData(inputdata)
        //NSLog("%@", inpipe)

//        guard let output: String = String(data: inputdata, encoding: NSUTF8StringEncoding)
//            else {
//                NSLog("Couldn't unwrap inputdata")
//                return false
//        }
//        NSLog("%@", output)
//        //inpipe.fileHandleForWriting.closeFile()
        task.waitUntilExit()
        let data = outpipe.fileHandleForReading.readDataToEndOfFile()
        let output: String = String(data: data, encoding: NSUTF8StringEncoding)!
        NSLog("%@",output)
        NSLog("fdesetup returned %@",task.terminationStatus)
        if task.terminationStatus != 0 {
            return false
        } else {
            let file = "ouput.plist" //this is the file. we will write to and read from it
            
            
            if let dir : NSString = "/var/root" {
                let path = dir.stringByAppendingPathComponent(file);
                
                //writing
                do {
                    try output.writeToFile(path, atomically: false, encoding: NSUTF8StringEncoding)
                }
                catch {/* error handling here */}
                
                }
            return true
        }
    }
    
    //
    // This is how we set the inter-mechanism context data
    private func setHintValue(encryptionWasEnabled : Bool) -> Bool {
        
        // Try and unwrap the optional NSString
//        guard let pin = pin
//            else {
//                NSLog("VerifyAuth:MechanismInvoke:MachinePIN:setHintValue [+] Failed to unwrap inPin");
//                return false
//        }
        
        // Try and unwrap the optional NSData returned from archivedDataWithRootObject
        // This can be decoded on the other side with unarchiveObjectWithData
        guard let data : NSData = NSKeyedArchiver.archivedDataWithRootObject(encryptionWasEnabled)
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

