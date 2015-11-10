//
//  Check.swift
//  Crypt
//
//  Created by Graham Gilbert on 10/11/2015.
//  Copyright © 2015 Graham Gilbert. All rights reserved.
//

import Foundation
import Foundation
import Security
import CoreFoundation

class Check: NSObject {
    let bundleid = "com.grahamgilbert.crypt"
    
    // Define a pointer to the MechanismRecord. This will be used to get and set
    // all the inter-mechanism data. It is also used to allow or deny the login.
    private var mechanism:UnsafePointer<MechanismRecord>
    
    // This NSString will be used as the domain for the inter-mechanism context data
    private let contextCryptDomain : NSString = "com.grahamgilbert.crypt"
    
    //
    // init the class with a MechanismRecord
    init(mechanism:UnsafePointer<MechanismRecord>) {
        NSLog("Crypt:MechanismInvoke:Check:[+] initWithMechanismRecord");
        self.mechanism = mechanism
    }
    
    func run(){
        
        NSLog("Crypt:MechanismInvoke:Check:run:[+]");
        
        let serverURL : NSString = getServerURL()
        let fvEnabled : Bool = getFVEnabled()
        
        
        if fvEnabled == true {
            NSLog("%@","filevault is enabled, encrypting or decrypting, allow login")
            setBoolHintValue(false)
            allowLogin()
        }
        else if serverURL == "NOT SET" {
            NSLog("%@","Preference isn't set, let's just log in")
            setBoolHintValue(false)
            allowLogin()
        }
        else {
            setBoolHintValue(true)
        }
        
    }
    
    private func setBoolHintValue(encryptionWasEnabled : NSNumber) -> Bool {
        
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