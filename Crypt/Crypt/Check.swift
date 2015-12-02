//
//  Check.swift
//  Crypt
//
//  Created by Graham Gilbert on 10/11/2015.
//  Copyright © 2015 Graham Gilbert. All rights reserved.
//

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
    
    // init the class with a MechanismRecord
    init(mechanism:UnsafePointer<MechanismRecord>) {
        NSLog("Crypt:MechanismInvoke:Check:[+] initWithMechanismRecord");
        self.mechanism = mechanism
    }
    
    func run(){
        NSLog("Crypt:MechanismInvoke:Check:run:[+]");
        
        let serverURL : NSString? = getServerURL()
        let fvEnabled : Bool = getFVEnabled()
        let skipUsers : Bool = getSkipUsers()
        
        if fvEnabled {
            NSLog("%@","filevault is enabled, encrypting or decrypting, allow login")
            setBoolHintValue(false)
            allowLogin()
        }
        else if skipUsers {
            NSLog("%@","Username is in the skip list, not enforcing filevault")
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
                NSLog("Crypt:MechanismInvoke:Check:setHintValue [+] Failed to unwrap archivedDataWithRootObject");
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
        guard let output: String = String(data: data, encoding: NSUTF8StringEncoding)
            else { return false }
        return (output.rangeOfString("FileVault is Off.") != nil) ? false : true
    }
    
    func trim_string(the_string:String) -> String {
        let output = the_string.stringByTrimmingCharactersInSet(NSCharacterSet.whitespaceAndNewlineCharacterSet())
        NSLog("Trimming %@ to %@", the_string, output)
        return output
    }
    
    private func getSkipUsers() -> Bool {
        let uid : uid_t = getUID()
        NSLog("%u", uid)
        if (uid < 501) {
            return true
        }
        guard let prefValue = CFPreferencesCopyAppValue("SkipUsers", bundleid) as? [String]
            else { return false }
        guard let username = getUsername()
            else { return false }
        for s in prefValue {
            if trim_string(s) == username {
                return true
            }
        }
        return false
    }
    
    private func getServerURL() -> NSString? {
        let prefValue = CFPreferencesCopyAppValue("ServerURL", bundleid) as? String
        if prefValue != nil {
            return prefValue
        } else {
            return "NOT SET"
        }
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
        
        return username.stringByReplacingOccurrencesOfString("\0", withString: "")
    }
    
    private func getUID() -> uid_t {
        var value : UnsafePointer<AuthorizationValue> = nil
        var flags = AuthorizationContextFlags()
        var uid : uid_t = 0
        if (self.mechanism.memory.fPlugin.memory.fCallbacks.memory.GetContextValue(
            mechanism.memory.fEngine,
            ("uid" as NSString).UTF8String,
            &flags, &value) == errSecSuccess) {
                let uidData = NSData.init(bytes: value.memory.data, length: sizeof(uid_t))
                uidData.getBytes(&uid, length: sizeof(uid_t))
            }
        return uid
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