//
//  CryptGUI.swift
//  Crypt
//
//  Created by Graham Gilbert on 09/11/2015.
//  Copyright © 2015 Graham Gilbert. All rights reserved.
//

import Foundation
class CryptGUI: NSObject {
    
    let bundleid = "com.grahamgilbert.crypt"
    
    // Define a pointer to the MechanismRecord. This will be used to get and set
    // all the inter-mechanism data. It is also used to allow or deny the login.
    private var mechanism:UnsafePointer<MechanismRecord>
    
    // This NSString will be used as the domain for the inter-mechanism context data
    private let contextCryptDomain : NSString = "com.grahamgilbert.crypt"
    
    //
    // init the class with a MechanismRecord
    init(mechanism:UnsafePointer<MechanismRecord>) {
        NSLog("Crypt:MechanismInvoke:CryptGUI:[+] initWithMechanismRecord");
        self.mechanism = mechanism
    }
    
    func run() {
        
        NSLog("Crypt:MechanismInvoke:CryptGUI:run:[+]");
        
    }
    
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
    
    private func setHintValue(encryptionWasEnabled : Bool) -> Bool {
        
        
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
    

}