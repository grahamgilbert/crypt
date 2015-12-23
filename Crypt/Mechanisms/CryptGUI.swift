//
//  CryptGUI.swift
//  Crypt
//
//  Created by Burgin, Thomas (NIH/CIT) [C] on 12/17/15.
//  Copyright © 2015 Graham Gilbert. All rights reserved.
//

import Foundation

class CryptGUI: NSObject {
    
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
    
    func run() {
        if (getBoolHintValue()) {
            let promptWindowController = PromptWindowController.init()
            promptWindowController.mechanism = self.mechanism
            guard let promptWindow = promptWindowController.window
                else { return }
            NSApp.runModalForWindow(promptWindow)
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
}
