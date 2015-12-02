/*
 CryptGUI.m
 Crypt
 
 Copyright 2015 Graham Gilbert.
 
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

#import "CryptGUI.h"
#import "PromptWindowController.h"


@implementation CryptGUI

- (id)initWithMechanism:(MechanismRecord *)inMechanism {
    if ([super init]) {
        _mechanism = (MechanismRecord *)inMechanism;
    }
    return self;
}

- (void)run {
    NSLog(@"Crypt:MechanismInvoke:GryptGUI:run [+] ");
    // Create an instance of the CryptWindowController
    PromptWindowController *promptWindowController = [[PromptWindowController alloc] init];
    [promptWindowController setMechanism:_mechanism];
    if ([self getBoolHintValue]) {
        [NSApp runModalForWindow:[promptWindowController window]];
    }
}

- (BOOL)getBoolHintValue {
    // Setup method variables
    NSString *hint;
    const AuthorizationValue *value;
    
    // This NSString will be used as the domain for the inter-mechanism context data
    NSString *contextCryptDomain = @"com.grahamgilbert.crypt";
    
    // Use the MechanismRecord GetHintValue callback to get the
    // inter-mechanism context data
    NSLog(@"Crypt:MechanismInvoke:CryptGui [+] Attempting to read %@", contextCryptDomain);
    if (_mechanism->fPlugin->fCallbacks->GetHintValue(_mechanism->fEngine,
                                                      [contextCryptDomain UTF8String],
                                                      &value) == errAuthorizationSuccess) {
        
        NSData *hintData = [[NSData alloc] initWithBytes:value->data length:value->length];
        id ret = [NSKeyedUnarchiver unarchiveObjectWithData:hintData];
        hint = (NSString *)ret;
        
    } else {
        NSLog(@"VerifyAuth:MechanismInvoke:Verify [!] Failed to read %@", contextCryptDomain);
    }
    
    NSLog(@"%@", hint);
    return [hint boolValue];
}

@end

