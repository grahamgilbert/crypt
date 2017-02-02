/*
 Crypt

 Copyright 2017 The Crypt Project.

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

#import <XCTest/XCTest.h>

#import "CryptCallbackEngine.h"

CryptCallbackEngine *callbackEngine = nil;

AuthorizationResult CryptPluginCoreGlobalResult;

OSStatus CryptSetResult(AuthorizationEngineRef inEngine, AuthorizationResult inResult) {
  CryptPluginCoreGlobalResult = inResult;
  return errAuthorizationSuccess;
}

OSStatus CryptDidDeactivate(AuthorizationEngineRef inEngine) {
  return errAuthorizationSuccess;
}

OSStatus CryptGetContextValue(AuthorizationEngineRef inEngine,
                              AuthorizationString inKey,
                              AuthorizationContextFlags *outContextFlags,
                              const AuthorizationValue **outValue) {
  return [callbackEngine getContextValue:inEngine
                                  forKey:inKey
                                outFlags:outContextFlags
                                outValue:outValue];
}

OSStatus CryptGetHintValue(AuthorizationEngineRef inEngine,
                           AuthorizationString inKey,
                           const AuthorizationValue **outValue) {
  return [callbackEngine getHintValue:inEngine
                               forKey:inKey
                             outValue:outValue];
}

OSStatus CryptSetHintValue(AuthorizationEngineRef inEngine,
                           AuthorizationString inKey,
                           const AuthorizationValue *value) {
  return [callbackEngine setHintValue:inEngine
                               forKey:inKey
                             outValue:value];
}

@interface CryptTests : XCTestCase

@end

@implementation CryptTests

- (void)testCryptPluginCore {
  callbackEngine = [[CryptCallbackEngine alloc] init];
  [callbackEngine setUsername:@"bur"];
  [callbackEngine setPassword:@"tomtom"];
  [callbackEngine setUID:501];
  [callbackEngine setGID:20];

  AuthorizationCallbacks *callbacks =
      (AuthorizationCallbacks *)malloc(sizeof(AuthorizationCallbacks));
  callbacks->version = kAuthorizationCallbacksVersion;
  callbacks->SetResult = &CryptSetResult;
  callbacks->DidDeactivate = &CryptDidDeactivate;
  callbacks->GetContextValue = &CryptGetContextValue;
  callbacks->GetHintValue = &CryptGetHintValue;
  callbacks->SetHintValue = &CryptSetHintValue;

  AuthorizationPluginRef plugin;
  const AuthorizationPluginInterface *pluginInterface;
  AuthorizationPluginCreate(callbacks, &plugin, &pluginInterface);
  PluginRecord *pluginRecord = (PluginRecord *)plugin;
  XCTAssertTrue(pluginRecord->fMagic == kPluginMagic);
  XCTAssertTrue(pluginRecord->fCallbacks != NULL);
  XCTAssertTrue(pluginRecord->fCallbacks->version >= kAuthorizationCallbacksVersion);

  NSArray *mechIDs = @[ @"Check", @"Prompt", @"Enablement" ];

  for (NSString *mechID in mechIDs) {
    CryptPluginCoreGlobalResult = -1;
    AuthorizationEngineRef engine;
    AuthorizationMechanismRef mechanism;
    pluginInterface->MechanismCreate(plugin, engine, [mechID UTF8String], &mechanism);
    MechanismRecord *mechanismRecord = (MechanismRecord *)mechanism;
    XCTAssertTrue(mechanismRecord->fMagic == kMechanismMagic);
    XCTAssertTrue(mechanismRecord->fPlugin != NULL);
    pluginInterface->MechanismInvoke(mechanism);
    XCTAssertTrue(CryptPluginCoreGlobalResult == kAuthorizationResultAllow);
    pluginInterface->MechanismDeactivate(mechanism);
    pluginInterface->MechanismDestroy(mechanism);
  }

  pluginInterface->PluginDestroy(plugin);
  free(callbacks);
}

@end
