//
//  CryptTests.m
//  CryptTests
//
//  Created by Tom Burgin on 11/10/17.
//  Copyright © 2017 Graham Gilbert. All rights reserved.
//

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

  NSArray *mechIDs = @[ @"Check", @"CryptGUI", @"Enablement" ];

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
