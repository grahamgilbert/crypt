/*
 CryptAuthPlugin.h
 Crypt
 
 Copyright 2016 The Crypt Project.
 
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

#import "FDEAddUserService.h"

#include <dlfcn.h>

@interface FDEAddUserService ()

@property void *libcsfdeHandle;
@property void *libodfdeHandle;

@end

@implementation FDEAddUserService

- (id)init {
  self = [super init];
  if (self) {
    // Open libcsfde.dylib.
    _libcsfdeHandle = dlopen("libcsfde.dylib", RTLD_LOCAL | RTLD_LAZY);
    if (!_libcsfdeHandle) {
      NSLog(@"Crypt:FDEAddUserService:[!] Unable to load library: %s\n", dlerror());
    }
    // Open libodfde.dylib.
    _libodfdeHandle = dlopen("libodfde.dylib", RTLD_LOCAL | RTLD_LAZY);
    if (!_libodfdeHandle) {
      NSLog(@"Crypt:FDEAddUserService:[!] Unable to load library: %s\n", dlerror());
    }
  }
  return self;
}

- (CFStringRef)CSFDEStorePassphrase:(NSString *)password {
  CFStringRef passwordRef = NULL;
  
  // Grab the CSFDEStorePassphrase symbol
  CFStringRef (*CSFDEStorePassphrase)(const char *) =
  dlsym(self.libcsfdeHandle, "CSFDEStorePassphrase");
  
  if (!CSFDEStorePassphrase) {
    NSLog(@"Crypt:FDEAddUserService:[!] Unable to get symbol: %s\n", dlerror());
    return passwordRef;
  }
  
  passwordRef = CSFDEStorePassphrase((const char *)[password UTF8String]);
  return passwordRef;
}

- (void)CSFDERemovePassphrase:(CFStringRef)passwordRef {
  // Grab the CSFDEStorePassphrase symbol
  void (*CSFDERemovePassphrase)(CFStringRef) =
  dlsym(self.libcsfdeHandle, "CSFDERemovePassphrase");
  
  if (!CSFDERemovePassphrase) {
    NSLog(@"Crypt:FDEAddUserService:[!] Unable to get symbol: %s\n", dlerror());
  }
  
  CSFDERemovePassphrase(passwordRef);
}

- (void)ODFDEAddUser:(NSString *)username
        withPassword:(NSString *)password
           withReply:(void (^)(BOOL))reply {
  // Check libHandles
  if (!self.libcsfdeHandle || !self.libodfdeHandle) {
    NSLog(@"Crypt:FDEAddUserService:[!] libHandles not loaded");
    reply(false);
    return;
  }
  
  // Grab the ODFDEAddUser symbol
  BOOL (*ODFDEAddUser)(CFStringRef,
                       CFStringRef,
                       CFStringRef,
                       CFStringRef) = dlsym(self.libodfdeHandle, "ODFDEAddUser");
  if (!ODFDEAddUser) {
    NSLog(@"Crypt:FDEAddUserService:[!] Unable to get symbol: %s\n", dlerror());
    reply(false);
    return;
  }
  
  CFStringRef passwordRef = [self CSFDEStorePassphrase:password];
  
  // Try and add the user
  BOOL ret = ODFDEAddUser((__bridge CFStringRef)username, passwordRef,
                          (__bridge CFStringRef)username, passwordRef);
  
  if (passwordRef) {
    [self CSFDERemovePassphrase:passwordRef];
  }
  reply(ret);
}

@end
