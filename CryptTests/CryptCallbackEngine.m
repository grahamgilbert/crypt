/*
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


#import "CryptCallbackEngine.h"

@interface CryptCallbackEngine ()
@property NSMutableDictionary *context;
@property NSMutableDictionary *hint;
@end

@implementation CryptCallbackEngine

- (instancetype)init {
  self = [super init];
  if (self) {
    _context = [[NSMutableDictionary alloc] init];
    _hint = [[NSMutableDictionary alloc] init];
  }
  return self;
}

- (OSStatus)getContextValue:(AuthorizationEngineRef)inEngine
                     forKey:(AuthorizationString)inKey
                   outFlags:(AuthorizationContextFlags *)outContextFlags
                   outValue:(const AuthorizationValue **)outValue {
  if (!inKey || !outValue) return errAuthorizationInternal;

  NSString *key = @(inKey);
  AuthorizationValue *value = (AuthorizationValue *)calloc(1, sizeof(AuthorizationValue));

  if ([self.context[key] isKindOfClass:[NSString class]]) {
    value->length = (size_t)[self.context[key] length];
    value->data = (void *)[self.context[key] UTF8String];
    *outValue = value;
  } else if ([key isEqualToString:@"uid"]) {
    value->length = (size_t)[self.context[key] length];
    value->data = (void *)[self.context[key] bytes];
    *outValue = value;
  }

  return value->length ? errAuthorizationSuccess : errAuthorizationInternal;
}

- (OSStatus)getHintValue:(AuthorizationEngineRef)inEngine
                  forKey:(AuthorizationString)inKey
                outValue:(const AuthorizationValue **)outValue {
  if (!inKey || !outValue) return errAuthorizationInternal;

  NSString *key = @(inKey);
  AuthorizationValue *value = (AuthorizationValue *)calloc(1, sizeof(AuthorizationValue));

  if ([self.hint[key] isKindOfClass:[NSData class]]) {
    value->length = (size_t)[self.hint[key] length];
    value->data = (void *)[self.hint[key] bytes];
    *outValue = value;
  }

  return value->length ? errAuthorizationSuccess : errAuthorizationInternal;
}

- (OSStatus)setHintValue:(AuthorizationEngineRef)inEngine
                  forKey:(AuthorizationString)inKey
                outValue:(const AuthorizationValue *)value {
  if (!inKey || !value) return errAuthorizationInternal;
  NSString *key = @(inKey);
  NSData *data = [NSData dataWithBytes:value->data length:value->length];
  if (data) self.hint[key] = data;
  return data ? errAuthorizationSuccess : errAuthorizationInternal;;
}

- (void)setUsername:(NSString *)username {
  self.context[@kAuthorizationEnvironmentUsername] = username;
}

- (void)setPassword:(NSString *)password {
  self.context[@kAuthorizationEnvironmentPassword] = password;
}

- (void)setUID:(uid_t)uid {
  NSData *data = [NSData dataWithBytes:&uid length:sizeof(uid_t)];
  self.context[@"uid"] = data;
}

@end
