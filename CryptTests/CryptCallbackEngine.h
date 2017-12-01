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


#import <Foundation/Foundation.h>

#import "CryptAuthPlugin.h"

@interface CryptCallbackEngine : NSObject

@property(nonatomic) NSString *username;
@property(nonatomic) NSString *password;
@property(nonatomic) uid_t UID;

- (OSStatus)getContextValue:(AuthorizationEngineRef)inEngine
                     forKey:(AuthorizationString)inKey
                   outFlags:(AuthorizationContextFlags *)outContextFlags
                   outValue:(const AuthorizationValue **)outValue;

- (OSStatus)getHintValue:(AuthorizationEngineRef)inEngine
                  forKey:(AuthorizationString)inKey
                outValue:(const AuthorizationValue **)outValue;

- (OSStatus)setHintValue:(AuthorizationEngineRef)inEngine
                  forKey:(AuthorizationString)inKey
                outValue:(const AuthorizationValue *)value;

@end
