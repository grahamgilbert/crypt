//
//  CryptGUI.h
//  Crypt
//
//  Created by Graham Gilbert on 10/11/2015.
//  Copyright © 2015 Graham Gilbert. All rights reserved.
//
#import <Foundation/Foundation.h>
#import "CryptAuthPlugin.h"

@interface CryptGUI : NSObject

@property MechanismRecord *mechanism;

- (id)initWithMechanism:(MechanismRecord *)inMechanism;
- (void)run;

@end
