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
#import "FDEAddUserService.h"

@interface ServiceDelegate : NSObject <NSXPCListenerDelegate>
@end

@implementation ServiceDelegate

- (BOOL)listener:(NSXPCListener *)listener
    shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
  newConnection.exportedInterface =
      [NSXPCInterface interfaceWithProtocol:@protocol(FDEAddUserServiceProtocol)];
  FDEAddUserService *exportedObject = [[FDEAddUserService alloc] init];
  newConnection.exportedObject = exportedObject;
  [newConnection resume];
  return YES;
}

@end

int main(int argc, const char *argv[]) {
  ServiceDelegate *delegate = [[ServiceDelegate alloc] init];
  NSXPCListener *listener = [NSXPCListener serviceListener];
  listener.delegate = delegate;
  [listener resume];
  return 0;
}
