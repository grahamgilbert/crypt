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

#import "PromptWindowController.h"

@interface PromptWindowController()
@property const MechanismRecord *mechanism;
@property NSRect screenRect;
@property (weak) IBOutlet NSView *mainView;
@property (weak) IBOutlet NSView *promptView;
- (IBAction)continueClicked:(id)sender;
@end

@implementation PromptWindowController

- (id)initWithMechanismRecord:(const MechanismRecord *)mechanism {
  self = [super initWithWindowNibName:@"PromptWindowController"];
  if (self) {
    NSLog(@"Crypt:PromptWindowController initWithWindowNibName");
    _mechanism = mechanism;
  }
  return self;
}

- (void)awakeFromNib {
  NSLog(@"Crypt:PromptWindowController awakeFromNib.");
  // Make the window visible at the LoginWindow
  // Set the order so the Main Window will
  // be on top of the BackdropWindow
  [[self window] setCanBecomeVisibleWithoutLogin:TRUE];
  [[self window] setLevel:NSScreenSaverWindowLevel + 1];
  [[self window] orderFrontRegardless];
  [self.mainView addSubview:self.promptView];
};

- (void)windowWillClose:(NSNotification *)notification {
  [NSApp abortModal];
}

- (IBAction)continueClicked:(id)sender {
  self.mechanism->fPlugin->fCallbacks->SetResult(self.mechanism->fEngine,
                                                 kAuthorizationResultAllow);
  [self close];
}

@end
