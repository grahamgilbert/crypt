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

#import "PromptWindowController.h"

@interface PromptWindowController()

@property NSRect screenRect;
@property (weak) IBOutlet NSView *mainView;
@property (weak) IBOutlet NSView *promptView;
- (IBAction)continueClicked:(id)sender;
@property (weak) IBOutlet NSTextField *windowText;

@end

@implementation PromptWindowController

- (id)init {
    self = [super init];
    if (self) {
        NSLog(@"Crypt:MechanismInvoke:PromptWindowController:init [+] initWithWindowNibName");
        self = [super initWithWindowNibName:@"PromptWindowController"];
    }
    return self;
}

- (void)awakeFromNib {
    NSLog(@"Crypt:MechanismInvoke:PromptWindowController [+] awakeFromNib.");
    // Make the window visible at the LoginWindow
    // Set the order so the Main Window will
    // be on top of the BackdropWindow
    [[self window] setCanBecomeVisibleWithoutLogin:TRUE];
    [[self window] setLevel:NSScreenSaverWindowLevel + 1];
    [[self window] orderFrontRegardless];
    [self.mainView addSubview:_promptView];
};

- (void)windowWillClose:(NSNotification *)notification {
    [NSApp abortModal];
}

- (IBAction)continueClicked:(id)sender {
    self.mechanism->fPlugin->fCallbacks->SetResult(_mechanism->fEngine, kAuthorizationResultAllow);
    [self close];
}
@end
