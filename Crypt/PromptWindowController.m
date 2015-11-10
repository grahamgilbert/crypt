/*
    PromptWindowController.m
    VerifyAuthPlugin

    Copyright 2015 Thomas Burgin.

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

static NSString *const kTTSRequired = @"/Library/Security/SecurityAgentPlugins/VerifyAuthPlugin.bundle/Contents/Resources/shallnotpass.mp3";

@implementation PromptWindowController

- (id)init
{
    if ([super init]) {
        NSLog(@"VerifyAuth:MechanismInvoke:PromptWindowController:init [+] initWithWindowNibName");
        self = [super initWithWindowNibName:@"PromptWindowController"];
    }
    return self;
}

- (void)awakeFromNib {
    
    NSLog(@"VerifyAuth:MechanismInvoke:PromptWindowController [+] awakeFromNib.");
    // Make the window visible at the LoginWindow
    // Set the order so the Main Window will
    // be on top of the BackdropWindow
    [[self window] setCanBecomeVisibleWithoutLogin:TRUE];
    [[self window] setLevel:NSScreenSaverWindowLevel + 1];
    [[self window] orderFrontRegardless];
    
    [_mainView addSubview:_promptView];
    [_promptPINTextField becomeFirstResponder];
    
};

- (void)showStopLogin {
    
    // Get the Main Screen's size
    _screenRect = [[NSScreen mainScreen] frame];
    // Make a copy for editing
    NSRect windowRect = _screenRect;
    
    // Set the final destination of the Main Window
    // Centered on x
    // y offset by 80 towards the top of the display
    windowRect.origin.x = windowRect.size.width / 2 - 305;
    windowRect.origin.y = windowRect.size.height / 2 - 150;
    windowRect.size.width = 610.0;
    windowRect.size.height = 460.0;
    
    [_promptView removeFromSuperview];
    [[self window] setFrame:windowRect display:true];
    [_mainView addSubview:_stopLoginView];
    
    [self playAudio];
    [self dimBackdrop];
    
}

- (void)dimBackdrop {
    
    // Create the fading grey backdrop
    [_backdropWindow setCanBecomeVisibleWithoutLogin:TRUE];
    [_backdropWindow setFrame:_screenRect display:TRUE];
    NSColor *translucentColor = [[NSColor blackColor] colorWithAlphaComponent:0.65];
    [_backdropWindow setBackgroundColor:translucentColor];
    [_backdropWindow setOpaque:FALSE];
    [_backdropWindow setIgnoresMouseEvents:FALSE];
    [_backdropWindow setAlphaValue:0.0];
    [_backdropWindow orderFrontRegardless];
    
    // Second animation for the fading grey backdrop.
    // This NSViewAnimationFadeInEffect simply calls the setAlphaValue on the window over and over.
    // So we setAlphaValue to 0 initially.
    // Then the animation will fade in the window to alpha 1.
    NSDictionary *backdropWindowAnimationDict = [NSDictionary dictionaryWithObjectsAndKeys:
                                                 _backdropWindow, NSViewAnimationTargetKey,\
                                                 [NSValue valueWithRect:_screenRect], NSViewAnimationStartFrameKey, \
                                                 [NSValue valueWithRect:_screenRect], NSViewAnimationEndFrameKey, \
                                                 NSViewAnimationFadeInEffect, NSViewAnimationEffectKey,nil];
    
    NSViewAnimation *backdropWindowAnimation = [[NSViewAnimation alloc] initWithViewAnimations:[NSArray arrayWithObjects:backdropWindowAnimationDict, nil]];
    [backdropWindowAnimation setDuration:1.5];
    [backdropWindowAnimation setAnimationBlockingMode:NSAnimationNonblockingThreaded];
    [backdropWindowAnimation startAnimation];

}

- (void)playAudio {
    
    NSLog(@"VerifyAuth:MechanismInvoke:PromptWindowController [+] TTS kTTSRequired");
    _tts = [[NSSound alloc] initWithContentsOfFile:kTTSRequired byReference:FALSE];
    [_tts play];
    
}

- (IBAction)okayButton:(id)sender {
    
    [self close];
    [_backdropWindow close];
    _mechanism->fPlugin->fCallbacks->SetResult(_mechanism->fEngine, kAuthorizationResultDeny);
    
}


- (void)windowWillClose:(NSNotification *)notification {
    
    if (_tts != NULL) {
        [_tts stop];
    }
    [NSApp abortModal];
    
}

- (IBAction)loginButton:(id)sender {
    
    if (_pin && ![_pin isEqualToString:[_promptPINTextField stringValue]]) {
        NSLog(@"VerifyAuth:MechanismInvoke:PromptWindowController [+] Stop the login");
        [self showStopLogin];
    } else {
        NSLog(@"VerifyAuth:MechanismInvoke:PromptWindowController [+] Allow the login");
        [self close];
    }
    
}
@end
