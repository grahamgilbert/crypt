/*
    CryptAuthPlugin.m
    Crypt

    Copyright 2015 The Crypt Project.

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


#import "CryptAuthPlugin.h"
#import "Crypt-Swift.h" // Auto-generated header - Makes the Swift classes available to ObjC
#import "PromptWindowController.h"
#import "CryptGUI.h"

#pragma mark
#pragma mark Entry Point Wrappers

CryptAuthPlugin *authorizationPlugin = nil;

static OSStatus PluginDestroy(AuthorizationPluginRef inPlugin) {
    return [authorizationPlugin PluginDestroy:inPlugin];
}

static OSStatus MechanismCreate(AuthorizationPluginRef inPlugin,
                                AuthorizationEngineRef inEngine,
                                AuthorizationMechanismId mechanismId,
                                AuthorizationMechanismRef *outMechanism) {
    return [authorizationPlugin MechanismCreate:inPlugin
                                      EngineRef:inEngine
                                    MechanismId:mechanismId
                                   MechanismRef:outMechanism];
}

static OSStatus MechanismInvoke(AuthorizationMechanismRef inMechanism) {
    return [authorizationPlugin MechanismInvoke:inMechanism];
}

static OSStatus MechanismDeactivate(AuthorizationMechanismRef inMechanism) {
    return [authorizationPlugin MechanismDeactivate:inMechanism];
}

static OSStatus MechanismDestroy(AuthorizationMechanismRef inMechanism) {
    return [authorizationPlugin MechanismDestroy:inMechanism];
}

static AuthorizationPluginInterface gPluginInterface = {
    kAuthorizationPluginInterfaceVersion,
    &PluginDestroy,
    &MechanismCreate,
    &MechanismInvoke,
    &MechanismDeactivate,
    &MechanismDestroy
};

extern OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *callbacks,
                                          AuthorizationPluginRef *outPlugin,
                                          const AuthorizationPluginInterface **outPluginInterface) {
    if (authorizationPlugin == nil) {
        authorizationPlugin = [[CryptAuthPlugin alloc] init];
    }

    return [authorizationPlugin AuthorizationPluginCreate:callbacks
                                                PluginRef:outPlugin
                                          PluginInterface:outPluginInterface];
}

#pragma mark
#pragma mark CryptAuthPlugin Implementation
@implementation CryptAuthPlugin

- (OSStatus)AuthorizationPluginCreate:(const AuthorizationCallbacks *)callbacks
                            PluginRef:(AuthorizationPluginRef *)outPlugin
                      PluginInterface:(const AuthorizationPluginInterface **)outPluginInterface {
    PluginRecord *plugin = (PluginRecord *) malloc(sizeof(*plugin));
    if (plugin == NULL) return errSecMemoryError;
    plugin->fMagic = kPluginMagic;
    plugin->fCallbacks = callbacks;
    *outPlugin = plugin;
    *outPluginInterface = &gPluginInterface;
    return errSecSuccess;
}

- (OSStatus)MechanismCreate:(AuthorizationPluginRef)inPlugin
                  EngineRef:(AuthorizationEngineRef)inEngine
                MechanismId:(AuthorizationMechanismId)mechanismId
               MechanismRef:(AuthorizationMechanismRef *)outMechanism {
    MechanismRecord *mechanism = (MechanismRecord *)malloc(sizeof(MechanismRecord));
    if (mechanism == NULL) return errSecMemoryError;
    mechanism->fMagic = kMechanismMagic;
    mechanism->fEngine = inEngine;
    mechanism->fPlugin = (PluginRecord *)inPlugin;;
    mechanism->fCheck = (strcmp(mechanismId, "Check") == 0);
    mechanism->fCryptGUI = (strcmp(mechanismId, "CryptGUI") == 0);
    mechanism->fEnablement = (strcmp(mechanismId, "Enablement") == 0);
    *outMechanism = mechanism;
    return errSecSuccess;
}

- (OSStatus)MechanismInvoke:(AuthorizationMechanismRef)inMechanism {
    OSStatus err;
    MechanismRecord *mechanism = (MechanismRecord *)inMechanism;

    // Call the GUI mechanism
    #pragma mark --Check
    if (mechanism->fCheck) {
        Check *check = [[Check alloc] initWithMechanism:mechanism];
        [check run];
    }

    // Call the Check mechanism
    #pragma mark --CryptGUI
    if (mechanism->fCryptGUI) {
        CryptGUI *cryptgui = [[CryptGUI alloc] initWithMechanism:mechanism];
        [cryptgui run];
    }

    // Call the Enablement mechanism
    #pragma mark --Enablement
    if (mechanism->fEnablement) {
        Enablement *enablement = [[Enablement alloc] initWithMechanism:mechanism];
        [enablement run];
    }

    // Default "Allow Login". Used if none of the mechanisms above are called or don't make
    // a decision
    err = mechanism->fPlugin->fCallbacks->SetResult(mechanism->fEngine, kAuthorizationResultAllow);
    return err;
}

- (OSStatus)MechanismDeactivate:(AuthorizationMechanismRef)inMechanism {
    OSStatus err;
    MechanismRecord *mechanism = (MechanismRecord *)inMechanism;
    err = mechanism->fPlugin->fCallbacks->DidDeactivate(mechanism->fEngine);
    return err;
}

- (OSStatus)MechanismDestroy:(AuthorizationMechanismRef)inMechanism {
    free(inMechanism);
    return noErr;
}

- (OSStatus)PluginDestroy:(AuthorizationPluginRef)inPlugin {
    free(inPlugin);
    return noErr;
}

@end
