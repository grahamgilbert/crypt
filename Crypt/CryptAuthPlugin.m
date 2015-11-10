//
//  CryptAuthPlugin.m
//  Crypt
//
//  Created by Graham Gilbert on 07/11/2015.
//  Copyright © 2015 Graham Gilbert. All rights reserved.
//

#import "CryptAuthPlugin.h"

#pragma mark --MechHeaders
// Special auto-generated header. It makes the Swift classes available to ObjC
#import "Crypt-Swift.h"
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
    
    OSStatus        err;
    PluginRecord *  plugin;
    
    assert(callbacks != NULL);
    assert(callbacks->version >= kAuthorizationCallbacksVersion);
    assert(outPlugin != NULL);
    assert(outPluginInterface != NULL);
    
    // Create the plugin.
    err = noErr;
    plugin = (PluginRecord *) malloc(sizeof(*plugin));
    if (plugin == NULL) {
        err = memFullErr;
    }
    
    // Fill it in.
    if (err == noErr) {
        plugin->fMagic     = kPluginMagic;
        plugin->fCallbacks = callbacks;
    }
    
    *outPlugin = plugin;
    *outPluginInterface = &gPluginInterface;
    
    assert( (err == noErr) == (*outPlugin != NULL) );
    
    return err;
    
}

- (OSStatus)MechanismCreate:(AuthorizationPluginRef)inPlugin
                  EngineRef:(AuthorizationEngineRef)inEngine
                MechanismId:(AuthorizationMechanismId)mechanismId
               MechanismRef:(AuthorizationMechanismRef *)outMechanism {
    
    OSStatus            err;
    PluginRecord *      plugin;
    MechanismRecord *   mechanism;
    
    plugin = (PluginRecord *) inPlugin;
    assert([self PluginValid:plugin]);
    assert(inEngine != NULL);
    assert(mechanismId != NULL);
    assert(outMechanism != NULL);
    
    err = noErr;
    mechanism = (MechanismRecord *) malloc(sizeof(*mechanism));
    if (mechanism == NULL) {
        err = memFullErr;
    }
    
    if (err == noErr) {
        mechanism->fMagic = kMechanismMagic;
        mechanism->fEngine = inEngine;
        mechanism->fPlugin = plugin;
        mechanism->fCheck = (strcmp(mechanismId, "Check") == 0);
        mechanism->fCryptGUI = (strcmp(mechanismId, "CryptGUI") == 0);
        mechanism->fEnablement = (strcmp(mechanismId, "Enablement") == 0);
    }
    
    *outMechanism = mechanism;
    
    assert( (err == noErr) == (*outMechanism != NULL) );
    
    return err;
    
}

- (OSStatus)MechanismInvoke:(AuthorizationMechanismRef)inMechanism {
    
    OSStatus                    err;
    MechanismRecord *           mechanism;
    
    mechanism = (MechanismRecord *) inMechanism;
    assert([self MechanismValid:mechanism]);
    
    // Call the Check mechanism
    #pragma mark --CryptGUI
    if (mechanism->fCryptGUI) {
        CryptGUI *cryptgui = [[CryptGUI alloc] initWithMechanism:mechanism];
        [cryptgui run];
    }
    
    // Call the GUI mechanism
    #pragma mark --Check
    if (mechanism->fCheck) {
        Check *check = [[Check alloc] initWithMechanism:mechanism];
        [check run];
    }
    
    // Call the Enablement mechanism
    #pragma mark --Enablement
    if (mechanism->fEnablement) {
        Enablement *enablement = [[Enablement alloc] initWithMechanism:mechanism];
        [enablement run];
    }
    
//    Enablement *enablement = [[Enablement alloc]initWithMechanism:mechanism];
//    [enablement run];
    
    // Default "Allow Login". Used if none of the mechanisms above are called or don't make
    // a decision
    NSLog(@"No mechs called");
    err = mechanism->fPlugin->fCallbacks->SetResult(mechanism->fEngine, kAuthorizationResultAllow);
    return err;
    
}

- (OSStatus)MechanismDeactivate:(AuthorizationMechanismRef)inMechanism {
    
    OSStatus            err;
    MechanismRecord *   mechanism;
    
    mechanism = (MechanismRecord *) inMechanism;
    assert([self MechanismValid:mechanism]);
    
    err = mechanism->fPlugin->fCallbacks->DidDeactivate(mechanism->fEngine);
    
    return err;
    
}

- (OSStatus)MechanismDestroy:(AuthorizationMechanismRef)inMechanism {
    
    MechanismRecord *mechanism;
    
    mechanism = (MechanismRecord *) inMechanism;
    assert([self MechanismValid:mechanism]);
    
    free(mechanism);
    
    return noErr;
    
}

- (OSStatus)PluginDestroy:(AuthorizationPluginRef)inPlugin {
    
    PluginRecord *plugin;
    
    plugin = (PluginRecord *) inPlugin;
    assert([self PluginValid:plugin]);
    
    free(plugin);
    
    return noErr;
    
}


- (BOOL)MechanismValid:(const MechanismRecord *)mechanism {
    
    return (mechanism != NULL)
    && (mechanism->fMagic == kMechanismMagic)
    && (mechanism->fEngine != NULL)
    && (mechanism->fPlugin != NULL);
    
}


- (BOOL)PluginValid:(const PluginRecord *)plugin {
    
    return (plugin != NULL)
    && (plugin->fMagic == kPluginMagic)
    && (plugin->fCallbacks != NULL)
    && (plugin->fCallbacks->version >= kAuthorizationCallbacksVersion);
    
}

@end
