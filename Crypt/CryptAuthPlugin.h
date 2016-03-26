/*
    CryptAuthPlugin.h
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

#import <Foundation/Foundation.h>
#include <CoreServices/CoreServices.h>
#include <Security/AuthorizationPlugin.h>
#include <Security/AuthSession.h>
#include <Security/AuthorizationTags.h>

#pragma mark
#pragma mark Core Data Structures

#pragma mark - Plugin
enum {
  kPluginMagic = 'PlgN'
};
struct PluginRecord {
  OSType fMagic;
  const AuthorizationCallbacks *fCallbacks;
};
typedef struct PluginRecord PluginRecord;

#pragma mark - Mechanism
enum {
  kMechanismMagic = 'Mchn'
};
struct MechanismRecord {
  OSType                          fMagic;
  AuthorizationEngineRef          fEngine;
  const PluginRecord *            fPlugin;
  Boolean                         fCheck;
  Boolean                         fCryptGUI;
  Boolean                         fEnablement;
};
typedef struct MechanismRecord MechanismRecord;

#pragma mark
#pragma mark ObjC AuthPlugin Wrapper

@interface CryptAuthPlugin : NSObject

#pragma mark
#pragma mark Mechanism Entry Points

/**
 * Called by the plugin host to create a mechanism, that is, a specific
 * instance of authentication.
 *
 * inPlugin is the plugin reference, that is, the value returned by
 * AuthorizationPluginCreate.
 *
 * inEngine is a reference to the engine that's running the plugin.
 * We need to keep it around because it's a parameter to all the
 * callbacks.
 *
 * mechanismId is the name of the mechanism.  When you configure your
 * mechanism in "/etc/authorization", you supply a string of the
 * form:
 *
 *   plugin:mechanism[,privileged]
 *
 * where:
 *
 * o plugin is the name of this bundle (without the extension)
 * o mechanism is the string that's passed to mechanismId
 * o privileged, if present, causes this mechanism to be
 *   instantiated in the privileged (rather than the GUI-capable)
 *   plug-in host
 *
 * You can use the mechanismId to support multiple types of
 * operation within the same plugin code.  For example, your plugin
 * might have two cooperating mechanisms, one that needs to use the
 * GUI and one that needs to run privileged.  This allows you to put
 * both mechanisms in the same plugin.
 *
 * outMechanism is a pointer to a place where you return a reference to
 * the newly created mechanism.
 *
 *  @param inPlugin AuthorizationPluginRef
 *  @param inEngine AuthorizationEngineRef
 *  @param mechanismId AuthorizationMechanismId
 *  @param outMechanism AuthorizationMechanismRef
 *
 *  @return OSStatus
 */
- (OSStatus)MechanismCreate:(AuthorizationPluginRef)inPlugin
                  EngineRef:(AuthorizationEngineRef)inEngine
                MechanismId:(AuthorizationMechanismId)mechanismId
               MechanismRef:(AuthorizationMechanismRef *)outMechanism;

/**
 * Called by the system to start authentication using this mechanism.
 * This is where the real work is done.
 *
 *  @param inMechanism AuthorizationMechanismRef
 *
 *  @return OSStatus
 */
- (OSStatus)MechanismInvoke:(AuthorizationMechanismRef)inMechanism;

/**
 * Called by the system to deactivate the mechanism, in the traditional
 * GUI sense of deactivating a window.  After your plugin has deactivated
 * it's UI, it should call the DidDeactivate callback.
 *
 *  @param inMechanism AuthorizationMechanismRef
 *
 *  @return OSStatus
 */
- (OSStatus)MechanismDeactivate:(AuthorizationMechanismRef)inMechanism;

/**
 *  Called by the system when it's done with the mechanism.
 *
 *  @param inMechanism AuthorizationMechanismRef
 *
 *  @return OSStatus
 */
- (OSStatus)MechanismDestroy:(AuthorizationMechanismRef)inMechanism;

#pragma mark
#pragma mark Plugin Entry Points

/**
 * Called by the system when it's done with the plugin.
 * All of the mechanisms should have been destroyed by this time.
 *
 *  @param inPlugin AuthorizationMechanismRef
 *
 *  @return OSStatus
 */
- (OSStatus)PluginDestroy:(AuthorizationPluginRef)inPlugin;

/**
 * The primary entry point of the plugin.  Called by the system
 * to instantiate the plugin.
 *
 * callbacks is a pointer to a bunch of callbacks that allow
 * your plugin to ask the system to do operations on your behalf.
 *
 * outPlugin is a pointer to a place where you can return a
 * reference to the newly created plugin.
 *
 * outPluginInterface is a pointer to a place where you can return
 * a pointer to your plugin dispatch table.
 *
 *  @param callbacks          AuthorizationCallbacks
 *  @param outPlugin          AuthorizationPluginRef
 *  @param outPluginInterface AuthorizationPluginInterface
 *
 *  @return OSStatus
 */
- (OSStatus)AuthorizationPluginCreate:(const AuthorizationCallbacks *)callbacks
                            PluginRef:(AuthorizationPluginRef *)outPlugin
                      PluginInterface:(const AuthorizationPluginInterface **)outPluginInterface;

@end
