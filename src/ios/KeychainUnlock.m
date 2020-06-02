/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

#import "KeychainUnlock.h"
#include <sys/types.h>
#include <sys/sysctl.h>
#import <Cordova/CDV.h>
#import <LocalAuthentication/LocalAuthentication.h>

@implementation KeychainUnlock

static NSString *const FingerprintDatabaseStateKey = @"FingerprintDatabaseStateKey";

// These two combined need to be unique, so one can be fixed
NSString *keychainItemIdentifier = @"KeychainUnlockKey";
NSString *keychainItemServiceName;

- (void) available:(CDVInvokedUrlCommand*)command {

  if (NSClassFromString(@"LAContext") == NULL) {
    [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR] callbackId:command.callbackId];
    return;
  }

  [self.commandDelegate runInBackground:^{

    NSError *error = nil;
    LAContext *context = [[LAContext alloc] init];

    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
      [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK] callbackId:command.callbackId];
    } else {
      NSArray *errorKeys = @[@"code", @"localizedDescription"];
      [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[error dictionaryWithValuesForKeys:errorKeys]]
                                  callbackId:command.callbackId];
    }
  }];
}

- (void) update:(CDVInvokedUrlCommand*)command {
  // Get enrollment state
  [self.commandDelegate runInBackground:^{
    LAContext *context = [[LAContext alloc] init];
    NSError *error = nil;

    // we expect the dev to have checked 'isAvailable' already so this should not return an error,
    // we do however need to run canEvaluatePolicy here in order to get a non-nil evaluatedPolicyDomainState
    if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
      [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:[error localizedDescription]] callbackId:command.callbackId];
      return;
    }

    // only supported on iOS9+, so check this.. if not supported just report back as false
    if (![context respondsToSelector:@selector(evaluatedPolicyDomainState)]) {
      [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:NO] callbackId:command.callbackId];
      return;
    }

    NSData * state = [context evaluatedPolicyDomainState];
    if (state != nil) {

      NSString * stateStr = [state base64EncodedStringWithOptions:0];

      NSString * storedState = [[NSUserDefaults standardUserDefaults] stringForKey:FingerprintDatabaseStateKey];

      // whenever a finger is added/changed/removed the value of the storedState changes,
      // so compare agains a value we previously stored in the context of this app
      BOOL changed = storedState != nil && ![stateStr isEqualToString:storedState];

      [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:changed] callbackId:command.callbackId];

      // Store enrollment
      [[NSUserDefaults standardUserDefaults] setObject:stateStr forKey:FingerprintDatabaseStateKey];
      [[NSUserDefaults standardUserDefaults] synchronize];
    }
  }];
}

- (void) verify:(CDVInvokedUrlCommand*)command {
  self.tag = (NSString*)[command.arguments objectAtIndex:0];
  NSString *message = [command.arguments objectAtIndex:1];
  self.wrapper = [[KeychainWrapper alloc]init];

  if (NSClassFromString(@"LAContext") == NULL) {
    [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR]
       callbackId:command.callbackId];
    return;
  }

  [self.commandDelegate runInBackground:^{
    NSError *error = nil;
    LAContext *context = [[LAContext alloc] init];

    if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
      [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:[error localizedDescription]]
         callbackId:command.callbackId];
      return;
    }

    // if we add a 'verifyFingerprintWithOptions' method we can add stuff like this:
    // the nr of seconds you allow to reuse the last touchid device unlock (default 0, so never reuse)
    // context.touchIDAuthenticationAllowableReuseDuration = 30;

    [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication localizedReason:message reply:^(BOOL authOK, NSError *error) {
      if (authOK) {
        NSString *password = [self.wrapper myObjectForKey:@"v_Data"];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString: password];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
      } else {
        // invoked when the scan failed 3 times in a row, the cancel button was pressed, or the 'enter password' button was pressed
        NSArray *errorKeys = @[@"code", @"localizedDescription"];
        [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[error dictionaryWithValuesForKeys:errorKeys]]
                                    callbackId:command.callbackId];
      }
    }];
  }];
}

- (void)save:(CDVInvokedUrlCommand*)command{
    self.tag = (NSString*)[command.arguments objectAtIndex:0];
    NSString* password = (NSString*)[command.arguments objectAtIndex:1];
    @try {
        self.wrapper = [[KeychainWrapper alloc]init];
        [self.wrapper mySetObject:password forKey:(__bridge id)(kSecValueData)];
        [self.wrapper writeToKeychain];
        [[NSUserDefaults standardUserDefaults]setBool:true forKey:self.tag];
        [[NSUserDefaults standardUserDefaults]synchronize];

        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    @catch(NSException *exception){
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Password could not be save in chain"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

-(void)delete:(CDVInvokedUrlCommand*)command{
	 	self.tag = (NSString*)[command.arguments objectAtIndex:0];
    @try {

        if(self.tag && [[NSUserDefaults standardUserDefaults] objectForKey:self.tag])
        {
            self.wrapper = [[KeychainWrapper alloc]init];
            [self.wrapper resetKeychainItem];
        }

        [[NSUserDefaults standardUserDefaults] removeObjectForKey:self.tag];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    @catch(NSException *exception) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Could not delete password from chain"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

// Note that this needs to run only once but it can deal with multiple runs
- (BOOL) createKeyChainEntry {
  NSMutableDictionary	* attributes = [[NSMutableDictionary alloc] initWithObjectsAndKeys:(__bridge id)(kSecClassGenericPassword), kSecClass,
                                      keychainItemIdentifier, kSecAttrAccount, keychainItemServiceName, kSecAttrService, nil];

  CFErrorRef accessControlError = NULL;
  SecAccessControlRef accessControlRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                         kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                                         2, // either kSecAccessControlBiometryAny (iOS 11.3+) or kSecAccessControlTouchIDAny (iOS < 11.3),
                                                                         &accessControlError);
  if (accessControlRef == NULL || accessControlError != NULL)
  {
    NSLog(@"Can't store identifier '%@' in the KeyChain: %@.", keychainItemIdentifier, accessControlError);
    return NO;
  }

  attributes[(__bridge id)kSecAttrAccessControl] = (__bridge id)accessControlRef;
  attributes[(__bridge id)kSecUseAuthenticationUI] = @YES;
  // The content of the password is not important.
  attributes[(__bridge id)kSecValueData] = [@"dummy content" dataUsingEncoding:NSUTF8StringEncoding];

  SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
  return YES;
}

- (void)has:(CDVInvokedUrlCommand*)command{
  	self.tag = (NSString*)[command.arguments objectAtIndex:0];
    BOOL hasLoginKey = [[NSUserDefaults standardUserDefaults] boolForKey:self.tag];
    if(hasLoginKey){
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    else{
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"No Password in chain"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

@end
