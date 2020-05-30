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

#import "TouchID.h"
#include <sys/types.h>
#include <sys/sysctl.h>
#import <Cordova/CDV.h>
#import <LocalAuthentication/LocalAuthentication.h>

@implementation TouchID

static NSString *const FingerprintDatabaseStateKey = @"FingerprintDatabaseStateKey";

// These two combined need to be unique, so one can be fixed
NSString *keychainItemIdentifier = @"TouchIDKey";
NSString *keychainItemServiceName;

- (void) isAvailable:(CDVInvokedUrlCommand*)command {

  if (NSClassFromString(@"LAContext") == NULL) {
    [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR] callbackId:command.callbackId];
    return;
  }

  [self.commandDelegate runInBackground:^{

    NSError *error = nil;
    LAContext *laContext = [[LAContext alloc] init];

    if ([laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
      NSString *biometryType = @"touch";
      if (@available(iOS 11.0, *)) {
        if (laContext.biometryType == LABiometryTypeFaceID) {
          biometryType = @"face";
        }
      }
      [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:biometryType]
                                  callbackId:command.callbackId];
    } else {
      NSArray *errorKeys = @[@"code", @"localizedDescription"];
      [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[error dictionaryWithValuesForKeys:errorKeys]]
                                  callbackId:command.callbackId];
    }
  }];
}

- (void) didFingerprintDatabaseChange:(CDVInvokedUrlCommand*)command {
  // Get enrollment state
  [self.commandDelegate runInBackground:^{
    LAContext *laContext = [[LAContext alloc] init];
    NSError *error = nil;

    // we expect the dev to have checked 'isAvailable' already so this should not return an error,
    // we do however need to run canEvaluatePolicy here in order to get a non-nil evaluatedPolicyDomainState
    if (![laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
      [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:[error localizedDescription]] callbackId:command.callbackId];
      return;
    }

    // only supported on iOS9+, so check this.. if not supported just report back as false
    if (![laContext respondsToSelector:@selector(evaluatedPolicyDomainState)]) {
      [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:NO] callbackId:command.callbackId];
      return;
    }

    NSData * state = [laContext evaluatedPolicyDomainState];
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

// this 'default' method uses keychain instead of localauth so the passcode fallback can be used
- (void) verifyFingerprint:(CDVInvokedUrlCommand*)command {

  NSString *message = [command.arguments objectAtIndex:0];
  NSString *callbackId = command.callbackId;

  [self.commandDelegate runInBackground:^{

    if (keychainItemServiceName == nil) {
      NSString *bundleID = [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleIdentifier"];
      keychainItemServiceName = [bundleID stringByAppendingString:@".TouchIDPlugin"];
    }

    if (![self createKeyChainEntry]) {
      NSLog(@"Keychain trouble. Falling back to verifyFingerprintWithCustomPasswordFallback.");
      [self verifyFingerprintWithCustomPasswordFallback:command];
      return;
    }

    // Create the keychain query attributes using the values from the first part of the code.
    NSMutableDictionary * query = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                   (__bridge id)(kSecClassGenericPassword), kSecClass,
                                   keychainItemIdentifier, kSecAttrAccount,
                                   keychainItemServiceName, kSecAttrService,
                                   message, kSecUseOperationPrompt,
                                   nil];

    // Start the query and the fingerprint scan and/or device passcode validation
    OSStatus userPresenceStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);

    // Ignore the found content of the key chain entry (the dummy password) and only evaluate the return code.
    if (noErr == userPresenceStatus)
    {
      NSLog(@"Fingerprint or device passcode validated.");
      [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK]
                                  callbackId:command.callbackId];
    }
    else
    {
      NSLog(@"Fingerprint or device passcode could not be validated. Status %d.", (int) userPresenceStatus);

      NSError *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:userPresenceStatus userInfo:nil];
      NSArray *errorKeys = @[@"code", @"localizedDescription"];
      [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                           messageAsDictionary:[error dictionaryWithValuesForKeys:errorKeys]]
                                  callbackId:callbackId];
      return;
    }
  }];
}

// This implementation uses LocalAuthentication and has no built-in passcode fallback
- (void) verifyFingerprintWithCustomPasswordFallback:(CDVInvokedUrlCommand*)command {
  NSString *message = [command.arguments objectAtIndex:0];
  [self verifyFingerprintWithCustomPasswordFallback:command.callbackId withMessage:message andEnterPasswordLabel:nil];
}

- (void) verifyFingerprintWithCustomPasswordFallbackAndEnterPasswordLabel:(CDVInvokedUrlCommand*)command {
  NSString *message = [command.arguments objectAtIndex:0];
  NSString *enterPasswordLabel = [command.arguments objectAtIndex:1];
  [self verifyFingerprintWithCustomPasswordFallback:command.callbackId withMessage:message andEnterPasswordLabel:enterPasswordLabel];
}

- (void) verifyFingerprintWithCustomPasswordFallback:(NSString*)callbackId withMessage:(NSString*)message andEnterPasswordLabel:(NSString*)enterPasswordLabel {
  self.MyKeychainWrapper = [[KeychainWrapper alloc]init];

  if (NSClassFromString(@"LAContext") == NULL) {
    [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR]
       callbackId:callbackId];
    return;
  }

  [self.commandDelegate runInBackground:^{
    NSError *error = nil;
    LAContext *laContext = [[LAContext alloc] init];

    if (![laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
      [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:[error localizedDescription]]
         callbackId:callbackId];
      return;
    }

    // if we add a 'verifyFingerprintWithOptions' method we can add stuff like this:
    // the nr of seconds you allow to reuse the last touchid device unlock (default 0, so never reuse)
//    laContext.touchIDAuthenticationAllowableReuseDuration = 30;

    // this replaces the default 'Enter password' button label
    if (enterPasswordLabel != nil) {
      laContext.localizedFallbackTitle = enterPasswordLabel;
    }

    [laContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:message reply:^(BOOL authOK, NSError *error) {
      if (authOK) {
        NSString *password = [self.MyKeychainWrapper myObjectForKey:@"v_Data"];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString: password];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
      } else {
        // invoked when the scan failed 3 times in a row, the cancel button was pressed, or the 'enter password' button was pressed
        NSArray *errorKeys = @[@"code", @"localizedDescription"];
        [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                    messageAsDictionary:[error dictionaryWithValuesForKeys:errorKeys]]
                                    callbackId:callbackId];
      }
    }];
  }];
}

// Note that this needs to run only once but it can deal with multiple runs
- (BOOL) createKeyChainEntry {
  NSMutableDictionary	* attributes = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                      (__bridge id)(kSecClassGenericPassword), kSecClass,
                                      keychainItemIdentifier, kSecAttrAccount,
                                      keychainItemServiceName, kSecAttrService,
                                      nil];

  CFErrorRef accessControlError = NULL;
  SecAccessControlRef accessControlRef = SecAccessControlCreateWithFlags(
                                                                         kCFAllocatorDefault,
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


- (void) askPassword:(CDVInvokedUrlCommand*)command {
    LAContext *laContext = [[LAContext alloc] init];
    __block  NSString *message;
    NSString *reasonMessage = [command.arguments objectAtIndex:0]; // @"Unlock access to locked feature"
    
    [laContext evaluatePolicy:LAPolicyDeviceOwnerAuthentication localizedReason:reasonMessage reply:^(BOOL success, NSError *authenticationError) {
        if (success) {
            message = @"success";
            
            [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:message]
            callbackId:command.callbackId];
        }
        else {
            message = [NSString stringWithFormat:@"%@", authenticationError.localizedDescription];
            
            [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:[authenticationError localizedDescription]]
            callbackId:command.callbackId];
        }
    }];
}

// ORIGINAL

//- (void)isAvailable:(CDVInvokedUrlCommand*)command{
//    if (NSClassFromString(@"LAContext") == NULL) {
//        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
//        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
//        return;
//    }
//    
//    self.laContext = [[LAContext alloc] init];
//    
//    if ([self.laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil]) {
//        NSString *biometryType = @"";
//        if (@available(iOS 11.0, *)) {
//            if (self.laContext.biometryType == LABiometryTypeFaceID) {
//                biometryType = @"face";
//            }
//            else {
//                biometryType = @"touch";
//            }
//            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:biometryType];
//            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
//        }
//        else {
//            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString: @"touch"];
//            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
//        }
//    }
//    else {
//        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Touch ID not available"];
//        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
//    }
//}

- (void)setLocale:(CDVInvokedUrlCommand*)command{
  CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)has:(CDVInvokedUrlCommand*)command{
  	self.TAG = (NSString*)[command.arguments objectAtIndex:0];
    BOOL hasLoginKey = [[NSUserDefaults standardUserDefaults] boolForKey:self.TAG];
    if(hasLoginKey){
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    else{
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"No Password in chain"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

- (void)save:(CDVInvokedUrlCommand*)command{
	 	self.TAG = (NSString*)[command.arguments objectAtIndex:0];
    NSString* password = (NSString*)[command.arguments objectAtIndex:1];
    @try {
        self.MyKeychainWrapper = [[KeychainWrapper alloc]init];
        [self.MyKeychainWrapper mySetObject:password forKey:(__bridge id)(kSecValueData)];
        [self.MyKeychainWrapper writeToKeychain];
        [[NSUserDefaults standardUserDefaults]setBool:true forKey:self.TAG];
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
	 	self.TAG = (NSString*)[command.arguments objectAtIndex:0];
    @try {

        if(self.TAG && [[NSUserDefaults standardUserDefaults] objectForKey:self.TAG])
        {
            self.MyKeychainWrapper = [[KeychainWrapper alloc]init];
            [self.MyKeychainWrapper resetKeychainItem];
        }


        [[NSUserDefaults standardUserDefaults] removeObjectForKey:self.TAG];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    @catch(NSException *exception) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Could not delete password from chain"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }


}

- (void) verify:(CDVInvokedUrlCommand*)command {
  NSString *message = [command.arguments objectAtIndex:0];
  NSString *enterPasswordLabel = [command.arguments objectAtIndex:1];
  [self verifyFingerprintWithCustomPasswordFallback:command.callbackId withMessage:message andEnterPasswordLabel:enterPasswordLabel];
}

//-(void)verify:(CDVInvokedUrlCommand*)command{
//	 	self.TAG = (NSString*)[command.arguments objectAtIndex:0];
//	  NSString* message = (NSString*)[command.arguments objectAtIndex:1];
//    self.laContext = [[LAContext alloc] init];
//    self.MyKeychainWrapper = [[KeychainWrapper alloc]init];
//
//    BOOL hasLoginKey = [[NSUserDefaults standardUserDefaults] boolForKey:self.TAG];
//    if(hasLoginKey){
//        NSError * error;
//        BOOL touchIDAvailable = [self.laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
//
//        if(touchIDAvailable){
//            [self.laContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:message reply:^(BOOL success, NSError *error) {
//                dispatch_async(dispatch_get_main_queue(), ^{
//
//                if(success){
//                    NSString *password = [self.MyKeychainWrapper myObjectForKey:@"v_Data"];
//                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString: password];
//                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
//                }
//                    if(error != nil) {
//                        NSDictionary *errorDictionary = @{@"OS":@"iOS",@"ErrorCode":[NSString stringWithFormat:@"%li", (long)error.code],@"ErrorMessage":error.localizedDescription};
//                        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:errorDictionary];
//                        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
//                    }
//                });
//            }];
//        }
//        else{
//            if(error)
//            {
//                //If an error is returned from LA Context (should always be true in this situation)
//                NSDictionary *errorDictionary = @{@"OS":@"iOS",@"ErrorCode":[NSString stringWithFormat:@"%li", (long)error.code],@"ErrorMessage":error.localizedDescription};
//                CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:errorDictionary];
//                [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
//            }
//            else
//            {
//                //Should never come to this, but we treat it anyway
//                CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Touch ID not available"];
//                [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
//            }
//        }
//    }
//    else{
//           CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"-1"];
//            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
//    }
//}

@end
