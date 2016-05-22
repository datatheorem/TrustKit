/*
 
 TrustKit+Private.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#ifndef TrustKit_TrustKit_Private____FILEEXTENSION___
#define TrustKit_TrustKit_Private____FILEEXTENSION___

#import <TrustKit/TrustKit.h>
#import "ssl_pin_verifier.h"


#pragma mark Utility functions

void TSKLog(NSString *format, ...);

void sendPinFailureReport_async(TSKPinValidationResult validationResult, SecTrustRef serverTrust, NSString *serverHostname, NSString *notedHostname, NSDictionary *notedHostnameConfig, void (^onCompletion)(void));

void sendValidationNotification_async(NSString *serverHostname, SecTrustRef serverTrust, NSString *notedHostname, TSKPinValidationResult validationResult, TSKTrustDecision finalTrustDecision, NSTimeInterval validationDuration, void (^onCompletion)(void));

#pragma mark Methods for the unit tests

@interface TrustKit(Private)

+ (void) resetConfiguration;
+ (NSDictionary *) configuration;
+ (BOOL) wasTrustKitInitialized;
+ (NSString *) getDefaultReportUri;

@end


#endif
