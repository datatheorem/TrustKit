/*
 
 TrustKit+Private.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#ifndef TrustKit_TrustKit_Private____FILEEXTENSION___
#define TrustKit_TrustKit_Private____FILEEXTENSION___

#import "TrustKit.h"
#import "Pinning/ssl_pin_verifier.h"
#import "Reporting/TSKBackgroundReporter.h"

// The logging function we use within TrustKit
#ifdef DEBUG
#define TSKLog(format, ...) NSLog(@"=== TrustKit: " format, ##__VA_ARGS__);
#else
#define TSKLog(format, ...)
#endif

#pragma mark Methods for the unit tests

@interface TrustKit(Private)

@property (nonatomic) TSKBackgroundReporter *pinFailureReporter;

- (void)sendValidationReport:(TSKPinningValidatorResult *)result;

+ (void) resetConfiguration;
+ (BOOL) wasTrustKitInitialized;
+ (NSString *) getDefaultReportUri;
+ (TSKBackgroundReporter *) getGlobalPinFailureReporter;
+ (void) setGlobalPinFailureReporter:(TSKBackgroundReporter *) reporter;

@end


#endif
