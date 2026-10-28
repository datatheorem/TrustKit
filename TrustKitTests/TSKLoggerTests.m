//
//  TSKLoggerTests.m
//  TrustKit
//
//  Created by Alban Diquet on 8/29/16.
//  Copyright © 2016 TrustKit. All rights reserved.
//

#import "../TrustKit/Pinning/TSKSPKIHashCache.h"
#import "../TrustKit/TSKPinningValidator_Private.h"
#import "../TrustKit/parse_configuration.h"
#import "../TrustKit/public/TrustKit/TSKPinningValidator.h"
#import "../TrustKit/public/TrustKit/TSKPinningValidatorResult.h"
#import "../TrustKit/public/TrustKit/TSKTrustKitConfig.h"
#import "../TrustKit/public/TrustKit/TrustKit.h"
#import "TSKCertificateUtils.h"
#import <OSLog/OSLog.h>
#import <XCTest/XCTest.h>

@interface TSKLoggerTests : XCTestCase

@end

@implementation TSKLoggerTests

- (void)testPinValidationFailureIsLoggedAsError {
    NSDate *startDate = [NSDate date];

    SecCertificateRef rootCertificate = [TSKCertificateUtils createCertificateFromDer:@"GoodRootCA"];
    SecCertificateRef leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com"];
    SecCertificateRef certChainArray[1] = { leafCertificate };
    SecCertificateRef trustStoreArray[1] = { rootCertificate };
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:1
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:1];

    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(@{
        kTSKSwizzleNetworkDelegates: @NO,
        kTSKPinnedDomains: @ { @"www.good.com": @ { kTSKPublicKeyHashes: @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="] } }
    });
    TSKPinningValidator *validator = [[TSKPinningValidator alloc]
        initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                            hashCache:[[TSKSPKIHashCache alloc] initWithIdentifier:@"test"]
        ignorePinsForUserTrustAnchors:NO
              validationCallbackQueue:dispatch_get_main_queue()
                   validationCallback:^(TSKPinningValidatorResult *result, NSString *notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *notedHostnamePinningPolicy) {
                   }];

    XCTAssertEqual([validator evaluateTrust:trust forHostname:@"www.good.com"], TSKTrustDecisionShouldBlockConnection);
    CFRelease(trust);
    CFRelease(leafCertificate);
    CFRelease(rootCertificate);

    NSPredicate *trustKitEntries = [NSPredicate predicateWithFormat:@"subsystem == %@ AND category == %@", @"com.datatheorem.trustkit", @"TrustKit"];
    dispatch_semaphore_t failureEntryFound = dispatch_semaphore_create(0);
    __block OSLogEntryLogLevel failureEntryLevel = OSLogEntryLogLevelUndefined;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:30];
        while ([deadline timeIntervalSinceNow] > 0) {
            OSLogStore *store = [OSLogStore storeWithScope:OSLogStoreCurrentProcessIdentifier error:nil];
            OSLogEnumerator *entries = [store entriesEnumeratorWithOptions:0 position:[store positionWithDate:startDate] predicate:trustKitEntries error:nil];
            for (OSLogEntry *entry in entries) {
                if ([entry isKindOfClass:[OSLogEntryLog class]] && [entry.composedMessage isEqualToString:@"Pin validation failed for www.good.com"]) {
                    failureEntryLevel = ((OSLogEntryLog *)entry).level;
                    dispatch_semaphore_signal(failureEntryFound);
                    return;
                }
            }
            [NSThread sleepForTimeInterval:0.25];
        }
    });

    if (dispatch_semaphore_wait(failureEntryFound, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC)) != 0) {
        XCTFail(@"The pin validation failure did not reach the log store within 30 seconds");
        return;
    }
    XCTAssertEqual(failureEntryLevel, OSLogEntryLogLevelError);
}

@end
