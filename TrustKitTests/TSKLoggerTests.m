//
//  TSKLoggerTests.m
//  TrustKit
//
//  Created by Alban Diquet on 8/29/16.
//  Copyright © 2016 TrustKit. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <OSLog/OSLog.h>
#import "../TrustKit/public/TrustKit/TrustKit.h"
#import "../TrustKit/public/TrustKit/TSKPinningValidator.h"
#import "../TrustKit/public/TrustKit/TSKTrustKitConfig.h"
#import "../TrustKit/parse_configuration.h"
#import "../TrustKit/public/TrustKit/TSKPinningValidatorResult.h"
#import "../TrustKit/TSKPinningValidator_Private.h"
#import "../TrustKit/Pinning/TSKSPKIHashCache.h"
#import "TSKCertificateUtils.h"


@interface TSKLoggerTests : XCTestCase

@end

@implementation TSKLoggerTests

- (void)testPinValidationFailureIsLoggedAsError
{
    NSDate *startDate = [NSDate date];

    SecCertificateRef rootCertificate = [TSKCertificateUtils createCertificateFromDer:@"GoodRootCA"];
    SecCertificateRef leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com"];
    SecCertificateRef certChainArray[1] = {leafCertificate};
    SecCertificateRef trustStoreArray[1] = {rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:1
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:1];

    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                                      kTSKPinnedDomains: @{@"www.good.com": @{
                                                                          kTSKPublicKeyHashes: @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                                                                                 @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="]}}});
    TSKPinningValidator *validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                                                      hashCache:[[TSKSPKIHashCache alloc] initWithIdentifier:@"test"]
                                                                  ignorePinsForUserTrustAnchors:NO
                                                                        validationCallbackQueue:dispatch_get_main_queue()
                                                                             validationCallback:^(TSKPinningValidatorResult *result, NSString *notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *notedHostnamePinningPolicy) {}];

    XCTAssertEqual([validator evaluateTrust:trust forHostname:@"www.good.com"], TSKTrustDecisionShouldBlockConnection);
    CFRelease(trust);
    CFRelease(leafCertificate);
    CFRelease(rootCertificate);

    NSError *error = nil;
    OSLogStore *store = [OSLogStore storeWithScope:OSLogStoreCurrentProcessIdentifier error:&error];
    XCTAssertNotNil(store, @"%@", error);

    NSPredicate *predicate = [NSPredicate predicateWithFormat:@"subsystem == %@ AND category == %@", @"com.datatheorem.trustkit", @"TrustKit"];
    OSLogEnumerator *entries = [store entriesEnumeratorWithOptions:0
                                                          position:[store positionWithDate:startDate]
                                                         predicate:predicate
                                                             error:&error];
    XCTAssertNotNil(entries, @"%@", error);

    OSLogEntryLog *failureEntry = nil;
    for (OSLogEntry *entry in entries) {
        if ([entry isKindOfClass:[OSLogEntryLog class]] && [entry.composedMessage isEqualToString:@"Pin validation failed for www.good.com"]) {
            failureEntry = (OSLogEntryLog *)entry;
            break;
        }
    }
    XCTAssertNotNil(failureEntry);
    XCTAssertEqual(failureEntry.level, OSLogEntryLogLevelError);
}

@end
