/*

 TSKSPKIHashCacheTests.m
 TrustKit

 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.

 */

#import "../TrustKit/parse_configuration.h"
#import "../TrustKit/public/TrustKit/TSKTrustKitConfig.h"
#import <XCTest/XCTest.h>

#import "../TrustKit/Pinning/TSKSPKIHashCache.h"
#import "../TrustKit/Pinning/ssl_pin_verifier.h"
#import "../TrustKit/Reporting/reporting_utils.h"
#import <TrustKit/TrustKit-Swift.h>

#import "TSKCertificateUtils.h"
#import <OCMock/OCMock.h>

@interface TSKSPKIHashCache (TestSupport)
- (void)resetSubjectPublicKeyInfoDiskCache;
- (NSMutableDictionary<NSNumber *, SPKICacheDictionnary *> *)getSubjectPublicKeyInfoHashesCache;
@end

@interface TSKSPKIHashCacheTests : XCTestCase
@end

@implementation TSKSPKIHashCacheTests {
    TSKSPKIHashCache *spkiCache;
}

- (void)setUp {
    [super setUp];
    [spkiCache resetSubjectPublicKeyInfoDiskCache];
    spkiCache = [[TSKSPKIHashCache alloc] initWithIdentifier:@"test"];
}

- (void)tearDown {
    [spkiCache resetSubjectPublicKeyInfoDiskCache];
    spkiCache = nil;
    [super tearDown];
}

- (void)testExtractRsa2048 {
    // Ensure a RSA 2048 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"www.globalsign.com"];

    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];

    XCTAssertEqualObjects(spkiPin, @"NDCIt6TrQnfOk+lquunrmlPQB3K/7CLOCmSS5kW+KCc=");
    CFRelease(certificate);
}

- (void)testExtractRsa3072 {
    // Ensure a RSA 3072 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"Corporation Service Company RSA OV SSL CA"];

    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];

    XCTAssertEqualObjects(spkiPin, @"eJFNz94QPdv8RexRcSa3nwty3nRqFlR7YXqKA5RGUGE=");
    CFRelease(certificate);
}

- (void)testExtractRsa4096 {
    // Ensure a RSA 4096 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com"];

    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];

    XCTAssertEqualObjects(spkiPin, @"TwyNzy19zZi7cKfPsucs1E+h8ODOCPMrT8681sFWJvw=");
    CFRelease(certificate);
}

- (void)testExtractEcDsaSecp256r1 {
    // Ensure a secp256r1 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"www.cloudflare.com"];

    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];

    XCTAssertEqualObjects(spkiPin, @"Gc7EN2acfkbE0dUOAd34tr1XLr+JdkTiTrMAfhESQHI=");
    CFRelease(certificate);
}

- (void)testExtractEcDsaSecp384r1 {
    // Ensure a secp384r1 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"GeoTrust_Primary_CA_G2_ECC"];

    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];

    XCTAssertEqualObjects(spkiPin, @"vPtEqrmtAhAVcGtBIep2HIHJ6IlnWQ9vlK50TciLePs=");
    CFRelease(certificate);
}

- (void)testExtractEcDsaSecp521r1 {
    // Ensure a secp521r1 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"Secp521r1TestCA"];

    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];

    XCTAssertEqualObjects(spkiPin, @"JDbjp5T1MJ6GUN/fY/voVivkg/5a+kiWCTF7yBFL4DM=");
    CFRelease(certificate);
}

- (void)testSubjectPublicKeyInfoFromMalformedCertificate {
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com"];
    NSData *certificateData = (__bridge_transfer NSData *)SecCertificateCopyData(certificate);
    CFRelease(certificate);

    XCTAssertNotNil([TSKSubjectPublicKeyInfo dataFromCertificate:certificateData]);
    for (NSUInteger length = 0; length < [certificateData length]; length++) {
        XCTAssertNil([TSKSubjectPublicKeyInfo dataFromCertificate:[certificateData subdataWithRange:NSMakeRange(0, length)]], @"Truncated to %lu bytes", (unsigned long)length);
    }

    const uint8_t indefiniteLength[] = { 0x30, 0x80, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00 };
    const uint8_t fiveByteLength[] = { 0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x02, 0x30, 0x00 };
    const uint8_t notASequence[] = { 0x31, 0x02, 0x30, 0x00 };
    XCTAssertNil([TSKSubjectPublicKeyInfo dataFromCertificate:[NSData dataWithBytes:indefiniteLength length:sizeof(indefiniteLength)]]);
    XCTAssertNil([TSKSubjectPublicKeyInfo dataFromCertificate:[NSData dataWithBytes:fiveByteLength length:sizeof(fiveByteLength)]]);
    XCTAssertNil([TSKSubjectPublicKeyInfo dataFromCertificate:[NSData dataWithBytes:notASequence length:sizeof(notASequence)]]);
}

- (void)testSPKICacheMissOffMainThreadDoesNotWaitForMainThread {
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"www.globalsign.com"];
    dispatch_semaphore_t hashed = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        [self->spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
        CFRelease(certificate);
        dispatch_semaphore_signal(hashed);
    });

    long timedOut = dispatch_semaphore_wait(hashed, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)));
    XCTAssertEqual(timedOut, 0L, @"Hashing an uncached certificate must not wait on the main thread");

    XCTestExpectation *mainQueueDrained = [self expectationWithDescription:@"Main queue drained"];
    dispatch_async(dispatch_get_main_queue(), ^{
        [mainQueueDrained fulfill];
    });
    [self waitForExpectations:@[mainQueueDrained] timeout:5.0];
}

#if TARGET_OS_IPHONE && !TARGET_OS_WATCH
- (void)testSPKICacheThreadSafetyAndProtectedData {
    XCTestExpectation *expectation = [self expectationWithDescription:@"Cache operations completed"];

    id mockApplication = OCMClassMock([UIApplication class]);
    OCMStub([mockApplication sharedApplication]).andReturn(mockApplication);
    // Simulate protected data being unavailable
    OCMStub([mockApplication isProtectedDataAvailable]).andReturn(NO);

    // Perform multiple cache operations in parallel on a background queue
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"www.globalsign.com"];
    dispatch_group_t group = dispatch_group_create();
    for (int i = 0; i < 10; i++) {
        dispatch_group_async(group, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [self->spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
        });
    }

    dispatch_group_notify(group, dispatch_get_main_queue(), ^{
        NSDictionary *cache = [self->spkiCache getSubjectPublicKeyInfoHashesCache];
        XCTAssertEqual(cache.count, 1, @"Cache should contain one entry");

        // Simulate protected data becoming available
        OCMStub([mockApplication isProtectedDataAvailable]).andReturn(YES);

        // Perform one more cache operation to trigger filesystem write
        [self->spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            NSDictionary *finalCache = [self->spkiCache getSubjectPublicKeyInfoHashesCache];
            XCTAssertEqual(finalCache.count, 1, @"Cache should still contain one entry");

            CFRelease(certificate);
            [mockApplication stopMocking];
            [expectation fulfill];
        });
    });

    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

// This test hardly manages to reproduce the crash, but it does reproduce it sometimes.
- (void)testSPKICacheThreadSafetyAndProtectedDataDoesntCrash {
    XCTestExpectation *expectation = [self expectationWithDescription:@"Cache operations completed"];

    id mockApplication = OCMClassMock([UIApplication class]);
    OCMStub([mockApplication sharedApplication]).andReturn(mockApplication);
    OCMStub([mockApplication isProtectedDataAvailable]).andReturn(YES);

    // Perform multiple cache operations in parallel on a background queue
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"www.globalsign.com"];
    dispatch_group_t group = dispatch_group_create();
    for (int i = 0; i < 100; i++) {
        dispatch_group_async(group, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [self->spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
        });
    }

    dispatch_group_notify(group, dispatch_get_main_queue(), ^{
        NSDictionary *cache = [self->spkiCache getSubjectPublicKeyInfoHashesCache];
        XCTAssertEqual(cache.count, 1, @"Cache should contain one entry");

        BOOL yes = YES;
        OCMStub([mockApplication isProtectedDataAvailable]).andReturn(YES).andDo(^(NSInvocation *invocation) {
            self->spkiCache = nil;
            [invocation setReturnValue:(void *)&yes];
        });

        // Perform one more cache operation to trigger filesystem write
        [self->spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            CFRelease(certificate);
            [mockApplication stopMocking];
            [expectation fulfill];
        });
    });

    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}
#endif

@end
