/*
 
 TSKPublicKeyAlgorithmTests.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <XCTest/XCTest.h>
#import "../TrustKit/public/TSKTrustKitConfig.h"
#import "../TrustKit/parse_configuration.h"

#import "../TrustKit/Pinning/ssl_pin_verifier.h"
#import "../TrustKit/Pinning/TSKSPKIHashCache.h"
#import "../TrustKit/Reporting/reporting_utils.h"

#import "TSKCertificateUtils.h"
#import <OCMock/OCMock.h>


@interface TSKSPKIHashCache (TestSupport)
- (void)resetSubjectPublicKeyInfoDiskCache;
- (NSMutableDictionary<NSNumber *, SPKICacheDictionnary *> *)getSubjectPublicKeyInfoHashesCache;
@end


@interface TSKPublicKeyAlgorithmTests : XCTestCase
@end

@implementation TSKPublicKeyAlgorithmTests
{
    TSKSPKIHashCache *spkiCache;
}

- (void)setUp
{
    [super setUp];
    [spkiCache resetSubjectPublicKeyInfoDiskCache];
    spkiCache = [[TSKSPKIHashCache alloc] initWithIdentifier:@"test"];
}

- (void)tearDown
{
    [spkiCache resetSubjectPublicKeyInfoDiskCache];
    spkiCache = nil;
    [super tearDown];
}


- (void)testExtractRsa2048
{
    // Ensure a RSA 2048 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"www.globalsign.com"];

    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];

    XCTAssertEqualObjects(spkiPin, @"NDCIt6TrQnfOk+lquunrmlPQB3K/7CLOCmSS5kW+KCc=");
    CFRelease(certificate);
}

- (void)testExtractRsa3072
{
    // Ensure a RSA 2048 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"Corporation Service Company RSA OV SSL CA"];

    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];

    XCTAssertEqualObjects(spkiPin, @"eJFNz94QPdv8RexRcSa3nwty3nRqFlR7YXqKA5RGUGE=");
    CFRelease(certificate);
}

- (void)testExtractRsa4096
{
    // Ensure a RSA 4096 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com"];
    
    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    XCTAssertEqualObjects(spkiPin, @"TwyNzy19zZi7cKfPsucs1E+h8ODOCPMrT8681sFWJvw=");
    CFRelease(certificate);
}


- (void)testExtractEcDsaSecp256r1
{
    // Ensure a secp256r1 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"www.cloudflare.com"];
    
    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    XCTAssertEqualObjects(spkiPin, @"Gc7EN2acfkbE0dUOAd34tr1XLr+JdkTiTrMAfhESQHI=");
    CFRelease(certificate);
}


- (void)testExtractEcDsaSecp384r1
{
    // Ensure a secp384r1 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"GeoTrust_Primary_CA_G2_ECC"];
    
    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    XCTAssertEqualObjects(spkiPin, @"vPtEqrmtAhAVcGtBIep2HIHJ6IlnWQ9vlK50TciLePs=");
    CFRelease(certificate);
}


- (void)testSPKICacheThreadSafetyAndProtectedData
{
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

@end
