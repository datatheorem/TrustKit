/*
 
 TSKPinValidationOnlineTests.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <XCTest/XCTest.h>
#import "TrustKit+Private.h"
#import "public_key_utils.h"


@interface TSKPinValidationOnlineTests : XCTestCase

@end

@implementation TSKPinValidationOnlineTests
/*  WARNING: For the online tests, we need to use a different domain for every test otherwise the tests will be disrupted by SSL session resumption.
    Specifically, connecting to the same host more than once will potentially allow the first session to be resumed, thereby skipping all SSL validation including TrustKit's. This is not a security issue but will make the tests report unexpected results.
 */

- (void)setUp {
    [super setUp];
    [TrustKit resetConfiguration];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}




// Tests a secure connection to https://www.datatheorem.com by pinning only to the CA public key
- (void)testConnectionValidatingCAPublicKey
{
    NSDictionary *trustKitConfig =
    @{
      @"www.datatheorem.com" : @{
              kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
              kTSKPublicKeyHashes : @[@"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=" // CA key
                                      ]}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    NSError *error = nil;
    NSHTTPURLResponse *response;
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.datatheorem.com"]];
    [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:&error];
    
    XCTAssertNil(error, @"Connection had an error: %@", error);
    XCTAssert(response.statusCode==200, @"Server did not respond with a 200 OK");
    XCTAssert([TrustKit wasTrustKitCalled], @"TrustKit was not called");
}


// Tests a secure connection to https://www.yahoo.com and forces validation to fail by providing a fake hash
- (void)testConnectionUsingFakeHashInvalidatingAllCertificates
{
    NSDictionary *trustKitConfig =
    @{
      @"www.yahoo.com" : @{
              kTSKEnforcePinning : @YES,
              kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
              kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" //Fake key
                                      ]}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    NSError *error = nil;
    NSHTTPURLResponse *response;
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.yahoo.com"]];
    [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:&error];
    
    XCTAssert(error.code==-1202 && [error.domain isEqual:@"NSURLErrorDomain"], @"Invalid certificate error not fired");
    XCTAssert([TrustKit wasTrustKitCalled], @"TrustKit was not called");
}


// Tests a secure connection to https://www.google.com and validation should fail because of a fake hash,
// however TrustKit is configured to not enforce pinning so the connection must work
- (void)testConnectionUsingFakeHashInvalidatingAllCertificatesButNotEnforcingPinning
{
    NSDictionary *trustKitConfig =
            @{
                    @"www.github.com" : @{
                    kTSKEnforcePinning : @NO, // Pinning disabled!
                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                    kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" //Fake key
                    ]}};

    [TrustKit initializeWithConfiguration:trustKitConfig];

    NSError *error = nil;
    NSHTTPURLResponse *response;
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.github.com"]];
    [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:&error];

    XCTAssertNil(error, @"Connection had an error: %@", error);
    XCTAssert(response.statusCode==200, @"Server did not respond with a 200 OK");
    XCTAssert([TrustKit wasTrustKitCalled], @"TrustKit was not called");
}


// Don't pin anything (connection must work)
- (void)testConnectionWithoutPinningAnything
{
    NSError *error = nil;
    NSHTTPURLResponse *response;
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.outlook.com"]];
    [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:&error];
    
    XCTAssertNil(error, @"Connection had an error: %@", error);
    XCTAssert(response.statusCode==200, @"Server did not respond with a 200 OK");
    XCTAssert(![TrustKit wasTrustKitCalled], @"TrustKit was called");
}


@end
