/*
 
 TSKPinConfigurationTests.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <XCTest/XCTest.h>
#import "TrustKit+Private.h"
#import "ssl_pin_verifier.h"
#import "parse_configuration.h"
#import "public_key_utils.h"



@interface TSKPinConfigurationTests : XCTestCase
{
    
}
@end

@implementation TSKPinConfigurationTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}


// Pin to only one key and ensure it fails; TrustKit requires at least two pins (which should include a backup pin)
- (void)testPinOnePublicKey
{
    XCTAssertThrows(parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                 kTSKPinnedDomains : @{
                                                         @"www.good.com" : @{
                                                                 kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                 kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                         @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                         ]}}}),
                    @"Configuration with one pin only must be rejected");
}


- (void)testNokTSKSwizzleNetworkDelegates
{
    XCTAssertThrows(parseTrustKitConfiguration(@{kTSKPinnedDomains : @{
                                                         @"www.good.com" : @{
                                                                 kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                 kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                         @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                         ]}}}),
                    @"Configuration that does not specify kTSKSwizzleNetworkDelegates must be rejected");
}


- (void)testGetConfigurationPinningEnabled
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains : @{
                                                      @"www.good.com" : @{
                                                              kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                              kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                      @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                      ]}}});
    
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.good.com", trustKitConfig);
    XCTAssert([serverConfigKey isEqualToString:@"www.good.com"], @"Did not receive a configuration for a pinned domain");
}


- (void)testGetConfigurationPinningDisabled
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains : @{
                                                      @"good.com" : @{
                                                              kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                              kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                      @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                      ]}}});
    
    // Ensure www.datatheorem.com gets no configuration
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.datatheorem.com", trustKitConfig);
    XCTAssert(serverConfigKey == nil, @"Received a configuration a non-pinned domain");
}


- (void)testIncludeSubdomainsEnabled
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains : @{
                                                      @"good.com" : @{
                                                              kTSKIncludeSubdomains : @YES,
                                                              kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                              kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                      @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                      ]}}});
    
    // Ensure www.good.com gets the configuration set for good.com as includeSubdomains is enabled
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.good.com", trustKitConfig);
    XCTAssert([serverConfigKey isEqualToString:@"good.com"], @"IncludeSubdomains did not work");
}


- (void)testIncludeSubdomainsEnabledSameDomain
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains : @{@"good.com" : @{
                                                                            kTSKIncludeSubdomains : @YES,
                                                                            kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                            kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                                    ]}}});
    
    // Ensure good.com gets the configuration set for good.com as includeSubdomains is enabled
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"good.com", trustKitConfig);
    XCTAssert([serverConfigKey isEqualToString:@"good.com"], @"IncludeSubdomains did not work");
}


- (void)testIncludeSubdomainsEnabledSubSubDomain
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains :
                                                  @{@"www.good.com" : @{
                                                            kTSKIncludeSubdomains : @YES,
                                                            kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                            kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                    ]}}});
    
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"sub.www.good.com.www.good.com", trustKitConfig);
    XCTAssert([serverConfigKey isEqualToString:@"www.good.com"], @"IncludeSubdomains did not work");
}


- (void)testIncludeSubdomainsEnabledNotSubdomain
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains :
                                                  @{@"good.com" : @{
                                                            kTSKIncludeSubdomains : @YES,
                                                            kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                            kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                    ]}}});
    
    // Corner case to ensure two different domains with similar strings don't get returned as subdomains
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"good.com.otherdomain.com", trustKitConfig);
    XCTAssertNil(serverConfigKey);
}


- (void)testIncludeSubdomainsEnabledForSuffix
{
    XCTAssertThrows(parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                 kTSKPinnedDomains :
                                                 @{@"com" : @{
                                                           kTSKIncludeSubdomains : @YES,
                                                           kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                           kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                   @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                   ]}}}),
                    @"Configuration that pins *.com must be rejected");
}


- (void)testIncludeSubdomainsDisabled
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains :
                                                  @{@"good.com" : @{
                                                            kTSKIncludeSubdomains : @NO,
                                                            kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                            kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                    ]}}});
    
    // Ensure www.good.com does not get the configuration set for good.com
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.good.com", trustKitConfig);
    XCTAssert(serverConfigKey == nil, @"IncludeSubdomains did not work");
}


- (void)testIncludeSubdomainsEnabledAndSpecificConfiguration
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains :
                                                  @{@"good.com" : @{
                                                            kTSKIncludeSubdomains : @YES,
                                                            kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                            kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                    ]},
                                                    @"www.good.com": @{
                                                            kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                                                            kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=",
                                                                                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                    ]}}});
    
    // Ensure the configuration specific to www.good.com takes precedence over the more general config for good.com
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.good.com", trustKitConfig);
    XCTAssert([serverConfigKey isEqualToString:@"www.good.com"], @"IncludeSubdomains took precedence over a more specialized configuration");
}


- (void)testNoPinnedDomains
{
    XCTAssertThrows(parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates : @YES}),
                    @"Configuration with no pinned domains must be rejected");
}


- (void)testGlobalSettings
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains :
                                                      @{@"good.com" : @{
                                                                kTSKIncludeSubdomains : @YES,
                                                                kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                        @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                        ]}}});
    
    // Ensure the kTSKSwizzleNetworkDelegates setting was saved
    XCTAssert([trustKitConfig[kTSKSwizzleNetworkDelegates] boolValue] ==  NO, @"kTSKSwizzleNetworkDelegates was not saved in the configuration");
}

@end
