/*
 
 TSKPinConfigurationTests.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <XCTest/XCTest.h>

#import "../TrustKit/TrustKit.h"
#import "../TrustKit/TSKTrustKitConfig.h"
#import "../TrustKit/Pinning/ssl_pin_verifier.h"
#import "../TrustKit/parse_configuration.h"
#import "../TrustKit/configuration_utils.h"
#import "TSKCertificateUtils.h"

@interface TSKPinConfigurationTests : XCTestCase
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
    XCTAssertThrows(parseTrustKitConfiguration(@{kTSKPinnedDomains : @{
                                                         @"www.good.com" : @{
                                                                 kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                         @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                         ]}}}),
                    @"Configuration with one pin only must be rejected");
}


- (void)testDisablePinningForSubdomainAndNoPublicKey
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains : @{
                                                          @"good.com" : @{
                                                                  kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                          @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                                                                          ],
                                                                  kTSKIncludeSubdomains: @YES},
                                                          @"unsecured.good.com": @{
                                                                  // When using this option, TrustKit should accept an empty policy for the domain
                                                                  kTSKExcludeSubdomainFromParentPolicy: @YES
                                                                  }
                                                          }
                                                  });
    
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"unsecured.good.com", trustKitConfig[kTSKPinnedDomains]);
    XCTAssertEqualObjects(serverConfigKey, @"unsecured.good.com", @"Did not receive a configuration for pinned subdomain");
}

- (void)testExplicitNotDisablePinningForSubdomainAdditionalDomainKeys
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains : @{
                                                          @"good.com" : @{
                                                                  kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                          @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                                                                          ],
                                                                  kTSKIncludeSubdomains: @YES},
                                                          @"unsecured.good.com": @{
                                                                  // When using this option, TrustKit should allow/require a policy for the subdomain
                                                                  kTSKExcludeSubdomainFromParentPolicy: @NO,
                                                                  kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                          @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                                                                          ],
                                                                  }
                                                          }
                                                  });

    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"unsecured.good.com", trustKitConfig[kTSKPinnedDomains]);
    XCTAssertEqualObjects(serverConfigKey, @"unsecured.good.com", @"Did not receive a configuration for pinned subdomain");
}

- (void)testDisablePinningForSubdomainWithoutParentAndNoPublicKey
{
    XCTAssertThrows(parseTrustKitConfiguration(@{kTSKPinnedDomains : @{
                                                         @"good.com" : @{
                                                                 kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                         @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                                                                         ],
                                                                 // IncludeSubdomains set to NO so the configuration here is invalid
                                                                 kTSKIncludeSubdomains: @NO},
                                                         @"unsecured.good.com": @{
                                                                 kTSKExcludeSubdomainFromParentPolicy: @YES
                                                                 }
                                                         }
                                                 }),
                    @"Configuration with kTSKExcludeSubdomainFromParentPolicy must have a parent");
}


- (void)testDisablePinningForSubdomainAdditionalDomainKeys
{
    XCTAssertThrows(parseTrustKitConfiguration(@{kTSKPinnedDomains : @{
                                                         @"good.com" : @{
                                                                 kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                         @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                                                                         ],
                                                                 kTSKIncludeSubdomains: @YES},
                                                         @"unsecured.good.com": @{
                                                                 // When using this option, TrustKit should reject additional keys for the domain
                                                                 kTSKExcludeSubdomainFromParentPolicy: @YES,
                                                                 kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                         @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                                                                         ],
                                                                 }
                                                         }
                                                 }),
                    @"Configuration with kTSKExcludeSubdomainFromParentPolicy must reject additional domain keys");
}

- (void)testNokTSKSwizzleNetworkDelegates
{
    XCTAssertThrows(parseTrustKitConfiguration(@{kTSKPinnedDomains : @{
                                                         @"www.good.com" : @{
                                                                 kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                         @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                         ]}}}),
                    @"Configuration that does not specify kTSKSwizzleNetworkDelegates must be rejected");
}


- (void)testGetConfigurationPinningEnabled
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains : @{
                                                      @"www.good.com" : @{
                                                              kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                      @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                      ]}}});
    
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.good.com", trustKitConfig[kTSKPinnedDomains]);
    XCTAssertEqualObjects(serverConfigKey, @"www.good.com", @"Did not receive a configuration for a pinned domain");
    
    // Validate the content of the config
    NSDictionary *serverConfig = trustKitConfig[kTSKPinnedDomains][serverConfigKey];
    XCTAssertNil(serverConfig[kTSKExpirationDate]);
    XCTAssertEqual([serverConfig[kTSKPublicKeyHashes] count], (unsigned long) 2);
}


- (void)testGetConfigurationPinningEnabledWithExpirationDate
{
    NSString *expirationDateStr = @"2015-01-01";
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains : @{
                                                          @"www.good.com" : @{
                                                                  kTSKExpirationDate: expirationDateStr,
                                                                  kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                          @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                          ]}}});
    
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.good.com", trustKitConfig[kTSKPinnedDomains]);
    XCTAssertEqualObjects(serverConfigKey, @"www.good.com", @"Did not receive a configuration for a pinned domain");
    
    // Validate the content of the config
    NSDateFormatter *dateFormat = [[NSDateFormatter alloc] init];
    dateFormat.dateFormat = @"yyyy-MM-dd";
    dateFormat.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
    NSDate *expirationDate = [dateFormat dateFromString:expirationDateStr];
    
    NSDictionary *serverConfig = trustKitConfig[kTSKPinnedDomains][serverConfigKey];
    XCTAssertEqualObjects(expirationDate, serverConfig[kTSKExpirationDate]);
    XCTAssertEqual([serverConfig[kTSKPublicKeyHashes] count], (unsigned long)2);
}


- (void)testGetConfigurationPinningDisabled
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains : @{
                                                          @"good.com" : @{
                                                                  kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                          @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                          ]}}});
    
    // Ensure www.datatheorem.com gets no configuration
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.datatheorem.com", trustKitConfig[kTSKPinnedDomains]);
    XCTAssertNil(serverConfigKey, @"Received a configuration a non-pinned domain");
}


- (void)testIncludeSubdomainsEnabled
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains : @{
                                                      @"good.com" : @{
                                                              kTSKIncludeSubdomains : @YES,
                                                              kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                      @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                      ]}}});
    
    // Ensure www.good.com gets the configuration set for good.com as includeSubdomains is enabled
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.good.com", trustKitConfig[kTSKPinnedDomains]);
    XCTAssertEqualObjects(serverConfigKey, @"good.com", @"IncludeSubdomains did not work");
}


- (void)testIncludeSubdomainsEnabledSameDomain
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains : @{@"good.com" : @{
                                                                            kTSKIncludeSubdomains : @YES,
                                                                            kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                                    ]}}});
    
    // Ensure good.com gets the configuration set for good.com as includeSubdomains is enabled
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"good.com", trustKitConfig[kTSKPinnedDomains]);
    XCTAssertEqualObjects(serverConfigKey, @"good.com", @"IncludeSubdomains did not work");
}


- (void)testIncludeSubdomainsEnabledSubSubDomain
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains :
                                                  @{@"www.good.com" : @{
                                                            kTSKIncludeSubdomains : @YES,
                                                            kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                    ]}}});
    
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"sub.www.good.com.www.good.com", trustKitConfig[kTSKPinnedDomains]);
    XCTAssertEqualObjects(serverConfigKey, @"www.good.com", @"IncludeSubdomains did not work");
}


- (void)testIncludeSubdomainsEnabledNotSubdomain
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains :
                                                  @{@"good.com" : @{
                                                            kTSKIncludeSubdomains : @YES,
                                                            kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                    ]}}});
    
    // Corner case to ensure two different domains with similar strings don't get returned as subdomains
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"good.com.otherdomaingood.com", trustKitConfig[kTSKPinnedDomains]);
    XCTAssertNil(serverConfigKey);
}


- (void)testIncludeSubdomainsEnabledNotSubdomainDifferentTld
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains :
                                                      @{@"good.net" : @{
                                                                kTSKIncludeSubdomains : @YES,
                                                                kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                        @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                        ]}}});
    
    // Corner case to ensure two different domains (because different TLD) with similar strings don't get returned as subdomains
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"test.good.com", trustKitConfig[kTSKPinnedDomains]);
    XCTAssertNil(serverConfigKey);
}


- (void)testIncludeSubdomainsEnabledForSuffix
{
    XCTAssertThrows(parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                 kTSKPinnedDomains :
                                                 @{@"com" : @{
                                                           kTSKIncludeSubdomains : @YES,
                                                           kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                   @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                   ]}}}),
                    @"Configuration that pins *.com must be rejected");
}


- (void)testIncludeSubdomainsDisabled
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains :
                                                  @{@"good.com" : @{
                                                            kTSKIncludeSubdomains : @NO,
                                                            kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                    ]}}});
    
    // Ensure www.good.com does not get the configuration set for good.com
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.good.com", trustKitConfig[kTSKPinnedDomains]);
    XCTAssertNil(serverConfigKey, @"IncludeSubdomains did not work");
}


- (void)testIncludeSubdomainsEnabledAndSpecificConfiguration
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains :
                                                  @{@"good.com" : @{
                                                            kTSKIncludeSubdomains : @YES,
                                                            kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                    ]},
                                                    @"www.good.com": @{
                                                            kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=",
                                                                                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                    ]}}});
    
    // Ensure the configuration specific to www.good.com takes precedence over the more general config for good.com
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.good.com", trustKitConfig[kTSKPinnedDomains]);
    XCTAssertEqualObjects(serverConfigKey, @"www.good.com",
                          @"IncludeSubdomains took precedence over a more specialized configuration");
}


- (void)testIncludeSubdomainsEnabledAndOverlap
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains :
                                                      @{@"good.com" : @{
                                                                kTSKIncludeSubdomains : @YES,
                                                                kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                        @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                        ]},
                                                        @"www.good.com": @{
                                                                kTSKIncludeSubdomains : @YES,
                                                                kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=",
                                                                                        @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                        ]}}});

    // Ensure the configuration of www.good.com with a longer match takes precedence over the more general config for good.com
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"foo.www.good.com", trustKitConfig[kTSKPinnedDomains]);
    XCTAssertEqualObjects(serverConfigKey, @"www.good.com",
                          @"Overlapping configurations with IncludeSubdomains did not use the most specific (longest) matching configuration");
}


- (void)testNoPinnedDomains
{
    XCTAssertThrows(parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates : @YES}),
                    @"Configuration with no pinned domains must be rejected");
}


- (void)testGlobalSettings
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKPinnedDomains :
                                                      @{@"good.com" : @{
                                                                kTSKIncludeSubdomains : @YES,
                                                                kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                        @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                        ]}}});
    
    // Ensure the kTSKSwizzleNetworkDelegates setting was saved
    XCTAssertFalse([trustKitConfig[kTSKSwizzleNetworkDelegates] boolValue],
                   @"kTSKSwizzleNetworkDelegates was not saved in the configuration");
}


- (void)testSwizzleNetworkDelegatesInLocalInstance
{
    NSDictionary *trustKitConfig;
    // Swizzling can only be enabled in the shared instance
    trustKitConfig = @{kTSKSwizzleNetworkDelegates: @YES,
                                                  kTSKPinnedDomains :
                                                      @{@"good.com" : @{
                                                                kTSKIncludeSubdomains : @YES,
                                                                kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                                        @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                        ]}}};
    
    
    XCTAssertThrows([[TrustKit alloc] initWithConfiguration:trustKitConfig]);
}


@end
