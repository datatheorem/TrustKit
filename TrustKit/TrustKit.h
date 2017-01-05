/*
 
 TrustKit.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>
#import "TSKPinningValidator.h"

NS_ASSUME_NONNULL_BEGIN


#pragma mark TrustKit Version Number
FOUNDATION_EXPORT NSString * const TrustKitVersion;


#pragma mark TrustKit Configuration Keys

FOUNDATION_EXPORT NSString * const kTSKPinnedDomains;
FOUNDATION_EXPORT NSString * const kTSKPublicKeyHashes;
FOUNDATION_EXPORT NSString * const kTSKEnforcePinning;
FOUNDATION_EXPORT NSString * const kTSKIncludeSubdomains;
FOUNDATION_EXPORT NSString * const kTSKPublicKeyAlgorithms;
FOUNDATION_EXPORT NSString * const kTSKIgnorePinningForUserDefinedTrustAnchors NS_AVAILABLE_MAC(10_9);


#pragma mark Supported Public Key Algorithm Keys

FOUNDATION_EXPORT NSString * const kTSKAlgorithmRsa2048;
FOUNDATION_EXPORT NSString * const kTSKAlgorithmRsa4096;
FOUNDATION_EXPORT NSString * const kTSKAlgorithmEcDsaSecp256r1;

/**
 `TrustKit` is a class for programmatically configuring the global SSL pinning policy within an App.

## Initialization
 
  The policy can be set either by adding it to the App's _Info.plist_ under the `TSKConfiguration` key, or by programmatically supplying it using the `TrustKit` class described here. Throughout the App's lifecycle, TrustKit can only be initialized once so only one of the two techniques should be used.
 
 A TrustKit SSL pinning policy is a dictionary which contains some global, App-wide settings as well as domain-specific configuration keys. The following table shows the keys and their types, and uses indentation to indicate structure:
 
 | Key                                          | Type       |
 |----------------------------------------------|------------|
 | `TSKIgnorePinningForUserDefinedTrustAnchors` | Boolean    |
 | `TSKPinnedDomains`                           | Dictionary |
 | __ `<domain-name-to-pin-as-string>`          | Dictionary |
 | ____ `TSKPublicKeyHashes`                    | Array      |
 | ____ `TSKPublicKeyAlgorithms`                | Array      |
 | ____ `TSKIncludeSubdomains`                  | Boolean    |
 | ____ `TSKEnforcePinning`                     | Boolean    |

 When setting the pinning policy programmatically, it has to be supplied to the `initializeWithConfiguration:` method as a dictionary. For example:
 
    NSDictionary *trustKitConfig =
    @{
      kTSKPinnedDomains : @{
              @"www.datatheorem.com" : @{
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[
                              @"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
                              @"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="
                              ],
                      kTSKEnforcePinning : @NO,
                      },
              @"yahoo.com" : @{
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                      kTSKPublicKeyHashes : @[
                              @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                              @"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=",
                              ],
                      kTSKIncludeSubdomains : @YES
                      }
              }};

    [TrustKit initializeWithConfiguration:trustKitConfig];
 
 Similarly, TrustKit can be initialized in Swift:
 
     let trustKitConfig = [
         kTSKPinnedDomains: [
             "yahoo.com": [
                 kTSKPublicKeyAlgorithms: [kTSKAlgorithmRsa2048],
                 kTSKPublicKeyHashes: [
                     "JbQbUG5JMJUoI6brnx0x3vZF6jilxsapbXGVfjhN8Fg=",
                     "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18="
                   ],]]]
        
     TrustKit.initializeWithConfiguration(config)
 
 
  The various configuration keys that can be specified in the policy are described below.
 
 
 ### Required Global Configuration Keys
 
 #### `kTSKPinnedDomains`
 A dictionary with domains (such as _www.domain.com_) as keys and dictionaries as values. 
 
 Each entry should contain domain-specific settings for performing pinning validation when connecting to the domain, including for example the domain's public key hashes. A list of all domain-specific keys is available in the "Domain-specific Keys" sections.
 
 
 ### Optional Global Configuration Keys

 #### `kTSKIgnorePinningForUserDefinedTrustAnchors` (OS X only)
 If set to `YES`, pinning validation will be skipped if the server's certificate chain terminates at a user-defined trust anchor (such as a root CA that isn't part of OS X's default trust store); default value is `YES`.
 
 This is useful for allowing SSL connections through corporate proxies or firewalls. See "How does key pinning interact with local proxies and filters?" within the Chromium security FAQ at https://www.chromium.org/Home/chromium-security/security-faq for more information.


 ### Required Domain-specific Keys
 
 #### `kTSKPublicKeyHashes`
 An array of SSL pins, where each pin is the base64-encoded SHA-256 hash of a certificate's Subject Public Key Info.
 
 TrustKit will verify that at least one of the specified pins is found in the server's evaluated certificate chain.
 
 #### `kTSKPublicKeyAlgorithms`
 An array of `kTSKAlgorithm` constants to specify the public key algorithms for the keys to be pinned. 
 
 TrustKit requires this information in order to compute SSL pins when validating a server's certificate chain, because the `Security` framework does not provide APIs to extract the key's algorithm from an SSL certificate. To minimize the performance impact of Trustkit, only one algorithm should be enabled.
 
 
 ### Optional Domain-specific Keys
 
 #### `kTSKIncludeSubdomains`
 If set to `YES`, also pin all the subdomains of the specified domain; default value is `NO`.
 
 #### `kTSKEnforcePinning`
 If set to `NO`, TrustKit will not block SSL connections that caused a pin or certificate validation error; default value is `YES`. 
  
 ### Public Key Algorithms Keys
 
 Public key algorithms supported by TrustKit for computing SSL pins.
 
 #### `kTSKAlgorithmRsa2048`
 
 #### `kTSKAlgorithmRsa4096`
 
 #### `kTSKAlgorithmEcDsaSecp256r1`
 
 */
@interface TrustKit : NSObject

///---------------------
/// @name Initialization
///---------------------

/**
 Initialize the global SSL pinning policy with the supplied configuration.
 
 This method should be called as early as possible in the App's lifecycle to ensure that the App's very first SSL connections are validated by TrustKit.
 
 @param trustKitConfig A dictionary containing various keys for configuring the global SSL pinning policy.
 @exception NSException Thrown when the supplied configuration is invalid or TrustKit has already been initialized.
 
 */
+ (void) initializeWithConfiguration:(NSDictionary *)trustKitConfig;


///----------------------------
/// @name Current Configuration
///----------------------------

/**
 Retrieve a copy of the global SSL pinning policy.
 
 @return A dictionary with a copy of the current TrustKit configuration, or `nil` if TrustKit has not been initialized.
 */
+ (nullable NSDictionary *) configuration;

/**
 Set the global logger.
 
 This method sets the global logger, used when TrustKit needs to display a message to the developer. 
 
 If a global logger is not set, the default logger will be used, which will print TrustKit log messages (using `NSLog()`) when the App is built in Debug mode. If the App was built for Release, the default logger will not print any messages at all.
 */
+ (void)setLoggerBlock:(void (^)(NSString *))block;

@end
NS_ASSUME_NONNULL_END
