/*
 
 TrustKit.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>

//! Project version number for TrustKit.
FOUNDATION_EXPORT double TrustKitVersionNumber;

//! Project version string for TrustKit.
FOUNDATION_EXPORT const unsigned char TrustKitVersionString[];


#pragma mark TrustKit Configuration Keys
FOUNDATION_EXPORT const NSString *kTSKPublicKeyHashes;
FOUNDATION_EXPORT const NSString *kTSKEnforcePinning;
FOUNDATION_EXPORT const NSString *kTSKIncludeSubdomains;
FOUNDATION_EXPORT const NSString *kTSKPublicKeyAlgorithms;
FOUNDATION_EXPORT const NSString *kTSKReportUris;
FOUNDATION_EXPORT const NSString *kTSKDisableDefaultReportUri;
FOUNDATION_EXPORT const NSString *kTSKIgnorePinningForUserDefinedTrustAnchors NS_AVAILABLE_MAC(10_9);


#pragma mark Supported Public Key Algorithm Keys
FOUNDATION_EXPORT const NSString *kTSKAlgorithmRsa2048;
FOUNDATION_EXPORT const NSString *kTSKAlgorithmRsa4096;
FOUNDATION_EXPORT const NSString *kTSKAlgorithmEcDsaSecp256r1;


/**
 `TrustKit` is a class for configuring the global SSL pinning policy in an App that statically links TrustKit.
 
 Initializing TrustKit requires supplying a dictionary containing domain names as keys and dictionaries as values. Each domain dictionary should specify some configuration keys, which will specify the pinning policy for this domain. For example:
 
     NSDictionary *trustKitConfig;
     trustKitConfig = @{
                        @"www.datatheorem.com" : @{
                                kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                                kTSKPublicKeyHashes : @[
                                        @"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
                                        @"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="
                                        ],
                                kTSKEnforcePinning : @NO,
                                kTSKReportUris : @[@"http://report.datatheorem.com/log_hpkp_report"],
                                },
                        @"yahoo.com" : @{
                                kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                kTSKPublicKeyHashes : @[
                                        @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                        @"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=",
                                        ],
                                kTSKIncludeSubdomains : @YES
                                }
                        };

      [TrustKit initializeWithConfiguration:trustKitConfig];
 
  It also possible to supply the pinning policy by adding these configuration keys to the App's _Info.plist_ under a `TSKConfiguration` dictionary key. When doing so, no initialization method needs to be called and TrustKit will automatically be initialized with the policy.
 
 
 ### Required Configuration Keys
 
 #### `kTSKPublicKeyHashes`
 An array of SSL pins; each pin is the base64-encoded SHA-256 hash of a certificate's Subject Public Key Info. TrustKit will verify that at least one of the specified pins is found in the server's evaluated certificate chain.
 
 #### `kTSKPublicKeyAlgorithms`
 An array of `kTSKAlgorithm` constants to specify the public key algorithms for the keys to be pinned. TrustKit requires this information in order to compute SSL pins when validating a server's certificate chain, because there are no APIs to directly extract the key's algorithm from an SSL certificate. To minimize the performance impact of Trustkit, only one algorithm should be enabled.
 
 
 ### Optional Configuration Keys
 
 #### `kTSKIncludeSubdomains`
 If set to `YES`, also pin all the subdomains of the specified domain; default value is `NO`.
 
 #### `kTSKEnforcePinning`
 If set to `NO`, a pinning failure will not cause the SSL connection to fail; default value is `YES`. When a pinning failure occurs, pin failure reports will still be sent to the configured report URIs.
 
 #### `kTSKReportUris`
 An array of URLs to which pin validation failures should be reported. To minimize the performance impact of sending reports on each validation failure, the reports are uploaded using the background transfer service. For HTTPS report URLs, the HTTPS connections will ignore the SSL pinning policy and use the default certificate validation mechanisms, in order to maximize the chance of the reports reaching the server. The format of the reports is similar to the one described in the HPKP specification.

 #### `kTSKDisableDefaultReportUri`
 If set to `YES`, the default report URL for sending pin failure reports will be disabled; default value is `NO`. 
 By default, pin failure reports are sent to a report server hosted by Data Theorem, for detecting potential CA compromises and man-in-the-middle attacks, as well as providing a free dashboard for developers. Only pin failure reports are sent, which contain the App's bundle ID and the server's hostname and certificate chain that failed validation.
 
 #### `kTSKIgnorePinningForUserDefinedTrustAnchors` (OS X only)
 If set to `YES`, pinning validation will be skipped if the server's certificate chain terminates at a user-defined trust anchor (such as a root CA that isn't part of OS X's default trust store) and no pin failure reports will be sent; default value is `YES`.
 This is useful for allowing SSL connections through corporate proxies or firewalls. See "How does key pinning interact with local proxies and filters?" within the Chromium security FAQ at https://www.chromium.org/Home/chromium-security/security-faq for more information.
 
 
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
 Initializes the global SSL pinning policy with the supplied configuration.
 
 This method should be called as early as possible in the App's lifecycle to ensure that the App's very first SSL connections are validated by TrustKit.
 
 @param trustKitConfig A dictionnary containing various keys for configuring the global SSL pinning policy.
 @exception NSException Thrown when the supplied configuration is invalid or TrustKit has already been initialized.
 
 */
+ (void) initializeWithConfiguration:(NSDictionary *)trustKitConfig;

@end

