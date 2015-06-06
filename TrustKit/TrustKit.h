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
extern NSString * const kTSKPublicKeyHashes;
extern NSString * const kTSKEnforcePinning;
extern NSString * const kTSKIncludeSubdomains;
extern NSString * const kTSKPublicKeyAlgorithms;
extern NSString * const kTSKReportUris;
extern NSString * const kTSKDisableDefaultReportUri;

#pragma mark Supported Public Key Algorithm Keys
extern NSString * const kTSKAlgorithmRsa2048;
extern NSString * const kTSKAlgorithmRsa4096;
extern NSString * const kTSKAlgorithmEcDsaSecp256r1;


/**
 `TrustKit` is a class for configuring the global SSL pinning policy in an App that statically links TrustKit.
 
 Initializing TrustKit requires supplying a dictionary containing domain names as keys and dictionaries as values. Each domain dictionary should specify some configuration keys, which will specify the pinning policy for this domain. For example:
 
     NSDictionary *trustKitConfig = @{
         @"www.datatheorem.com" : @{
             kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
             kTSKPublicKeyHashes : @[
                 @"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
                 @"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="
                 ]
             }
        @"yahoo.com" : @{
            kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
            kTSKPublicKeyHashes : @[
                @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                @"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=",
                ]
            },
            kTSKIncludeSubdomains : YES
         };
 
     [TrustKit initializeWithConfiguration:trustKitConfig];
 
  When dynamically linked, TrustKit is automatically initialized by reading configuration keys from the App's _Info.plist_, and no initialization method needs to be called.
 
 
 ### Required Configuration Keys
 
 #### `kTSKPublicKeyHashes`
 An array of SSL pins; each pin is the base64-encoded SHA-256 hash of a certificate's Subject Public Key Info. TrustKit will verify that at least one of the specifed pins is found in the server's evaluated certificate chain.
 
 #### `kTSKPublicKeyAlgorithms`
 An array of `kTSKAlgorithm` constants to specify which public key algorithms need to be supported when computing SSL pins. To minimize the performance impact of Trustkit, only one algorithm should be enabled.
 
 
 ### Optional Configuration Keys
 
 #### `kTSKIncludeSubdomains`
 If set to `YES`, also pin all the subdomains of the specified domain; default value is `NO`.
 
 #### `kTSKEnforcePinning`
 If set to `NO`, a pinning failure will not cause the SSL connection to fail; default value is `YES`.
 
 #### `kTSKReportUris`
 An array of URLs to which pin validation failures should be reported. To minimize the performance impact of sending reports on each validation failure, the reports are uploaded using the background transfer service. For HTTPS report URLs, the HTTPS connections will ignore the SSL pinning policy and use the default certificate validation mechanisms, in order to maximize the chance of the reports reaching the server. The format of the reports is similar to the one described in the HPKP specification.

 #### `kTSKDisableDefaultReportUri`
 If set to `YES`, the default report URL for sending pin failure reports will be disabled. By default, pin failure reports are sent to a report server hosted by Data Theorem, for detecting potential CA compromises and man-in-the-middle attacks, as well as providing a free dashboard for developers. Only reports are sent, which contain the App's bundle ID and the server's hostname and certificate chain that failed validation. This behavior can be disabled by setting this key to `YES`.
 
 
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
 
 This method should be called as early as possible in the App's lifecycle to ensure that the App's very first HTTPS connections are protected.
 
 @param trustKitConfig A dictionnary containing various keys for configuring the global SSL pinning policy.
 
 @warning TrustKit can only be initialized once and calling this method multiple times will raise an exception.
 */
+ (void) initializeWithConfiguration:(NSDictionary *)trustKitConfig;

@end

