//
//  TrustKit.h
//  TrustKit
//
//  Created by Alban Diquet on 2/9/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

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

#pragma mark Supported Public Key Algorithm Keys
extern NSString * const kTSKAlgorithmRsa2048;
extern NSString * const kTSKAlgorithmRsa4096;
extern NSString * const kTSKAlgorithmEcDsaSecp256r1;


/**
 `TrustKit` is a utility class for configuring the SSL pinning policy in an App that statically links TrustKit.
 
 Initializing TrustKit requires supplying a dictionary containing domain names as keys and dictionaries as values. Each domain dictionary should specify some configuration keys, which will specify the pinning policy for this domain. For example:
 
     NSDictionary *trustKitConfig = @{
         @"www.datatheorem.com" : @{
             kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
             kTSKPublicKeyHashes : @[
                 @"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
                 @"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="
                 ]
             }
         };
     [TrustKit initializeWithConfiguration:trustKitConfig];
 
  When dynamically linking TrustKit, the Framework is automatically initialized by reading configuration keys from the App's Info.plist, and no initialization method needs to be called.
 
 
 ### Required Configuration Keys
 
 #### `kTSKPublicKeyHashes`
 This value should be an array of SSL pins; each pin is the base64-encoded SHA 256 of a certificate's subject public key info. TrustKit will verify that at least one of the specifed pins is found in the server's certificate chain.
 
 #### `kTSKPublicKeyAlgorithms`
 This value should be an array of algorithm constants (kTSKAlgorithm) that TrustKit needs to support when generating public key hashes. Supporting multiple algorithms has a performance impact.
 
 
 ### Optional Configuration Keys
 
 #### `kTSKIncludeSubdomains`
 If set to `YES`, also pin all the subdomains of the specified domain; default value is `NO`.
 
 #### `kTSKEnforcePinning`
 If set to `NO`, a pinning failure will not cause the connection to fail; default value is `YES`.
 
 #### `kTSKReportUris`
 No effect at the moment.
 
 
 ### Public Key Algorithms Keys
 
 Public key algorithms supported by TrustKit for generating SSL pins.
 
 #### `kTSKAlgorithmRsa2048`
 
 #### `kTSKAlgorithmRsa4096`
 
 #### `kTSKAlgorithmEcDsaSecp256r1`
 
 */
@interface TrustKit : NSObject

///---------------------
/// @name Initialization
///---------------------

/**
 Initializes TrustKit's global state with the supplied SSL pinning configuration. 
 
 This method should be called as early as possible in the App's lifecycle to ensure that the App's very first HTTPS connections are protected.
 
 @param trustKitConfig A dictionnary containing various keys for configuring the App's SSL pinning policy.
 
 @warning TrustKit can only be initialized once and calling this method multiple times will raise an exception.
 */
+ (void) initializeWithConfiguration:(NSDictionary *)trustKitConfig;

@end

