/*
 
 TrustKit.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>
#import <TrustKit/TSKPinningValidator.h>

//! Project version number for TrustKit.
FOUNDATION_EXPORT double TrustKitVersionNumber;

//! Project version string for TrustKit.
FOUNDATION_EXPORT const unsigned char TrustKitVersionString[];


#pragma mark TrustKit Configuration Keys

FOUNDATION_EXPORT const NSString *kTSKSwizzleNetworkDelegates;
FOUNDATION_EXPORT const NSString *kTSKPinnedDomains;
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
 `TrustKit` is a class for programmatically configuring the global SSL pinning policy within an App.

  The policy can be set either by adding it to the App's _Info.plist_ under the `TSKConfiguration` key, or by programmatically supplying it using the `TrustKit` class described here. Throughout the App's lifecycle, TrustKit can only be initialized once so only one of the two techniques should be used.
 
 A TrustKit SSL pinning policy is a dictionary which contains some global, App-wide settings as well as domain-specific configuration keys. The following table shows the keys and their types, and uses indentation to indicate structure:
 
 | Key                                          | Type       |
 |----------------------------------------------|------------|
 | `TSKSwizzleNetworkDelegates`                 | Boolean    |
 | `TSKIgnorePinningForUserDefinedTrustAnchors` | Boolean    |
 | `TSKPinnedDomains`                           | Dictionary |
 | ── `<domain-name-to-pin-as-string>`          | Dictionary |
 | ──── `TSKPublicKeyHashes`                    | Array      |
 | ──── `TSKPublicKeyAlgorithms`                | Array      |
 | ──── `TSKIncludeSubdomains`                  | Boolean    |
 | ──── `TSKEnforcePinning`                     | Boolean    |
 | ──── `TSKReportUris`                         | Array      |
 | ──── `kTSKDisableDefaultReportUri`           | Boolean    |
 
 When setting the pinning policy programmatically, it has to be supplied to the `initializeWithConfiguration:` method as a dictionnary. For example:
 
    NSDictionary *trustKitConfig;
    trustKitConfig = @{
                       kTSKPinnedDomains : @{
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
                               }};

      [TrustKit initializeWithConfiguration:trustKitConfig];
 
  The various configuration keys that can be specified in the policy are described below.
 
 
 ### Required Global Configuration Keys
 
 #### `kTSKPinnedDomains`
 A dictionary with domains (such as _www.domain.com_) as keys and dictionaries as values. 
 
 Each entry should contain domain-specific settings for performing pinning validation when connecting to the domain, including for example the domain's public key hashes. A list of all domain-specific keys is available in the "Domain-specific Keys" sections.
 

 ### Optional Global Configuration Keys
 
 #### `kTSKSwizzleNetworkDelegates`
 If set to `YES`, TrustKit will perform method swizzling on the App's `NSURLConnection` and `NSURLSession` delegates in order to automatically add SSL pinning validation to the App's connections; default value is `YES`.
 
 Swizzling allows enabling pinning within an App without having to find and modify each and every instance of `NSURLConnection` or `NSURLSession` delegates. However, it might clash with anti-tampering mechanisms, as well as analytics SDKs that also perform swizzling of the App's network delegates. In such scenarios or if the developer wants a tigher control on the App's networking behavior, `kTSKSwizzleNetworkDelegates` should be set to `NO`; the developer should then manually add pinning validation to the App's authentication handlers. 
 
 See the `TSKPinningValidator` class for instructions on how to do so.
 

 #### `kTSKIgnorePinningForUserDefinedTrustAnchors` (OS X only)
 If set to `YES`, pinning validation will be skipped if the server's certificate chain terminates at a user-defined trust anchor (such as a root CA that isn't part of OS X's default trust store) and no pin failure reports will be sent; default value is `YES`.
 
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
 
 When a pinning failure occurs, pin failure reports will always be sent to the configured report URIs regardless of the value of `kTSKEnforcePinning`.
 
 #### `kTSKReportUris`
 An array of URLs to which pin validation failures should be reported. 
 
 To minimize the performance impact of sending reports on each validation failure, the reports are uploaded using the background transfer service and are also rate-limited to one per day and per type of failure. For HTTPS report URLs, the HTTPS connections will ignore the SSL pinning policy and use the default certificate validation mechanisms, in order to maximize the chance of the reports reaching the server. The format of the reports is similar to the one described in RFC 7469 for the HPKP specification:
 
    {
        "app-bundle-id":"com.example.ABC",
        "app-version":"1.0",
        "app-identifier":"599F9C00-92DC-4B5C-9464-7971F01F8370",
        "date-time": "2015-07-10T20:03:14Z",
        "hostname": "mail.example.com",
        "port": 0,
        "include-subdomains": true,
        "noted-hostname": "example.com",
        "validated-certificate-chain": [
            pem1, ... pemN
        ],
        "known-pins": [
            "pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"",
            "pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\""
        ],
        "validation-result":1
    }


 #### `kTSKDisableDefaultReportUri`
 If set to `YES`, the default report URL for sending pin failure reports will be disabled; default value is `NO`.
 
 By default, pin failure reports are sent to a report server hosted by Data Theorem, for detecting potential CA compromises and man-in-the-middle attacks, as well as providing a free dashboard for developers. Only pin failure reports are sent, which contain the App's bundle ID, the IDFV, and the server's hostname and certificate chain that failed validation.
 
 
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

