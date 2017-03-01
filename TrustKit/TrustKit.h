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

/**
 The version of TrustKit, such as "1.4.0".
 */
FOUNDATION_EXPORT NSString * const TrustKitVersion;


#pragma mark Configuration Keys


/**
 A global, App-wide configuration key that can be set in the pinning policy.
 */
typedef NSString *TSKGlobalConfigurationKey;


/**
 A domain-specific configuration key (to defined for a domain under the `kTSKPinnedDomains` key) that can be set in the pinning policy.
 */
typedef NSString *TSKDomainConfigurationKey;


#pragma mark Global Configuration Keys - Required


/**
 A boolean. If set to `YES`, TrustKit will perform method swizzling on the App's `NSURLConnection` and `NSURLSession` delegates in order to automatically add SSL pinning validation to the App's connections.
 
 Swizzling allows enabling pinning within an App without having to find and modify each and every instance of `NSURLConnection` or `NSURLSession` delegates.
 However, it should only be enabled for simple Apps, as it may not work properly in several scenarios including:
 
 * Apps with complex connection delegates, for example to handle client authentication via certificates or basic authentication.
 * Apps where method swizzling of the connection delegates is already performed by another module or library (such as Analytics SDKs).
 * Apps that do no use `NSURLSession` or `NSURLConnection` for their connections.
 
 In such scenarios or if the developer wants a tigher control on the App's networking behavior, `kTSKSwizzleNetworkDelegates` should be set to `NO`; the developer should then manually add pinning validation to the App's authentication handlers.
 
 See the `TSKPinningValidator` class for instructions on how to do so.
 */
FOUNDATION_EXPORT const TSKGlobalConfigurationKey kTSKSwizzleNetworkDelegates;


/**
 A dictionary with domains (such as _www.domain.com_) as keys and dictionaries as values.
 
 Each entry should contain domain-specific settings for performing pinning validation when connecting to the domain, including for example the domain's public key hashes. A list of all domain-specific keys is available in the "Domain-specific Keys" sections.
 */
FOUNDATION_EXPORT const TSKGlobalConfigurationKey kTSKPinnedDomains;



#pragma mark Global Configuration Keys - Optional


/**
 A boolean. If set to `YES`, pinning validation will be skipped if the server's certificate chain terminates at a user-defined trust anchor (such as a root CA that isn't part of OS X's default trust store) and no pin failure reports will be sent; default value is `YES`.
 
 This is useful for allowing SSL connections through corporate proxies or firewalls. See "How does key pinning interact with local proxies and filters?" within the Chromium security FAQ at https://www.chromium.org/Home/chromium-security/security-faq for more information.
 
 Only available on macOS.
 */
FOUNDATION_EXPORT const TSKGlobalConfigurationKey kTSKIgnorePinningForUserDefinedTrustAnchors NS_AVAILABLE_MAC(10_9);


#pragma mark Domain-Specific Configuration Keys - Required

/**
 An array of SSL pins, where each pin is the base64-encoded SHA-256 hash of a certificate's Subject Public Key Info.
 
 TrustKit will verify that at least one of the specified pins is found in the server's evaluated certificate chain.
 */
FOUNDATION_EXPORT const TSKDomainConfigurationKey kTSKPublicKeyHashes;


/**
 An array of `TSKSupportedAlgorithm` constants to specify the public key algorithms for the keys to be pinned.
 
 TrustKit requires this information in order to compute SSL pins when validating a server's certificate chain, because the `Security` framework does not provide APIs to extract the key's algorithm from an SSL certificate. To minimize the performance impact of Trustkit, only one algorithm should be enabled.
*/
FOUNDATION_EXPORT const TSKDomainConfigurationKey kTSKPublicKeyAlgorithms;


#pragma mark Domain-Specific Configuration Keys - Optional

/**
 A boolean. If set to `NO`, TrustKit will not block SSL connections that caused a pin or certificate validation error; default value is `YES`.
 
 When a pinning failure occurs, pin failure reports will always be sent to the configured report URIs regardless of the value of `kTSKEnforcePinning`.
 */
FOUNDATION_EXPORT const TSKDomainConfigurationKey kTSKEnforcePinning;


/**
 A boolean. If set to `YES`, also pin all the subdomains of the specified domain; default value is `NO`.
 */
FOUNDATION_EXPORT const TSKDomainConfigurationKey kTSKIncludeSubdomains;


/**
 A boolean. If set to `YES`, TrustKit will not pin this specific domain if `kTSKIncludeSubdomains` was set for this domain's parent domain.
 
 This allows excluding specific subdomains from a pinning policy that was applied to a parent domain.
 */
FOUNDATION_EXPORT const TSKDomainConfigurationKey kTSKExcludeSubdomainFromParentPolicy;


/**
 An array of URLs to which pin validation failures should be reported.
 
 To minimize the performance impact of sending reports on each validation failure, the reports are uploaded using the background transfer service and are also rate-limited to one per day and per type of failure. For HTTPS report URLs, the HTTPS connections will ignore the SSL pinning policy and use the default certificate validation mechanisms, in order to maximize the chance of the reports reaching the server. The format of the reports is similar to the one described in RFC 7469 for the HPKP specification:
 
    {
        "app-bundle-id": "com.datatheorem.testtrustkit2",
        "app-version": "1",
        "app-vendor-id": "599F9C00-92DC-4B5C-9464-7971F01F8370",
        "app-platform": "IOS",
        "app-platform-version": "10.2.0",
        "trustkit-version": "1.3.1",
        "hostname": "www.datatheorem.com",
        "port": 0,
        "noted-hostname": "datatheorem.com",
        "include-subdomains": true,
        "enforce-pinning": true,
        "validated-certificate-chain": [
            pem1, ... pemN
        ],
        "known-pins": [
            "pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"",
            "pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\""
        ],
        "validation-result":1
    }
 */
FOUNDATION_EXPORT const TSKDomainConfigurationKey kTSKReportUris;


/**
 A boolean. If set to `YES`, the default report URL for sending pin failure reports will be disabled; default value is `NO`.
 
 By default, pin failure reports are sent to a report server hosted by Data Theorem, for detecting potential CA compromises and man-in-the-middle attacks, as well as providing a free dashboard for developers; email info@datatheorem.com if you'd like a dashboard for your App. Only pin failure reports are sent, which contain the App's bundle ID, the IDFV, and the server's hostname and certificate chain that failed validation.
 */
FOUNDATION_EXPORT const TSKDomainConfigurationKey kTSKDisableDefaultReportUri;


/**
 A string containing the date, in yyyy-MM-dd format, on which the domain's configured SSL pins expire, thus disabling pinning validation. If the key is not set, then the pins do not expire.
 
 Expiration helps prevent connectivity issues in Apps which do not get updates to their pin set, such as when the user disables App updates.
 */
FOUNDATION_EXPORT const TSKDomainConfigurationKey kTSKExpirationDate;



#pragma mark Supported Public Key Algorithm Keys


/**
 A public key algorithm supported by TrustKit for computing SSL pins: 
 
 * `kTSKAlgorithmRsa2048`
 * `kTSKAlgorithmRsa4096`
 * `kTSKAlgorithmEcDsaSecp256r1`
 * `kTSKAlgorithmEcDsaSecp384r1`
 
 */
typedef NSString *TSKSupportedAlgorithm;


/**
 RSA 2048.
 */
FOUNDATION_EXPORT const TSKSupportedAlgorithm kTSKAlgorithmRsa2048;


/**
 RSA 4096.
 */
FOUNDATION_EXPORT const TSKSupportedAlgorithm kTSKAlgorithmRsa4096;


/**
 ECDSA with secp256r1 curve.
 */
FOUNDATION_EXPORT const TSKSupportedAlgorithm kTSKAlgorithmEcDsaSecp256r1;


/**
 ECDSA with secp384r1 curve.
 */
FOUNDATION_EXPORT const TSKSupportedAlgorithm kTSKAlgorithmEcDsaSecp384r1;


#pragma mark Pinning Validation Notification Name

/**
 The `name` of the notification to be posted for every request that is going through TrustKit's pinning validation mechanism.
 
 Once TrustKit has been initialized, notifications will be posted with this `name` every time TrustKit validates the certificate chain for a server configured in the SSL pinning policy; if the server's hostname does not have an entry in the pinning policy, no notifications get posted as no pinning validation was performed.
 
 These notifications can be used for performance measurement or to act upon any pinning validation performed by TrustKit (for example to customize the reporting mechanism). The notifications provide details about TrustKit's inner-workings which most Apps should not need to process. Hence, these notifications can be ignored unless the App requires some advanced customization in regards to pinning validation.
 */
FOUNDATION_EXPORT NSString *kTSKValidationCompletedNotification;


#pragma mark Pinning Validation Notification UserInfo Keys

/**
 A key to be used to retrieve data about the pinning validation that occured, from the `userInfo` dictionary attached to a `kTSKValidationCompletedNotification` notification.
 */
typedef NSString *TSKNotificationUserInfoKey;


/**
 The time in seconds it took for the SSL pinning validation to be performed.
 */
FOUNDATION_EXPORT const TSKNotificationUserInfoKey kTSKValidationDurationNotificationKey;


/**
 The `TSKPinningValidationResult` returned when validating the server's certificate chain, which represents the result of evaluating the certificate chain against the configured SSL pins for this server.
 */
FOUNDATION_EXPORT const TSKNotificationUserInfoKey kTSKValidationResultNotificationKey;

/**
 The `TSKTrustDecision` returned when validating the certificate's chain, which describes whether the connection should be blocked or allowed, based on the `TSKPinningValidationResult` returned when evaluating the server's certificate chain and the SSL pining policy configured for this server.
 
 For example, the pinning validation could have failed (returning `TSKPinningValidationFailed`) but the policy might be set to ignore pinning validation failures for this server, thereby returning `TSKTrustDecisionShouldAllowConnection`.
 */
FOUNDATION_EXPORT const TSKNotificationUserInfoKey kTSKValidationDecisionNotificationKey;

/**
 The certificate chain returned by the server as an array of PEM-formatted certificates.
 */
FOUNDATION_EXPORT const TSKNotificationUserInfoKey kTSKValidationCertificateChainNotificationKey;

/**
 The entry within the SSL pinning configuration that was used as the pinning policy for the server being validated. It will be the same as the `kTSKValidationServerHostnameNotificationKey` entry unless the server is a subdomain of a domain configured in the pinning policy with `kTSKIncludeSubdomains` enabled. The corresponding pinning configuration that was used for validation can be retrieved using:
    
     NSString *notedHostname = userInfo[kTSKValidationNotedHostnameNotificationKey];
     NSDictionary *hostnameConfiguration = [TrustKit configuration][kTSKPinnedDomains][notedHostname];
 */
FOUNDATION_EXPORT const TSKNotificationUserInfoKey kTSKValidationNotedHostnameNotificationKey;

/**
 The hostname of the server SSL pinning validation was performed against.
 */
FOUNDATION_EXPORT const TSKNotificationUserInfoKey kTSKValidationServerHostnameNotificationKey;


/**
 `TrustKit` is a class for programmatically configuring the global SSL pinning policy within an App.
 
  The policy can be set either by adding it to the App's _Info.plist_ under the `TSKConfiguration` key, or by programmatically supplying it using the `TrustKit` class described here. Throughout the App's lifecycle, TrustKit can only be initialized once so only one of the two techniques should be used.
 
 A TrustKit pinning policy is a dictionary which contains some global, App-wide settings (of type `TSKGlobalConfigurationKey`) as well as domain-specific configuration keys (of type `TSKDomainConfigurationKey`) to be defined under the `kTSKPinnedDomains` entry. The following table shows the keys and the types of the corresponding values, and uses indentation to indicate structure:
 
 ```
 | Key                                          | Type       |
 |----------------------------------------------|------------|
 | TSKSwizzleNetworkDelegates                   | Boolean    |
 | TSKIgnorePinningForUserDefinedTrustAnchors   | Boolean    |
 | TSKPinnedDomains                             | Dictionary |
 | __ <domain-name-to-pin-as-string>            | Dictionary |
 | ____ TSKPublicKeyHashes                      | Array      |
 | ____ TSKPublicKeyAlgorithms                  | Array      |
 | ____ TSKIncludeSubdomains                    | Boolean    |
 | ____ TSKExcludeSubdomainFromParentPolicy     | Boolean    |
 | ____ TSKEnforcePinning                       | Boolean    |
 | ____ TSKReportUris                           | Array      |
 | ____ TSKDisableDefaultReportUri              | Boolean    |
 ```
 
 When setting the pinning policy programmatically, it has to be supplied to the `initializeWithConfiguration:` method as a dictionary. For example:
 
 ```
    NSDictionary *trustKitConfig =
  @{
    kTSKSwizzleNetworkDelegates: @NO,
    kTSKPinnedDomains : @{
            @"www.datatheorem.com" : @{
                    kTSKExpirationDate: @"2017-12-01",
                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                    kTSKPublicKeyHashes : @[
                            @"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
                            @"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="
                            ],
                    kTSKEnforcePinning : @NO,
                    kTSKReportUris : @[@"http://report.datatheorem.com/log_report"],
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
 ```
 
 Similarly, TrustKit can be initialized in Swift:
 
 ```
        let trustKitConfig = [
            kTSKSwizzleNetworkDelegates: false,
            kTSKPinnedDomains: [
                "yahoo.com": [
                    kTSKExpirationDate: "2017-12-01",
                    kTSKPublicKeyAlgorithms: [kTSKAlgorithmRsa2048],
                    kTSKPublicKeyHashes: [
                        "JbQbUG5JMJUoI6brnx0x3vZF6jilxsapbXGVfjhN8Fg=",
                        "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18="
                    ],]]] as [String : Any]
        
        TrustKit.initialize(withConfiguration:trustKitConfig)
 ```
 
 The various configuration keys that can be specified in the policy are described in the "Constants" section of the documentation.
 
 Lastly, once TrustKit has been initialized, `kTSKValidationCompletedNotification` notifications will be posted every time TrustKit validates the certificate chain of a server; these notifications provide some information about the validation that was done and can be used for example for performance measurement.
 
 */
@interface TrustKit : NSObject

///---------------------
/// @name Initialization
///---------------------

/**
 Initialize the global SSL pinning policy with the supplied configuration.
 
 This method should be called as early as possible in the App's lifecycle to ensure that the App's very first SSL connections are validated by TrustKit. Once TrustKit has been initialized, notifications will be posted for any SSL pinning validation performed.
 
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
