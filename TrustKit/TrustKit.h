/*
 
 TrustKit.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

@import Foundation;

@class TSKPinningValidator;
@class TSKPinningValidatorResult;

NS_ASSUME_NONNULL_BEGIN

/**
 The version of TrustKit, such as "1.4.0".
 */
FOUNDATION_EXPORT NSString * const TrustKitVersion;

/** The default URI – maintained by DataTheorem – used for pinning failure reports
 if none is specified in the configuration.
 */
FOUNDATION_EXPORT NSString * const kTSKDefaultReportUri;

/**
 `TrustKit` is a class for programmatically configuring the global SSL pinning policy 
 within an App.
 
  The policy can be set either by adding it to the App's _Info.plist_ under the 
 `TSKConfiguration` key, or by programmatically supplying it using the `TrustKit` class 
 described here. Throughout the App's lifecycle, TrustKit can only be initialized once so 
 only one of the two techniques should be used.
 
 A TrustKit pinning policy is a dictionary which contains some global, App-wide settings 
 (of type `TSKGlobalConfigurationKey`) as well as domain-specific configuration keys
 (of type `TSKDomainConfigurationKey`) to be defined under the `kTSKPinnedDomains` entry. 
 The following table shows the keys and the types of the corresponding values, and uses
 indentation to indicate structure:
 
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
 
 When setting the pinning policy programmatically, it has to be supplied to the
 `initializeWithConfiguration:` method as a dictionary. For example:
 
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
 
 The various configuration keys that can be specified in the policy are described in the
 "Constants" section of the documentation.
 */
@interface TrustKit : NSObject

///---------------------
/// @name Initialization
///---------------------
#pragma mark Class Methods


/**
 Access the shared TrustKit singleton instance. Raises an exception if +initializeWithConfiguration:
 has not yet been invoked.

 @return the shared TrustKit singleton
 */
+ (instancetype)sharedInstance;

/**
 Initialize the global SSL pinning policy with the supplied configuration.
 
 This method should be called as early as possible in the App's lifecycle to ensure that
 the App's very first SSL connections are validated by TrustKit. Once TrustKit has been
 initialized, notifications will be posted for any SSL pinning validation performed.
 
 @param trustKitConfig A dictionary containing various keys for configuring the global SSL
 pinning policy.
 @exception NSException Thrown when the supplied configuration is invalid or TrustKit has
 already been initialized.
 
 */
+ (void)initializeWithConfiguration:(NSDictionary *)trustKitConfig;


///----------------------------
/// @name Current Configuration
///----------------------------

/**
 Retrieve a copy of the global SSL pinning policy.
 
 @return A dictionary with a copy of the current TrustKit configuration, or `nil` if
 TrustKit has not been initialized.
 */
+ (NSDictionary * _Nullable) configuration;

#pragma mark Instance Methods

/**
 Initialize a TrustKit instance with the supplied SSL pinning policy configuration.
 
 This method should be called as early as possible in the App's lifecycle to ensure that 
 the App's very first SSL connections are validated by TrustKit. Once TrustKit has been
 initialized, notifications will be posted for any SSL pinning validation performed.
 
 @param trustKitConfig A dictionary containing various keys for configuring the global
        SSL pinning policy.
 @param uniqueIdentifier An identifier for this instance. It is required if you want the
        pin to be persisted to disk.
 */
- (instancetype)initWithConfiguration:(NSDictionary<NSString *, id> * _Nullable)trustKitConfig
                           identifier:(NSString * _Nullable)uniqueIdentifier;

/**
 Retrieve the SSL pinning policy for this instance.
 
 @return A dictionary with the current TrustKit configuration
 */
@property (nonatomic, readonly, nullable) NSDictionary *configuration;

/**
 A pinning validator instance conforming to the configuration of this TrustKit instance.
 */
@property (nonatomic, nonnull) TSKPinningValidator *pinningValidator;

/**
 Register a block to be invoked for every request that is going through TrustKit's pinning
 validation mechanism.
 
 Once TrustKit has been initialized, the callback will be invoked every time TrustKit validates 
 the certificate chain for a server configured in the SSL pinning policy; if the server's 
 hostname does not have an entry in the pinning policy, no invocations will result as no
 pinning validation was performed.
 
 This callback can be used for performance measurement or to act upon any pinning validation
 performed by TrustKit (for example to customize the reporting mechanism). The callback
 provide the `TSKPinningValidatorResult` resulting from the validation. That instance provides
 access to TrustKit's inner-workings which most Apps should not need. Hence, this callback
 should not be set unless the App requires some advanced customization in regards to pinning
 validation. Keep in mind that, if set, the callback may be invoked very frequently and is
 not a suitable place for expensive tasks.
 */
@property (nonatomic, nullable) void(^validationDelegateCallback)(TSKPinningValidatorResult * _Nonnull result);

/**
 Queue on which to invoke `validationDelegateCallback` (if set). Default value is main queue.
 */
@property (nonatomic, null_resettable) dispatch_queue_t validationDelegateQueue;

@end
NS_ASSUME_NONNULL_END
