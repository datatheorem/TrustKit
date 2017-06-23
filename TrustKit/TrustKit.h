/*
 
 TrustKit.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

@import Foundation;

#ifndef _TRUSTKIT_
#define _TRUSTKIT_
    #import "TSKTrustKitConfig.h"
    #import "TSKPinningValidatorResult.h"
    #import "TSKPinningValidator.h"
    #import "TSKTrustDecision.h"
#endif /* _TRUSTKIT_ */

NS_ASSUME_NONNULL_BEGIN


/**
 `TrustKit` is a class for programmatically configuring an SSL pinning policy within an App.
 
 For most Apps, TrustKit should be used as a singleton, where a global SSL pinning policy is
 configured for the App. In singleton mode, the policy can be set either:
 
 * By adding it to the App's _Info.plist_ under the `TSKConfiguration` key, or 
 * By programmatically supplying it using the `initializeWithConfiguration:` method. 
 
 In singleton mode, TrustKit can only be initialized once so only one of the two techniques 
 should be used.
 
 For more complex Apps where multiple SSL pinning policies need to be used independently 
 (for example within different frameworks), TrustKit can be used in "multi-instance" mode
 by leveraging the `initWithConfiguration:identifier:` method described at the end of this 
 page.
 
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
 | ____ TSKAdditionalTrustAnchors               | Array      |
 ```
 
 When setting the pinning policy programmatically, it has to be supplied to the
 `initializeWithConfiguration:` method as a dictionary in order to initialize TrustKit. 
 For example:
 
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
    trustKit = [TrustKit sharedInstance];
 ```
 
 Similarly, the TrustKit singleton can be initialized in Swift:
 
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


#pragma mark Singleton Mode

/**
 Initialize the global TrustKit singleton with the supplied pinning policy.
 
 @param trustKitConfig A dictionary containing various keys for configuring the SSL pinning policy.
 @exception NSException Thrown when the supplied configuration is invalid or TrustKit has
 already been initialized.
 
 */
+ (void)initializeWithConfiguration:(NSDictionary *)trustKitConfig;


/**
 Retrieve the global TrustKit singleton instance. Raises an exception if +initializeWithConfiguration:
 has not yet been invoked.
 
 @return the shared TrustKit singleton
 */
+ (instancetype)sharedInstance;


/**
 Retrieve the SSL pinning policy configured for this TrustKit instance.
 
 @return A dictionary with the current TrustKit configuration
 */
@property (nonatomic, readonly, nullable) NSDictionary *configuration;


/**
 Retrieve the validator instance conforming to the pinning policy of this TrustKit instance.
 
 The validator should be used to implement pinning validation within the App's network
 authentication handlers.
 */
@property (nonatomic, nonnull) TSKPinningValidator *pinningValidator;


/**
 Register a block to be invoked for every request that is going through TrustKit's pinning
 validation mechanism.
 
 The callback will be invoked every time the validator performs pinning validation against a server's
 certificate chain; if the server's hostname is not defined in the pinning policy, no invocations will
 result as no pinning validation was performed.
 
 The callback provides the `TSKPinningValidatorResult` resulting from the validation, and can be 
 used for advanced features such as performance measurement or customizing the reporting mechanism.
 Hence, most Apps should not have to use this callback. If set, the callback may be invoked very
 frequently and is not a suitable place for expensive tasks.
 
 Lastly, the callback is always invoked after the validation has been completed, and therefore
 cannot be used to modify the result of the validation (for example to accept invalid certificates).
 */
@property (nonatomic, nullable) void(^validationDelegateCallback)(TSKPinningValidatorResult * _Nonnull result);

/**
 Queue on which to invoke `validationDelegateCallback` (if set). Default value is the main queue.
 */
@property (nonatomic, null_resettable) dispatch_queue_t validationDelegateQueue;


#pragma mark Multi-Instance Mode

/**
 Initialize a local TrustKit instance with the supplied SSL pinning policy configuration.
 
 This method is useful in scenarios where the TrustKit singleton cannot be used, for example within
 larger Apps that have split some of their functionality into multiple framework/SDK. Each 
 framework can initialize its own instance of TrustKit and use it for pinning validation independently
 of the App's other components.
 
 @param trustKitConfig A dictionary containing various keys for configuring the SSL pinning policy.
 @param uniqueIdentifier An identifier for this instance.
 */
- (instancetype)initWithConfiguration:(NSDictionary<NSString *, id> * _Nullable)trustKitConfig
                           identifier:(NSString * _Nonnull)uniqueIdentifier;


@end
NS_ASSUME_NONNULL_END
