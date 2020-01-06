TrustKit
========

[![Build Status](https://app.bitrise.io/app/fe29405fb90f94ea/status.svg?token=TJ3o4dhSWa--0ZlJT7FV1A)](https://app.bitrise.io/app/fe29405fb90f94ea) [![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage) [![Version Status](https://img.shields.io/cocoapods/v/TrustKit.svg?style=flat)](https://cocoapods.org/pods/TrustKit) [![Platform](https://img.shields.io/cocoapods/p/TrustKit.svg?style=flat)](https://cocoapods.org/pods/TrustKit) [![License MIT](https://img.shields.io/cocoapods/l/TrustKit.svg?style=flat)](https://en.wikipedia.org/wiki/MIT_License)
[![Gitter chat](https://badges.gitter.im/datatheorem/gitter.png)](https://gitter.im/TrustKit/Lobby)

**TrustKit** is an open source framework that makes it easy to deploy SSL public key pinning and reporting in any iOS 10+, macOS 10.10+, tvOS 10+ or watchOS 3+ App; it supports both Swift and Objective-C Apps.

If you need SSL pinning/reporting in your Android App. we have also released **TrustKit for Android** at [https://github.com/datatheorem/TrustKit-Android](https://github.com/datatheorem/TrustKit-Android).


Overview
--------

**TrustKit** provides the following features:

* Simple API to configure an SSL pinning policy and enforce it within an App. The policy settings are heavily based on the [HTTP Public Key Pinning specification](https://tools.ietf.org/html/rfc7469).
* Sane implementation by pinning the certificate's Subject Public Key Info, [as opposed to the certificate itself or the public key bits](https://www.imperialviolet.org/2011/05/04/pinning.html).
* Reporting mechanism to notify a server about pinning validation failures happening within the App, when an unexpected certificate chain is detected. This is similar to the _report-uri_ directive described in the HPKP specification. The reporting mechanism can also be customized within the App by leveraging pin validation notifications sent by TrustKit.
* Auto-pinning functionality by swizzling the App's _NSURLConnection_ and _NSURLSession_ delegates in order to automatically add pinning validation to the App's HTTPS connections; this allows deploying **TrustKit** without even modifying the App's source code.


Getting Started
---------------

* Read the [Getting Started][getting-started] guide.
* Check out the [API documentation][api-doc].
* TrustKit was initially released at [Black Hat USA 2015][bh2015-pdf] and was also featured on [PayPal's engineering blog][paypal-post].


Sample Usage
------------

Deploying SSL pinning in the App requires initializing **TrustKit** with a pinning policy (domains, Subject Public Key Info hashes, and additional settings).

The policy can be configured within the App's `Info.plist`:

![Info.plist policy](https://datatheorem.github.io/TrustKit/images/linking3_dynamic.png)

Alternatively, the pinning policy can be set programmatically:

```objc
    NSDictionary *trustKitConfig =
  @{
    kTSKSwizzleNetworkDelegates: @NO,
    kTSKPinnedDomains : @{
            @"www.datatheorem.com" : @{
                    kTSKExpirationDate: @"2017-12-01",
                    kTSKPublicKeyHashes : @[
                            @"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
                            @"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="
                            ],
                    kTSKEnforcePinning : @NO,
                    kTSKReportUris : @[@"http://report.datatheorem.com/log_report"],
                    },
            @"yahoo.com" : @{
                    kTSKPublicKeyHashes : @[
                            @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                            @"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=",
                            ],
                    kTSKIncludeSubdomains : @YES
                    }
            }};
    
    [TrustKit initSharedInstanceWithConfiguration:trustKitConfig];
```

The policy can also be set programmatically in Swift Apps:
 
```swift
        let trustKitConfig = [
            kTSKSwizzleNetworkDelegates: false,
            kTSKPinnedDomains: [
                "yahoo.com": [
                    kTSKExpirationDate: "2017-12-01",
                    kTSKPublicKeyHashes: [
                        "JbQbUG5JMJUoI6brnx0x3vZF6jilxsapbXGVfjhN8Fg=",
                        "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18="
                    ],]]] as [String : Any]
        
        TrustKit.initSharedInstance(withConfiguration:trustKitConfig)
```

After TrustKit has been initialized, a 
[`TSKPinningValidator` instance](https://datatheorem.github.io/TrustKit/documentation/Classes/TSKPinningValidator.html) 
can be retrieved from the TrustKit singleton, and can be used to perform SSL pinning validation 
in the App's network delegates. For example in an NSURLSessionDelegate:

```objc
- (void)URLSession:(NSURLSession *)session 
              task:(NSURLSessionTask *)task 
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge 
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler {
{
    TSKPinningValidator *pinningValidator = [[TrustKit sharedInstance] pinningValidator];
    // Pass the authentication challenge to the validator; if the validation fails, the connection will be blocked
    if (![pinningValidator handleChallenge:challenge completionHandler:completionHandler])
    {
        // TrustKit did not handle this challenge: perhaps it was not for server trust
        // or the domain was not pinned. Fall back to the default behavior
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}
```

For more information, see the [Getting Started][getting-started] guide.


Credits
-------

**TrustKit** is a joint-effort between the mobile teams at Data Theorem and Yahoo. See `AUTHORS` for details.


License
-------

**TrustKit** is released under the MIT license. See `LICENSE` for details.

[getting-started]: https://github.com/datatheorem/TrustKit/blob/master/docs/getting-started.md
[bh2015-pdf]: https://github.com/datatheorem/TrustKit/blob/master/docs/TrustKit-BH2015.pdf
[bh2015-conf]: https://www.blackhat.com/us-15/briefings.html#trustkit-code-injection-on-ios-8-for-the-greater-good
[api-doc]: https://datatheorem.github.io/TrustKit/documentation
[ios9-post]: https://datatheorem.github.io/ios/2015/10/17/trustkit-ios-9-shared-cache/
[paypal-post]: https://www.paypal-engineering.com/2015/10/14/key-pinning-in-mobile-applications/
