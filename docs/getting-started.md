# Getting Started

Adding TrustKit to an App can be achieved through the following steps:

1. Generating SSL pins for the App's server endpoints and choosing a pinning
policy.
2. Adding TrustKit as a dependency to the App's Xcode project.
3. Initializing TrustKit with the pinning policy.


## Warning

Public key pinning can be dangerous and requires more than just code-level
changes in your App. If you make a mistake, you might cause your App to pin a
set of keys that validates today but which stops validating a week or a year
from now, if something changes. In that case, your App will no longer be able to
connect to its servers and will most likely stop working, until it gets updated
with a new set of pins.

Unless you are confident that you understand the Web PKI that you can manage
the App servers' cryptographic identity very well, you should not use key
pinning.


## Generating SSL Pins

Before deploying SSL pinning within your App, you first need to investigate and
choose which domains and public keys need to be pinned. This is **very
important** as enabling the wrong pinning policy may prevent your App from being
able to connect to its servers, when the servers' keys are rotated.

The following blog post provides some information on which keys to pin and what
the trade-offs are:
[https://noncombatant.org/2015/05/01/about-http-public-key-pinning/](https://noncombatant.org/2015/05/01/about-http-public-key-pinning/).

In the context of TrustKit, an SSL pin is the base64-encoded SHA-256 of a
certificate's Subject Public Key Info; this is the same as what is described in
the [HTTP Public Key Pinning
specification](https://developer.mozilla.org/en-US/docs/Web/Security/Public_Key_Pinning).

To generate such values, a Python helper script is available within the project's 
repository; it can be used to generate the pin configuration from a PEM or DER 
certificate:

    $ python get_pin_from_certificate.py ca.pem
    $ python get_pin_from_certificate.py --type DER ca.der


## Deploying TrustKit

### Adding TrustKit as a Dependency

#### CocoaPods

Add the following line to your Podfile:

    pod 'TrustKit'

Then run:

    $ pod install

#### Carthage

Add the following line to your Cartfile:
    
    github "datatheorem/TrustKit"

Then run:

    $ carthage update
    $ carthage build --platform iOS --configuration Debug

Lastly, on your application targets’ “General” settings tab, in the “Embedded Binaries” 
section, drag and drop the TrustKit framework you want to use from the Carthage/Build
folder on disk.

### Configuring a Pinning Policy

Enabling TrustKit within an App requires generating a pinning policy and then
initializing TrustKit by calling the `initSharedInstanceWithConfiguration:` method with your 
pinning policy.

A pinning policy is a dictionary of domain names and pinning configuration keys.
At a minimum, the configuration should specify a list of SSL pins. For example:

```objc
#import <TrustKit/TrustKit.h>

NSDictionary *trustKitConfig =
@{
  // The list of domains we want to pin and their configuration
  kTSKPinnedDomains: @{
          
          @"yahoo.com" : @{
                  // Pin all subdomains of yahoo.com
                  kTSKIncludeSubdomains:@YES,
                  
                  // Do not block connections if pinning validation failed so the App doesn't break
                  kTSKEnforcePinning:@NO,
                
                  // Send reports for pin validation failures so we can track them
                  kTSKReportUris: @[@"https://some-reporting-server.com/log_report"],
                  
                  // The pinned public keys' Subject Public Key Info hashes
                  kTSKPublicKeyHashes : @[
                          @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                          @"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=",
                          ],
                  },
          
          @"www.datatheorem.com" : @{
                  // Block connections if pinning validation failed
                  kTSKEnforcePinning:@YES,
                  
                  kTSKPublicKeyHashes : @[
                          @"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
                          @"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="
                          ]
}}};
[TrustKit initSharedInstanceWithConfiguration:trustKitConfig];
```

The list of all the configuration keys is available in the
[documentation](https://datatheorem.github.io/TrustKit/documentation/Classes/TrustKit.html).

### Implementing Pinning Validation

After TrustKit has been initialized, a 
[`TSKPinningValidator` instance](https://datatheorem.github.io/TrustKit/documentation/Classes/TSKPinningValidator.html) 
can be retrieved from the TrustKit singleton, and can be used to perform SSL pinning validation 
in the App's network delegates. For example in an NSURLSessionDelegate:

```objc
- (void)URLSession:(NSURLSession *)session 
              task:(NSURLSessionTask *)task 
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge 
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
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

Some additional consideration in regards to the right pinning policy to deploy follow. 

### Additional Notes

#### Always start with pinning enforcement disabled

To avoid locking out too many users from your App when deploying SSL pinning
for the first time, it is advisable to set `kTSKEnforcePinning` to `NO`, so that SSL 
connections will succeed regardless of pin validation. This means that TrustKit
will mirror iOS' default behavior.


#### Always provide at least one backup pin

In order to prevent accidentally locking users out of your site, make sure you
have at least one backup pin and that you have procedures in place to
transition to using the backup pin if your primary pin can no longer be used.
For example, if you pin to the public key of your server's certificate, you
should generate a backup key that is stored somewhere safe. If you pin to an
intermediate CA or a root CA, then you should also select an alternative CA
that you are willing to switch to if your current CA (or their intermediate CA)
becomes invalid for some reason.

If you do not have a backup pin, you could inadvertently prevent your app from
working until you released a new version of your app, and your users updated
it. [One such
incident](https://cabforum.org/pipermail/public/2016-November/008989.html) led
to a bank having to ask their CA to issue a new certificate using a deprecated
intermediate CA in order to allow their users to use the app, or face weeks of
the app being unusable.


#### Properly implement pinning in WebViews

Adding SSL pinning to connections initiated within a `UIWebView` is difficult as the 
class does not provide direct APIs to handle authentication challenges. As 
mentionned in [Apple's technical note about HTTPS trust evaluation](https://developer.apple.com/library/ios/technotes/tn2232/_index.html), 
customizing certificate validation in a `UIWebView` can still be achieved using 
`NSURLProtocol` to intercept all outgoing connections. However, implemeting this 
technique is a complex and significant engineering effort. 

Overall, the best approach to implementing SSL pinning in webviews is by 
migrating to the `WKWebView` class introduced in iOS 8, which provides 
[delegate methods](https://developer.apple.com/library/ios/documentation/WebKit/Reference/WKNavigationDelegate_Ref/) 
to handle authentication challenges (such as server SSL certificate validation).
However, this approach still requires some testing as it seems like the 
`webView:didReceiveAuthenticationChallenge:completionHandler:` delegate method 
[only works reliably on iOS 9](https://bugs.webkit.org/show_bug.cgi?id=135327).


#### Consider leveraging auto-swizzling for simple Apps

For simple Apps, TrustKit can be deployed without having to modify the App's
source code. 

First, TrustKit should be initialized by adding configuration keys to the App's 
_Info.plist_ file under a `TSKConfiguration` dictionary key, instead of using 
`TrustKit`'s initialization method:

![](https://datatheorem.github.io/TrustKit/images/linking3_dynamic.png)

By setting the `kTSKSwizzleNetworkDelegates` key to `YES`, TrustKit will then 
perform method swizzling on the App's `NSURLSession` and `NSURLConnection` 
delegates in order to automatically perform SSL pinning validation against the server's 
certificate chain, based on the configured pinning policy. This allows deploying TrustKit
without changing the App's source code.

Auto-swizzling should only be enabled for simple Apps, as it may not work properly 
in several scenarios including:
    
* Apps with complex connection delegates, for example to handle client 
authentication via certificates or basic authentication.
* Apps where method swizzling of the connection delegates is already performed 
by another module or library (such as Analytics SDKs)
* Apps that do no use `NSURLSession` or `NSURLConnection` for their 
connections.

Even when auto-swizzling is enabled with `kTSKSwizzleNetworkDelegates`, there
are specific scenarios where TrustKit cannot intercept outgoing SSL connections 
and automatically validate the server's identity against the pinning policy. For these 
connections, the pin validation must be manually implemented using the 
[`TSKPinningValidator` class](https://datatheorem.github.io/TrustKit/documentation/Classes/TSKPinningValidator.html) 
class. 

#### Deploy a reporting server or use Data Theorem's free server

Adding a report URL using the `kTSKReportUris` setting to receive pin validation 
failure reports will help track pin validation failures happening across your user 
base. You can use your own report server or Data Theorem's, which provides a 
dashboard to display these reports for free (email info@datatheorem.com for 
access).

This will give you an idea of how many users would be blocked, if pin validation 
was to be enforced.

## Appendices

### Debugging network connections with TrustKit

SSL pinning can make it difficult for developers to develop network clients or
troubleshoot network requests. Common tools like Charles Proxy use self-signed
SSL certificates to effectively create an (untrusted) SSL proxy. This allows
Charles to decrypt and read SSL-protected information for debugging or reverse
engineering purposes. Since this configuration is identical to a malicious
man-in-the-middle attack, TrustKit will reject such proxied SSL connections.

There are several options available to mitigate this issue.

#### For small development teams

Create a self-signed SSL certificate authority for Charles to use instead of its
default randomly generated CA. This team CA cert & private key can be shared among
teammates and set as the custom root CA in each instance of Charles. The root CA
certificate must be installed and trusted in each iOS Simulator and Device used
for development.

For debugging in production, users will need to trust the self-signed root CA –
which is potentially dangerous and requires the owner of the device to enter their
passcode.

#### For large or enterprise development teams

If you're working in an enterprise environment where sharing a root CA certificate
and private key is impractical, issuing intermediate CA certs and keys might work
better. In this case, you create a self-signed root certificate authority which is
maintained in a production-secure fashion. This CA can issue intermediate CA certs
for use with Charles or other tools, as needed.

In this case, your SSL proxy can use an intermediate CA to proxy SSL requests. That
intermediate certifiate would not be pinned by TrustKit, but the self-signed root CA
would be. It's optional but recommended for the intermedate CA have a short validity
window (short expiration) and include a personal identifier for the employee that
requested the certificate (i.e. employee email in intermediate CA email field). This
way, if a rogue employee were to issue an intermediate CA certificate and bypass
protections in TrustKit, you'd be able to trace any attacks back to a person.
