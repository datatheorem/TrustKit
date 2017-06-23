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
    
    github "datatheorem/TrustKit" == 1.5.0

Then run:

    $ carthage build --platform iOS

Lastly, on your application targets’ “General” settings tab, in the “Embedded Binaries” 
section, drag and drop the TrustKit framework you want to use from the Carthage/Build
folder on disk.

### Configuring a Pinning Policy

Enabling TrustKit within an App requires generating a pinning policy and then
initializing TrustKit with this policy. There are two different ways to supply
a pinning policy to TrustKit:

* By adding configuration keys to the App's _Info.plist_ file under a 
`TSKConfiguration` dictionary key:

    ![](https://datatheorem.github.io/TrustKit/images/linking3_dynamic.png)

* Programmatically, by calling the `initializeWithConfiguration:` method with your 
pinning policy.

A pinning policy is a dictionary of domain names and pinning configuration keys.
At a minimum, the configuration should specify a list of SSL pins and the
corresponding certificates' public key algorithms. For example:

```
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
                  
                  // The pinned public keys' algorithms
                  kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                  
                  // The pinned public keys' Subject Public Key Info hashes
                  kTSKPublicKeyHashes : @[
                          @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                          @"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=",
                          ],
                  },
          
          @"www.datatheorem.com" : @{
                  // Block connections if pinning validation failed
                  kTSKEnforcePinning:@YES,
                  
                  kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                  
                  kTSKPublicKeyHashes : @[
                          @"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
                          @"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="
                          ]
}}};
```

The list of all the configuration keys is available in the
[documentation](https://datatheorem.github.io/TrustKit/documentation/Classes/TrustKit.html).

### Implementing Pinning Validation

After TrustKit has been initialized, a 
[`TSKPinningValidator` instance](https://datatheorem.github.io/TrustKit/documentation/Classes/TSKPinningValidator.html) 
can be retrieved from the TrustKit singleton, and can be used to perform SSL pinning validation 
in the App's network delegates. For example in an NSURLSessionDelegate:

```
- (void)URLSession:(NSURLSession *)session 
              task:(NSURLSessionTask *)task 
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge 
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler {
{
    TSKPinningValidator *pinningValidator = [[TrustKit sharedInstance] pinningValidator];
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

By setting `kTSKSwizzleNetworkDelegates` to `YES`, TrustKit will perform method 
swizzling on the App's `NSURLSession` and `NSURLConnection` delegates in order 
to automatically perform SSL pinning validation against the server's certificate 
chain, based on the configured pinning policy. This allows deploying TrustKit
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

Create a self-signed SSL certificate authority for Charles to use instead of it's
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

#### Leveraging additional trust anchors

Tired of adding the Charles certificate to dozens of iOS Simulators and devices on
a daily basis?

TrustKit supports custom trust anchors which bypass the OS trust store. This means
that you can pin your untrusted root debugging certificate from Charles, but not
specifically add it to the OS trust store on your simulators/devices/computers.

To use custom trust anchors, add the certificate strings to a list under the
`kTSKAdditionalTrustAnchors` configuration key. Each entry should include ony one
certificate in PEM format, with no password (it's a public key, right?). Exmaple:

```
    NSDictionary *trustKitConfig =
    @{
      // The list of domains we want to pin and their configuration
      kTSKPinnedDomains: @{

              @"yahoo.com" : @{
                      // The custom trust anchors to use. If a certificate trust chain
                      // ends in a certificate in this list, the OS trust store is not
                      // consulted if compiled with DEBUG=1.
                      // WARNING: potentially unsafe. See "Debugging with TrustKit" section
                      kTSKAdditionalTrustAnchors : @[
                          @"-----BEGIN CERTIFICATE-----\
                          MIIGQDCCBCigAwIBAgIJAKDVSMZou8YPMA0GCSqGSIb3DQEBCwUAMIGsMQswCQYD\
                          VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJU3Vubnl2YWxl\
                          MRMwEQYDVQQKDApZYWhvbywgSW5jMRswGQYDVQQLDBJQdWJsaXNoZXIgUHJvZHVj\
                          dHMxGTAXBgNVBAMMEFBpbmN1c2hpb24gRGVidWcxJzAlBgkqhkiG9w0BCQEWGGFk\
                          YW1rYXBsYW5AeWFob28taW5jLmNvbTAeFw0xNzA1MzEwMjM4MzFaFw0zNzA1MjYw\
                          MjM4MzFaMIGsMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAG\
                          A1UEBwwJU3Vubnl2YWxlMRMwEQYDVQQKDApZYWhvbywgSW5jMRswGQYDVQQLDBJQ\
                          dWJsaXNoZXIgUHJvZHVjdHMxGTAXBgNVBAMMEFBpbmN1c2hpb24gRGVidWcxJzAl\
                          BgkqhkiG9w0BCQEWGGFkYW1rYXBsYW5AeWFob28taW5jLmNvbTCCAiIwDQYJKoZI\
                          hvcNAQEBBQADggIPADCCAgoCggIBAMeMDecA/otarMBHfMYEfa42KeM0lsx4LVVM\
                          DhwTJUMBbU55DevPAksPnS1gIvzVGeFQ8VzS+2rCK3Dn96vyjcevRUFJRXh4p7FW\
                          aNCCya73inKHMBDNyIJaYxZbfww8uafyzpSssJLkx6PR29c/t6VlA2tRBfxdAOWI\
                          rUggP09IG65yWhvS8If3pNJ579iuKi+RTpN3Nakgktz0Vhp+BDpKpoC9TstlGJQV\
                          CCwSxxtUIRl9Eq6rymgHOU3f7SS12siQwibRq2Bp7Lgv034MCDQHRwkSCAvFw9c1\
                          DaxvE7CvAX69RyHbyZg2/TMjRWTleNkc3TnZrMoTdUrQ8CjHVAyp+j08hiK3MuIZ\
                          8nJfaORTxZkerj9Qe921lmC5CB9d8xYoArdU1JZ8guiRi1ZqXQjE9/IwTS3jvG2k\
                          W7HpaSLIVOPMbSGXG9XjEoDh3A7lCTQhwvBrITd1fyjvJaudVqcow1t1hySZshmU\
                          K1PO4FdpUd2w1SnZuE+c60P7Rcm3vXJ0DLEN02Zlogxw8VSoKNCKWGTfqEAcVP8d\
                          ICkDBvkbB5WTxesQ4KSO2A20qTpsMq8nkyc0aQIKsiOYflw58zT47hbJ2oqHjfFU\
                          R6jL1qPAbbTX+1y9XwtV6+7bOLMwqeOCg7+rv8Op89Oiv/eOGaMZaA41akwjl4fk\
                          an8ROv5pAgMBAAGjYzBhMB0GA1UdDgQWBBQef5GmV1R6agSIcUC+lLyIoJFhHDAf\
                          BgNVHSMEGDAWgBQef5GmV1R6agSIcUC+lLyIoJFhHDAPBgNVHRMBAf8EBTADAQH/\
                          MA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAM0dWgQ478nzQLG/x\
                          BJYk5CB8tYa3DTS5c896OQwig6yX4M1aokx+k8p5Zi9YE8YUXb6v0mcwDk072rUm\
                          xy68gTLSCrcfPPLAuI6mceg4t7re9HxLDF7/q3t6rdQGIxNJyVqU3e3AStckEjm6\
                          FaFQEVSaz3yNmcVix4MI5HoQ5q5dKyfDm1MQeW7MZCqDdD5vr40YExjNw2CX+0NQ\
                          kaJgfZFTo2+D9/uks2IeCUwhX0/nro4uafurshoBmfs82ZXLDHZQJZl3T7fo60aD\
                          N2aoZLOA1peXVhX/fbSXKfuuA7zHDMhShiqNmCOxpkWR8LaAdP4vnG94cMNnADcY\
                          xlEUVQXHjzTIDM+D703q54uogr2KLt0BC0u2yI4ePaumPAKRY7bSN4oq8uDPVAwV\
                          GhzAFrSP7rLsbQi+TQP9HoOpaf7evx32FRXH57NuAqRPDMbUo8sdQhiyzDLbDSzS\
                          nwMDtog294UGIcXS1ZjLq+4qzwsp18ip3iXrKj0Mf96rUa4vKRcLujtZUUCM0zlP\
                          5UNY1rDesuHsb2ziDjEXtxh0UsdoDaKa7gXPfNqtumW96v6hh0OkNWCX/x9GUIGe\
                          WsYtZBTD1+uqy4JHP4gEGewOU93Dhw6TWqqUcP516s67r59WBSxWSQnVA22wJLYc\
                          WcqquNULAx3uOWA5ZeO0yiOGgqc=\
                          -----END CERTIFICATE-----"
                    ];

```

#### Production exploit safeguards (and how to bypass them)

By default TrustKit is hard-coded to ignore the custom trust anchors created using
the above processes in a production build. TrustKit does this by checking a define
in `TSKPinningValidator`: custom anchors are ignored unless `#if DEBUG == 1`.

The idea is that `kTSKAdditionalTrustAnchors` configuration is primarily intended for
use during development. It simplifies your workflow by not requiring the iOS Simulator
or iOS device to manually add a custom OS trust anchor (or added to Keychain for macOS).

There may be practical applications for supporting untrusted trust anchors in production.
For example:
* if your team is skilled in running secure CAs, this would allow very easy
debugging.
* Supporting select instituational proxies would be possible with additional trust anchors.

##### Bypassing Custom Trust Anchor Safeguards In Production

- Add DEBUG=1 to "Preprocessor Macros" in the Xcode target build settings for your
distribution configuration (named "Release" by default). This will probably cause
issues in your app.
- Subclass `TSKPinningValidator` and override `+allowsAdditionalTrustAnchors` to return
`true`.

