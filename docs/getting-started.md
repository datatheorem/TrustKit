Getting Started
===============

Adding TrustKit to an App can be achieved through the following steps:

1. Generating SSL pins for the App's server endpoints and choosing a pinning
policy.
2. Adding TrustKit as a dependency to the App's Xcode project.
3. Initializing TrustKit with the pinning policy.


Warning
-------

Public key pinning can be dangerous and requires more than just code-level
changes in your App. If you make a mistake, you might cause your App to pin a
set of keys that validates today but which stops validating a week or a year
from now, if something changes. In that case, your App will no longer be able to
connect to its servers and will most likely stop working, until it gets updated
with a new set of pins.

Unless you are confident that you understand the Web PKI that you can manage
the App servers' cryptographic identity very well, you should not use key
pinning.


Generating SSL Pins
-------------------

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

To generate such values, three bash scripts are available. The first two scripts
can be used to generate the pin configuration from a PEM or DER certificate:

    $ ./get_pin_from_pem_certificate.sh ca.pem
    $ ./get_pin_from_der_certificate.sh ca.der

The second script can be used to generate the pin configuration for the highest
certificate within the certificate chain returned by a given server:

    $ ./get_pin_from_server.sh www.google.com


Deploying TrustKit
------------------

Enabling TrustKit within an App requires generating a pinning policy and then
initializing TrustKit with this policy. There are two different ways to supply
a pinning policy to TrustKit:

* Programmatically, using TrustKit's `initializeWithConfig:` method.
* By storing the pinning policy in the App's _Info.plist_; this approach allows 
deploying TrustKit without having to modify the App's source code.

After initialization, TrustKit will intercept the App's outgoing SSL
connections, in order to perform additional validation against the server's
certificate chain based on the configured SSL pinning policy.


### Choosing a Pinning Policy

A pinning policy is a dictionary of domain names and pinning configuration keys.
At a minimum, the configuration should specify a list of SSL pins and the
corresponding certificates' public key algorithms. For example:

    NSDictionary *trustKitConfig;
    trustKitConfig = @{
                       @"www.datatheorem.com" : @{
                               kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                               kTSKPublicKeyHashes : @[
                                       @"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
                                       @"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="
                                       ]
                               },
                       @"yahoo.com" : @{
                               kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                               kTSKPublicKeyHashes : @[
                                       @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                       @"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=",
                                       ]
                               }
                       };

To avoid locking out too many users from your App when deploying SSL pinning
for the first time, a more elaborate policy can be enabled using the following
configuration keys:

* Setting `kTSKEnforcePinning` to `NO`, so that SSL connections will succeed
regardless of pin validation.
* Adding a report URL using the `kTSKReportUris` setting to receive pin
validation failure reports.

This will allow the App to work regardless of pin validation failures, but the
reports will give you an idea of how many users would be blocked, if pin
validation was to be enforced.

The list of all the configuration keys is available in the
[documentation](https://datatheorem.github.io/TrustKit/documentation/Classes/TrustKit.html).


### Adding TrustKit as a Dependency

For Apps targeting iOS 7, TrustKit must be statically linked.

1. Drag and drop the TrustKit Xcode project file in your project:

    ![](https://datatheorem.github.io/TrustKit/images/linking1.png)

2. Within the "General" tab for your App's target, add _libTrustKit_Static.a_ to
the "Linked Framework and Binaries" section:

    ![](https://datatheorem.github.io/TrustKit/images/linking2_static.png)

3. Within the "Build Settings", add TrustKit's folder to the "User Header Search
Paths" setting and set "Always Search Header Paths" to "Yes":

    ![](https://datatheorem.github.io/TrustKit/images/linking3_static.png)

4. Lastly, initialize TrustKit with your pinning policy. 


### Initializing TrustKit With a Pinning Policy

There are two ways to supply a pinning policy to TrustKit:

* By adding configuration keys to the App's _Info.plist_ file under a 
`TSKConfiguration` dictionary key:

  ![](https://datatheorem.github.io/TrustKit/images/linking3_dynamic.png)

* Programmatically by calling the `initializeWithConfiguration:` method with your 
pinning policy:

        #import "TrustKit.h"

        [...]

        NSDictionary *trustKitConfig =
        @{
          @"www.datatheorem.com" : @{
                  kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                  kTSKPublicKeyHashes : @[@"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
                                          @"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="
                                          ]}};

        [TrustKit initializeWithConfiguration:trustKitConfig];


### CocoaPods

TrustKit will be made available through CocoaPods when it is open-sourced
at Black Hat 2015 in August. Until then, TrustKit can still be added as a local
pod by adding the following dependency to your project's Podfile:

    pod 'TrustKit', :path => '/path/to/TrustKit'


### Dynamic Linking

For Apps targeting iOS 8+ or OS X, TrustKit can be dynamically linked.

1. Drag and drop the TrustKit Xcode project file in your project:

    ![](https://datatheorem.github.io/TrustKit/images/linking1.png)

2. Within the "General" tab for your App's target, add TrustKit to the
"Embedded Binaries" section:

    ![](https://datatheorem.github.io/TrustKit/images/linking2_dynamic.png)

3. Lastly, initialize TrustKit with your pinning policy.


Manual Pin Validation
---------------------

In a few specific scenarios, TrustKit cannot intercept outgoing SSL connections
and automatically validate the server's identity against the pinning policy.
This includes for example connections initiated by external processes (such as
the `NSURLSession`'s background transfer service) or through third-party SSL
libraries (such as OpenSSL).

For these connections, the pin validation must be
triggered manually; see the documentation for the [TSKPinningValidator
class](https://datatheorem.github.io/TrustKit/documentation/Classes/TSKPinningValidator.html)
for more details.

