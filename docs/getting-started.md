Getting Started
===============

Adding TrustKit to an App can be achieved through the following steps:

1. Generating SSL pins for the App's server endpoints and choosing a pinning policy.
2. Adding TrustKit as a dependency to the App's Xcode project.
3. Initializing TrustKit with the pinning policy.


Generating SSL Pins
-------------------

Before deploying SSL pinning within your App, you first need to investigate and
choose which domains and public keys need to be pinned. This is *very* important
as enabling the wrong pinning policy may prevent your App from being able to
connect to its servers, if the servers' keys were compromised.

The following blog post provides some information on how to decide and what the
trade-offs are:
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
initializing TrustKit with this policy. This can be done using one of the
following mechanisms:

* By statically linking TrustKit and supplying the pinning policy
programmatically, using TrustKit's `initializeWithConfig:` method.
* By dynamically linking TrustKit and storing the pinning policy in the App's
Info.plist. This approach allows deploying TrustKit without modifying the App's
source code but is only available on iOS8+ and OS X.

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

The list of all configuration keys is available in the
[documentation](https://datatheorem.github.io/TrustKit/documentation/Classes/TrustKit.html).


### Static Linking

For Apps targeting iOS 7, TrustKit must be statically linked.

1. Drag and drop the TrustKit Xcode project file in your project:

    ![](https://datatheorem.github.io/TrustKit/images/linking1.png)

2. Within the "General" tab for your App's target, add _libTrustKit_Static.a_ to
the "Linked Framework and Binaries" section:

    ![](https://datatheorem.github.io/TrustKit/images/linking2_static.png)

3. Within the "Build Settings", add TrustKit's folder to the "User Header Search
Paths" setting and set "Always Search Header Paths" to "Yes":

    ![](https://datatheorem.github.io/TrustKit/images/linking3_static.png)

3. Lastly, call the `initializeWithConfiguration:` method with your pinning
policy:

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

Support for CocoaPods will be added when TrustKit is open-sourced at Black Hat
USA 2015.


### Dynamic Linking

For Apps targeting iOS 8+ or OS X, TrustKit can be dynamically linked, which
allows deploying SSL pinning without having to modify the App's source code.

1. Drag and drop the TrustKit Xcode project file in your project:

    ![](https://datatheorem.github.io/TrustKit/images/linking1.png)

2. Within the "General" tab for your App's target, add TrustKit to the
"Embedded Binaries" section:

    ![](https://datatheorem.github.io/TrustKit/images/linking2_dynamic.png)

3. Lastly, specify your App's pinning policy by adding configuration keys to
the App's _Info.plist_ file under a `TSKConfiguration` dictionary key:

  ![](https://datatheorem.github.io/TrustKit/images/linking3_dynamic.png)


Manual Pin Validation
---------------------

In a few specific scenarios, TrustKit cannot intercept outgoing SSL connections
and automatically validate the server's identity against the pinning policy.
This includes for example connections initiated by external processes (such as
the `NSURLSession`'s background transfer service) or through third-party SSL
libraries (such as OpenSSL).

For these connections, the pin validation must be
triggered manually; see the documentation for the [TSKPinVerifier
class](https://datatheorem.github.io/TrustKit/documentation/Classes/TSKPinVerifier.html)
for more details.
