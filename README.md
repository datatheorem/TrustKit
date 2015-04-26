TrustKit
========

TrustKit is an iOS / OS X framework for easily and efficiently deploying SSL pinning in any App:

* TrustKit will pin any connection performed using Apple Frameworks (`NSURLConnection`, `NSURLSession`, `NSStream`, etc.) even including connections performed within `UIWebViews`.
* For Apps targeting iOS 8+, TrustKit can be deployed without having to modify the App's source code.
* TrustKit follows the HTTP Public Key Pinning specification as closely as possible and provides HPKP functionality, such as pinning all subdomains of a given domain,  as well as reporting pin violations to a server.


Generating SSL Pins
-------------------

Before implementing SSL pinning within your App, you first need to figure out the list of server domains and public keys you would like to pin.

In the context of TrustKit, an SSL pin is the base64-encoded SHA-256 of a certificate's public key info; this is the same as what is described in the HTTP Public Key Pinning specification (https://developer.mozilla.org/en-US/docs/Web/Security/Public_Key_Pinning).

To generate such values, two bash scripts are available. The first script can be used to generate the pin from a PEM certificate:

    $ ./get_pin_from_pem_certificate.sh ca.pem

The second script can be used to generate the pin of the highest certificate within the certificate chain returned by a given server:

    $ ./get_pin_from_server.sh www.google.com


Deploying TrustKit Through Static Linking
-----------------------------------------

For Apps targeting iOS 7+, TrustKit should be statically linked; this can be achieved by dragging and dropping the TrustKit project file into your App's Xcode project. Then, to initialize the framework, build a dictionary containing the proper configuration keys for TrustKit.

Such keys include:

* `kTSKPublicKeyHashes`: Each element of this array should be the base64-encoded SHA 256 of a subject public key info that needs to be in the server's certificate chain.
* `kTSKPublicKeyAlgorithms`: The algorithms TrustKit needs to support when generating public key hashes. Should be an array containing one or multiple entries from `kTSKAlgorithmRsa2048`, `TSKAlgorithmRsa4096`, `TSKAlgorithmEcDsaSecp256r1`. Supporting multiple algorithms has a performance impact.
* `kTSKIncludeSubdomains` (optional): Pin all the subdomains of the specific domain.
* `kTSKReportUris` (optional): No effect at the moment.
* `kTSKEnforcePinning` (optional): If set to NO, a pinning failure will not cause the connection to fail; default value is YES. This is meant to be used with `kTSKReportUris` in order to report pin violations while still allowing connections to go through.

Then, call the `initializeWithConfiguration:` method with the configuration dictionary:

    NSDictionary *trustKitConfig =
    @{
      @"www.datatheorem.com" : @{
              kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
              kTSKPublicKeyHashes : @[@"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
                                      @"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="
                                      ]}};

    [TrustKit initializeWithConfiguration:trustKitConfig];



Deploying TrustKit Through Dynamic Linking
------------------------------------------

For Apps targeting iOS 8+, TrustKit can be dynamically linked, which allows enabling public key pinning without having to modify the App's source code. To embed TrustKit in your App:

* Drag and drop the TrustKit.xcodeproj file into your App's workspace in Xcode. Make sure TrustKit isn't already opened in Xcode:

![](http://datatheorem.github.io/TrustKit/images/dynamic1.png)

* In the App's "General" settings code, add TrustKit.framework in the list of "Embedded Binaries":

![](http://datatheorem.github.io/TrustKit/images/dynamic2.png)

* Lastly, add the public key hashes TrustKit will use to check certificate chains. In the App's Info.plist file ("Info" tab in Xcode):
    * Add a new Dictionary key called `TSKConfiguration`.
    * Within this dictionary add a Dictionary value and use the server's domain (such as www.google.com) as the entry's key.
    * Within dictionary you can add a few specific keys in order to configure how TrustKit handles pinning with this domain:
        * `TSKPublicKeyHashes`: Each element of this Array should be the base64-encoded SHA 256 of a subject public key info that needs to be in the server's certificate chain.
        * `TSKPublicKeyAlgorithms`: The algorithms TrustKit needs to support when generating public key hashes. Should be an array containing one or multiple entries from `TSKAlgorithmRsa2048`, `TSKAlgorithmRsa4096`, `TSKAlgorithmEcDsaSecp256r1`. Supporting multiple algorithms has a performance impact.
        * `TSKIncludeSubdomains` (optional): Pin all the subdomains of the specific domain.
        * `TSKReportUris` (optional): No effect at the moment.
        * `TSKEnforcePinning` (optional): If set to NO, a pinning failure will not cause the connection to fail; default value is YES. This is meant to be used with `TSKReportUris` in order to report pin violations while still allowing connections to go through.

Your App's Info.plist file should look like this:

![](http://datatheorem.github.io/TrustKit/images/dynamic3.png)

Then, all SSL connections relying on Apple's SecureTransport (NSURLSession, NSURLConnection, UIWebView, etc.) will be checking the server's certificate chain using the public key pins specified in the Info.plist.




Cordova
-------

TBD.
