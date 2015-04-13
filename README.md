TrustKit
========


Generating SSL Pins
-------------------

In the context of TrustKit, an SSL pin is the base64-encoded SHA-256 of a certificate's public key info; this is the same as what is described in the HTTP Public Key Pinning specification (https://developer.mozilla.org/en-US/docs/Web/Security/Public_Key_Pinning).

To generate such values, two bash scripts are available. The first script can be used to generate the pin from a PEM certificate:

    $ ./get_pin_from_pem_certificate.sh ca.pem
    -----------
    Certificate
    -----------
    subject= /C=US/O=thawte, Inc./OU=Certification Services Division/OU=(c) 2006 thawte, Inc. - For authorized use only/CN=thawte Primary Root CA
    issuer= /C=ZA/ST=Western Cape/L=Cape Town/O=Thawte Consulting cc/OU=Certification Services Division/CN=Thawte Premium Server CA/emailAddress=premium-server@thawte.com
    SHA1 Fingerprint=1F:A4:90:D1:D4:95:79:42:CD:23:54:5F:6E:82:3D:00:00:79:6E:A2
    ---------------------
    Subject Key Info Pin
    ---------------------
    HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=


The second script can be used to generate the pin of the highest certificate within the certificate chain returned by a given server:

    $ ./get_pin_from_server.sh www.google.com
    ----------------------------
    Top Intermediate Certificate
    ----------------------------
    subject= /C=US/O=GeoTrust Inc./CN=GeoTrust Global CA
    issuer= /C=US/O=Equifax/OU=Equifax Secure Certificate Authority
    SHA1 Fingerprint=73:59:75:5C:6D:F9:A0:AB:C3:06:0B:CE:36:95:64:C8:EC:45:42:A3

    ---------------------
    Subject Key Info Pin
    ---------------------
    h6801m+z8v3zbgkRHpq6L29Esgfzhj89C1SyUCOQmqU=


Deploying TrustKit Through Dynamic Linking
------------------------------------------

For Apps targeting iOS 8+, TrustKit can be dynamically linked, which allows enabling public key pinning without having to modify the App's source code. To embed TrustKit in your App:

* Drag and drop the TrustKit.xcodeproj file into your App's workspace in Xcode. Make sure TrustKit isn't already opened in Xcode:

![](http://datatheorem.github.io/TrustKit/images/dynamic1.png)

* In the App's "General" settings code, add TrustKit.framework in the list of "Embedded Binaries":

![](http://datatheorem.github.io/TrustKit/images/dynamic2.png)

* Lastly, add the public key hashes TrustKit will use to check certificate chains. In the App's Info.plist file ("Info" tab in Xcode):
    * Add a new Dictionary key called `TSKConfiguration`.
    * Within this dictionary add a Dictionnary value and use the server's domain (such as www.google.com) as the entry's key.
    * Within dictionary you can add a few specific keys in order to configure how TrustKit handles pinning with this domain:
        * `TSKPublicKeyHashes`: Each element of this Array should be the base64-encoded SHA 256 of a subject public key info that needs to be in the server's certificate chain.
        * `TSKPublicKeyAlgorithms`: The algorithms TrustKit needs to support when generating public key hashes. Should be an array containing one or multiple entries from `TSKAlgorithmRsa2048`, `TSKAlgorithmRsa4096`, `TSKAlgorithmEcDsaSecp256r1`. Supporting multiple algorithms has a performance impact.
        * `TSKEnforcePinning` (optional): If set to NO, a pinning failure will not cause the connection to fail; default value is YES.
        * `TSKReportUris` (optional): No effect at the moment.
        * `TSKIncludeSubdomains` (optional): No effect at the moment.

Your App's Info.plist file should look like this:

![](http://datatheorem.github.io/TrustKit/images/dynamic3.png)

Then, all SSL connections relying on Apple's SecureTransport (NSURLSession, NSURLConnection, UIWebView, etc.) will be checking the server's certificate chain using the public key pins specified in the Info.plist.



Deploying TrustKit Through Static Linking
-----------------------------------------

For Apps targeting iOS 7, TrustKit should be statically linked. To initialize the framework, build a dictionnary containing the proper configuration keys for TrustKit, as described in the previous section. Then, call the `initializeWithConfiguration:` method:

    NSDictionary *trustKitConfig =
    @{
      @"www.datatheorem.com" : @{
              kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
              kTSKPublicKeyHashes : @[@"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
                                      @"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="
                                      ]}};

    [TrustKit initializeWithConfiguration:trustKitConfig];



Cordova
-------

TBD.
