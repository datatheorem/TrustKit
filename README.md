TrustKit
========



Deploying TrustKit Through Dynamic Linking
------------------------------------------

For Apps targeting iOS 8+, TrustKit can be dynamically linked, which allows enabling public key pinning without having to modify the App's source code. To embed TrustKit in your App:

* Drag and drop the TrustKit.xcodeproj file into your App's workspace in Xcode. Make sure TrustKit isn't already opened in Xcode:

![](http://datatheorem.github.io/TrustKit/images/dynamic1.png)

* In the App's "General" settings code, add TrustKit.framework in the list of "Embedded Binaries":

![](http://datatheorem.github.io/TrustKit/images/dynamic2.png)

* Lastly, add the public key hashes TrustKit will use to check certificate chains. In the App's Info.plist file ("Info" tab in Xcode):
    * Add a new Dictionnary key called TSKConfiguration.
    * Within this dictionnary add a Dictionnary value and use the server's domain (such as www.google.com) as the entry's key.
    * Within dictionnary you can add a few specific keys in order to configure how TrustKit handles pinning with this domain:
        * `TSKPublicKeyHashes`: Each element of this Array should be the SHA 256 of a subject public key info that needs to be in the server's certificate chain.
        * `TSKPublicKeyAlgorithms`: The algorithms TrustKit needs to support when generating public key hashes. Should be an array containing one or multiple entries from TSKAlgorithmRsa2048, TSKAlgorithmRsa4096, TSKAlgorithmEcDsaSecp256r1. Supporting multiple algorithms has a performance impact.
        * `TSKEnforcePinning` (optional): If set to NO, a pinning failure will not cause the connection to fail; default value is YES.
        * `TSKReportUris` (optional): No effet at the moment.
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
              kTSKPublicKeyHashes : @[@"2741caeb7dc87a45083200b10037145d697723ec2bd5721b1e4af4dfcc48c919",
                                      @"1d75d0831b9e0885394d32c7a1bfdb3dbc1c28e2b0e8391fb135981dbc5ba936"
                                      ]}};

    [TrustKit initializeWithConfiguration:trustKitConfig];



Cordova
-------

TBD.
