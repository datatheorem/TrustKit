TrustKit
========



Deploying TrustKit Through Dynamic Linking
------------------------------------------

For Apps targeting iOS 8+, TrustKit can be dynamically linked, which allows enabling public key pinning without having to modify the App's source code. To embed TrustKit in your App:

1. Drag and drop the TrustKit.xcodeproj file into your App's workspace in Xcode. Make sure TrustKit isn't already opened in Xcode:

![](http://datatheorem.github.io/TrustKit/images/dynamic1.png)

2. In the App's "General" settings code, add TrustKit.framework in the list of "Embedded Binaries":

![](http://datatheorem.github.io/TrustKit/images/dynamic2.png)

3. Lastly, add the public key hashes TrustKit will use to check certificate chains. In the App's Info.plist file ("Info" tab in Xcode):
    * Add a new Dictionnary key called TSKPublicKeyPins.
    * Within this dictionnary add an Array key and use the server's domain (such as www.google.com) as the key's name.
    * Each element of this Array should be the SHA 256 of a subject public key info that needs to be in the server's certificate chain.

Your App's Info.plist file should look like this: 

![](http://datatheorem.github.io/TrustKit/images/dynamic3.png)

Then, all SSL connections relying on Appple's SecureTransport (NSURLSession, NSURLConnection, UIWebView, etc.) will be checking the server's certificate chain using the public key pins specified in the Info.plist.



Deploying TrustKit Through Static Linking
-----------------------------------------

For Apps targeting iOS 7, TrustKit should be statically linked.
TBD.


Cordova
-------

TBD.
