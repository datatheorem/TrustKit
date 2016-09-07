TrustKit is an open source framework that makes it easy to deploy SSL public key
pinning in any iOS, macOS, tvOS or watchOS App.

This is the API documentation for TrustKit. For an overview of the framework and
a more general guide to using it, see the project's page at
https://datatheorem.github.io/TrustKit .

TrustKit requires iOS 7.0, macOS 10.9, tvOS 10.0 or watchOS 3.0 as the minimum
deployment target.

Two classes are available enabling SSL pinning in an App:

* TrustKit, for programmatically configuring the global SSL pinning policy within an 
App.
* TSKPinningValidator, for manually validating a certificate chain against the App's
configured pinning policy.
