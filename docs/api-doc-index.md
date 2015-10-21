TrustKit is an open source framework that makes it easy to deploy SSL public key
pinning in any iOS or OS X App.

This is the API documentation for TrustKit. For an overview of the framework and
a more general guide to using it, see the project's page at
https://datatheorem.github.io/TrustKit .

TrustKit requires iOS 7+ or OS X 10.9+ as the minimum deployment target and
provides two classes:

* TrustKit, for programmatically configuring the global SSL pinning policy within an App.
* TSKPinningValidator, for manually validating a certificate chain against the
configured pinning policy.
