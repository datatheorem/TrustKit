# TrustKit Documentation

TrustKit is an open source framework that makes it easy to deploy SSL public key pinning in any iOS, macOS, tvOS or watchOS App.

This is the API documentation for TrustKit. A "Getting Started" guide is available at https://github.com/datatheorem/TrustKit/blob/master/docs/getting-started.md.

TrustKit exposes two core classes for enabling SSL pinning in an App:

* `TrustKit` for configuring an SSL pinning policy and initializing the framework.
* `TSKPinningValidator`, for validating a server's certificate chain against an SSL pinning policy.
