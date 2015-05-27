//
//  TSKReporterTests.m
//  TrustKit
//
//  Created by Angela Chow on 4/29/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "TSKSimpleReporter.h"
#import "TSKSimpleBackgroundReporter.h"

@interface TSKReporterTests : XCTestCase

@end

@implementation TSKReporterTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testSimpleReporter {
    
    //just try a simple valid case to see if we can post this to the server
    TSKSimpleReporter *reporter = [[TSKSimpleReporter alloc] initWithAppBundleId:@"com.example.ABC" appVersion:@"1.0"];
    
    [reporter pinValidationFailed:@"example.com"
                   serverHostname:@"mail.example.com"
                       serverPort:[NSNumber numberWithInt:443]
                     reportingURL:@"http://localhost:3000"
                includeSubdomains:YES
                 certificateChain:[NSArray arrayWithObjects:
                                   @"-----BEGIN CERTIFICATE-----"
                                   "MIIIdzCCB1+gAwIBAgIQTusxCWM5To6gTnCcqR3NpjANBgkqhkiG9w0BAQUFADCB"
                                   "tTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL"
                                   "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2Ug"
                                   "YXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykxMDEvMC0GA1UEAxMm"
                                   "VmVyaVNpZ24gQ2xhc3MgMyBTZWN1cmUgU2VydmVyIENBIC0gRzMwHhcNMTQwOTI0"
                                   "MDAwMDAwWhcNMTUwOTI1MjM1OTU5WjCBhDELMAkGA1UEBhMCVVMxEzARBgNVBAgT"
                                   "CkNhbGlmb3JuaWExEjAQBgNVBAcUCVN1bm55dmFsZTETMBEGA1UEChQKWWFob28g"
                                   "SW5jLjEfMB0GA1UECxQWSW5mb3JtYXRpb24gVGVjaG5vbG9neTEWMBQGA1UEAxQN"
                                   "d3d3LnlhaG9vLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMuz"
                                   "z21vayNu67CPCq2qmLoa2SYeiFIycWPJecSCLsgitM0vBJ+VLYOpUiIHJABC7hgX"
                                   "B0YpcxiXxbhpBngicCLQE0oRhitTmklpxaJ3tCs78XX5pIONPo5l+xegrBR9h+3U"
                                   "plyZt8j03qBqE9kzQSdqcVTPwknUxoseLDvzHbzauxHB/gZinDsrv41Dy3t7UU+f"
                                   "9B/SmW+hJJtkZV8s0JWtmLZqAiQ/x/OtP0exV7/doMLt3aTho3QkG3Nfp46LCRC8"
                                   "6qYmqjxXc+Rq1lNvnKr4+Ju/IvZy1Z/+4OKjOI+30q2RIoI2weaug2RuBxaA91nE"
                                   "TfT0XsjeTWvmtTDqjw8CAwEAAaOCBLAwggSsMIIDYAYDVR0RBIIDVzCCA1OCDXd3"
                                   "dy55YWhvby5jb22CCXlhaG9vLmNvbYIOaHNyZC55YWhvby5jb22CDHVzLnlhaG9v"
                                   "LmNvbYIMZnIueWFob28uY29tggx1ay55YWhvby5jb22CDHphLnlhaG9vLmNvbYIM"
                                   "aWUueWFob28uY29tggxpdC55YWhvby5jb22CDGVzLnlhaG9vLmNvbYIMZGUueWFo"
                                   "b28uY29tggxjYS55YWhvby5jb22CDHFjLnlhaG9vLmNvbYIMYnIueWFob28uY29t"
                                   "ggxyby55YWhvby5jb22CDHNlLnlhaG9vLmNvbYIMYmUueWFob28uY29tgg9mci1i"
                                   "ZS55YWhvby5jb22CDGFyLnlhaG9vLmNvbYIMbXgueWFob28uY29tggxjbC55YWhv"
                                   "by5jb22CDGNvLnlhaG9vLmNvbYIMdmUueWFob28uY29tghFlc3Bhbm9sLnlhaG9v"
                                   "LmNvbYIMcGUueWFob28uY29tggxpbi55YWhvby5jb22CDHNnLnlhaG9vLmNvbYIM"
                                   "aWQueWFob28uY29tghJtYWxheXNpYS55YWhvby5jb22CDHBoLnlhaG9vLmNvbYIM"
                                   "dm4ueWFob28uY29tghFtYWt0b29iLnlhaG9vLmNvbYIUZW4tbWFrdG9vYi55YWhv"
                                   "by5jb22CD2NhLm15LnlhaG9vLmNvbYIMZ3IueWFob28uY29tgg1hdHQueWFob28u"
                                   "Y29tggxhdS55YWhvby5jb22CDG56LnlhaG9vLmNvbYIMdHcueWFob28uY29tggxo"
                                   "ay55YWhvby5jb22CDWJyYi55YWhvby5jb22CDG15LnlhaG9vLmNvbYIQYWRkLm15"
                                   "LnlhaG9vLmNvbYIVZXNwYW5vbC5hdHQueWFob28uY29tghJmcm9udGllci55YWhv"
                                   "by5jb22CEXZlcml6b24ueWFob28uY29tghNjYS5yb2dlcnMueWFob28uY29tghZm"
                                   "ci1jYS5yb2dlcnMueWFob28uY29tghR0YXRhZG9jb21vLnlhaG9vLmNvbYIQdGlr"
                                   "b25hLnlhaG9vLmNvbYIXaWRlYW5ldHNldHRlci55YWhvby5jb22CEm10c2luZGlh"
                                   "LnlhaG9vLmNvbYITc21hcnRmcmVuLnlhaG9vLmNvbTAJBgNVHRMEAjAAMA4GA1Ud"
                                   "DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwZQYDVR0g"
                                   "BF4wXDBaBgpghkgBhvhFAQc2MEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1j"
                                   "Yi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBh"
                                   "MB8GA1UdIwQYMBaAFA1EXBZTRMGCfh0gqyX0AWPYvnmlMCsGA1UdHwQkMCIwIKAe"
                                   "oByGGmh0dHA6Ly9zZC5zeW1jYi5jb20vc2QuY3JsMFcGCCsGAQUFBwEBBEswSTAf"
                                   "BggrBgEFBQcwAYYTaHR0cDovL3NkLnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0"
                                   "cDovL3NkLnN5bWNiLmNvbS9zZC5jcnQwDQYJKoZIhvcNAQEFBQADggEBAI2remqe"
                                   "3MpkWxARQ9ZFBhdrMudD7ZZofWGYxHaXBnmrHO70rGeXNIhjkGJMEuScseuqOBHp"
                                   "itIU+QfNbe60Bc7NZdByaTkA+js6OwbeO36CwWkxvOQJfPiz/57UokAXQmjAv5EL"
                                   "rMbu3JEzheDkQ/LYs12kM/fA6Ekmzz2mP8BAeA1iDaoQN74/INu+6u2ZHc22dSMD"
                                   "E8hNhsXFvf7VrTxaLVzJcmq1994cQaj4pyCHW2cAByxITiKzKBmIoOmlEcX3KRgp"
                                   "GFGplashi56WxTAVb65VMQccLDr5dddmi7L9R/7z6p7izeKS0CODzq8EthRRXmNl"
                                   "2tT3KIKcgjEVvCk="
                                   "-----END CERTIFICATE-----",
                                   @"-----BEGIN CERTIFICATE-----"
                                   "MIIF7DCCBNSgAwIBAgIQbsx6pacDIAm4zrz06VLUkTANBgkqhkiG9w0BAQUFADCB"
                                   "yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL"
                                   "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp"
                                   "U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW"
                                   "ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0"
                                   "aG9yaXR5IC0gRzUwHhcNMTAwMjA4MDAwMDAwWhcNMjAwMjA3MjM1OTU5WjCBtTEL"
                                   "MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW"
                                   "ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2UgYXQg"
                                   "aHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykxMDEvMC0GA1UEAxMmVmVy"
                                   "aVNpZ24gQ2xhc3MgMyBTZWN1cmUgU2VydmVyIENBIC0gRzMwggEiMA0GCSqGSIb3"
                                   "DQEBAQUAA4IBDwAwggEKAoIBAQCxh4QfwgxF9byrJZenraI+nLr2wTm4i8rCrFbG"
                                   "5btljkRPTc5v7QlK1K9OEJxoiy6Ve4mbE8riNDTB81vzSXtig0iBdNGIeGwCU/m8"
                                   "f0MmV1gzgzszChew0E6RJK2GfWQS3HRKNKEdCuqWHQsV/KNLO85jiND4LQyUhhDK"
                                   "tpo9yus3nABINYYpUHjoRWPNGUFP9ZXse5jUxHGzUL4os4+guVOc9cosI6n9FAbo"
                                   "GLSa6Dxugf3kzTU2s1HTaewSulZub5tXxYsU5w7HnO1KVGrJTcW/EbGuHGeBy0RV"
                                   "M5l/JJs/U0V/hhrzPPptf4H1uErT9YU3HLWm0AnkGHs4TvoPAgMBAAGjggHfMIIB"
                                   "2zA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLnZlcmlz"
                                   "aWduLmNvbTASBgNVHRMBAf8ECDAGAQH/AgEAMHAGA1UdIARpMGcwZQYLYIZIAYb4"
                                   "RQEHFwMwVjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL2Nw"
                                   "czAqBggrBgEFBQcCAjAeGhxodHRwczovL3d3dy52ZXJpc2lnbi5jb20vcnBhMDQG"
                                   "A1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jcmwudmVyaXNpZ24uY29tL3BjYTMtZzUu"
                                   "Y3JsMA4GA1UdDwEB/wQEAwIBBjBtBggrBgEFBQcBDARhMF+hXaBbMFkwVzBVFglp"
                                   "bWFnZS9naWYwITAfMAcGBSsOAwIaBBSP5dMahqyNjmvDz4Bq1EgYLHsZLjAlFiNo"
                                   "dHRwOi8vbG9nby52ZXJpc2lnbi5jb20vdnNsb2dvLmdpZjAoBgNVHREEITAfpB0w"
                                   "GzEZMBcGA1UEAxMQVmVyaVNpZ25NUEtJLTItNjAdBgNVHQ4EFgQUDURcFlNEwYJ+"
                                   "HSCrJfQBY9i+eaUwHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwDQYJ"
                                   "KoZIhvcNAQEFBQADggEBAAyDJO/dwwzZWJz+NrbrioBL0aP3nfPMU++CnqOh5pfB"
                                   "WJ11bOAdG0z60cEtBcDqbrIicFXZIDNAMwfCZYP6j0M3m+oOmmxw7vacgDvZN/R6"
                                   "bezQGH1JSsqZxxkoor7YdyT3hSaGbYcFQEFn0Sc67dxIHSLNCwuLvPSxe/20majp"
                                   "dirhGi2HbnTTiN0eIsbfFrYrghQKlFzyUOyvzv9iNw2tZdMGQVPtAhTItVgooazg"
                                   "W+yzf5VK+wPIrSbb5mZ4EkrZn0L74ZjmQoObj49nJOhhGbXdzbULJgWOw27EyHW4"
                                   "Rs/iGAZeqa6ogZpHFt4MKGwlJ7net4RYxh84HqTEy2Y="
                                   "-----END CERTIFICATE-----",
                                   @"-----BEGIN CERTIFICATE-----"
                                   "MIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB"
                                   "yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL"
                                   "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp"
                                   "U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW"
                                   "ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0"
                                   "aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL"
                                   "MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW"
                                   "ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln"
                                   "biwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp"
                                   "U2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y"
                                   "aXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1"
                                   "nmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex"
                                   "t0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz"
                                   "SdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG"
                                   "BO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+"
                                   "rCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/"
                                   "NIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E"
                                   "BAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH"
                                   "BgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy"
                                   "aXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv"
                                   "MzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE"
                                   "p6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y"
                                   "5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK"
                                   "WE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ"
                                   "4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N"
                                   "hnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq"
                                   "-----END CERTIFICATE-----",
                                   nil]
                     expectedPins:[NSArray arrayWithObjects:
                                   @"pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"",
                                   @"pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\"",
                                   nil]];
    
    [NSThread sleepForTimeInterval:5.0];
    XCTAssert(YES, @"Pass");
}

- (void)testSimpleReporterWithLongCertChain {
    
    //try a case with a 5 levels deep cert chain to see if it still works
    TSKSimpleReporter *reporter = [[TSKSimpleReporter alloc] initWithAppBundleId:@"com.example.ABC" appVersion:@"1.0"];
    
    [reporter pinValidationFailed:@"example.com"
                   serverHostname:@"mail.example.com"
                       serverPort:[NSNumber numberWithInt:443]
                     reportingURL:@"http://localhost:3000"
                includeSubdomains:YES
                 certificateChain:[NSArray arrayWithObjects:
                                   @"-----BEGIN CERTIFICATE-----"
                                   "MIIIdzCCB1+gAwIBAgIQTusxCWM5To6gTnCcqR3NpjANBgkqhkiG9w0BAQUFADCB"
                                   "tTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL"
                                   "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2Ug"
                                   "YXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykxMDEvMC0GA1UEAxMm"
                                   "VmVyaVNpZ24gQ2xhc3MgMyBTZWN1cmUgU2VydmVyIENBIC0gRzMwHhcNMTQwOTI0"
                                   "MDAwMDAwWhcNMTUwOTI1MjM1OTU5WjCBhDELMAkGA1UEBhMCVVMxEzARBgNVBAgT"
                                   "CkNhbGlmb3JuaWExEjAQBgNVBAcUCVN1bm55dmFsZTETMBEGA1UEChQKWWFob28g"
                                   "SW5jLjEfMB0GA1UECxQWSW5mb3JtYXRpb24gVGVjaG5vbG9neTEWMBQGA1UEAxQN"
                                   "d3d3LnlhaG9vLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMuz"
                                   "z21vayNu67CPCq2qmLoa2SYeiFIycWPJecSCLsgitM0vBJ+VLYOpUiIHJABC7hgX"
                                   "B0YpcxiXxbhpBngicCLQE0oRhitTmklpxaJ3tCs78XX5pIONPo5l+xegrBR9h+3U"
                                   "plyZt8j03qBqE9kzQSdqcVTPwknUxoseLDvzHbzauxHB/gZinDsrv41Dy3t7UU+f"
                                   "9B/SmW+hJJtkZV8s0JWtmLZqAiQ/x/OtP0exV7/doMLt3aTho3QkG3Nfp46LCRC8"
                                   "6qYmqjxXc+Rq1lNvnKr4+Ju/IvZy1Z/+4OKjOI+30q2RIoI2weaug2RuBxaA91nE"
                                   "TfT0XsjeTWvmtTDqjw8CAwEAAaOCBLAwggSsMIIDYAYDVR0RBIIDVzCCA1OCDXd3"
                                   "dy55YWhvby5jb22CCXlhaG9vLmNvbYIOaHNyZC55YWhvby5jb22CDHVzLnlhaG9v"
                                   "LmNvbYIMZnIueWFob28uY29tggx1ay55YWhvby5jb22CDHphLnlhaG9vLmNvbYIM"
                                   "aWUueWFob28uY29tggxpdC55YWhvby5jb22CDGVzLnlhaG9vLmNvbYIMZGUueWFo"
                                   "b28uY29tggxjYS55YWhvby5jb22CDHFjLnlhaG9vLmNvbYIMYnIueWFob28uY29t"
                                   "ggxyby55YWhvby5jb22CDHNlLnlhaG9vLmNvbYIMYmUueWFob28uY29tgg9mci1i"
                                   "ZS55YWhvby5jb22CDGFyLnlhaG9vLmNvbYIMbXgueWFob28uY29tggxjbC55YWhv"
                                   "by5jb22CDGNvLnlhaG9vLmNvbYIMdmUueWFob28uY29tghFlc3Bhbm9sLnlhaG9v"
                                   "LmNvbYIMcGUueWFob28uY29tggxpbi55YWhvby5jb22CDHNnLnlhaG9vLmNvbYIM"
                                   "aWQueWFob28uY29tghJtYWxheXNpYS55YWhvby5jb22CDHBoLnlhaG9vLmNvbYIM"
                                   "dm4ueWFob28uY29tghFtYWt0b29iLnlhaG9vLmNvbYIUZW4tbWFrdG9vYi55YWhv"
                                   "by5jb22CD2NhLm15LnlhaG9vLmNvbYIMZ3IueWFob28uY29tgg1hdHQueWFob28u"
                                   "Y29tggxhdS55YWhvby5jb22CDG56LnlhaG9vLmNvbYIMdHcueWFob28uY29tggxo"
                                   "ay55YWhvby5jb22CDWJyYi55YWhvby5jb22CDG15LnlhaG9vLmNvbYIQYWRkLm15"
                                   "LnlhaG9vLmNvbYIVZXNwYW5vbC5hdHQueWFob28uY29tghJmcm9udGllci55YWhv"
                                   "by5jb22CEXZlcml6b24ueWFob28uY29tghNjYS5yb2dlcnMueWFob28uY29tghZm"
                                   "ci1jYS5yb2dlcnMueWFob28uY29tghR0YXRhZG9jb21vLnlhaG9vLmNvbYIQdGlr"
                                   "b25hLnlhaG9vLmNvbYIXaWRlYW5ldHNldHRlci55YWhvby5jb22CEm10c2luZGlh"
                                   "LnlhaG9vLmNvbYITc21hcnRmcmVuLnlhaG9vLmNvbTAJBgNVHRMEAjAAMA4GA1Ud"
                                   "DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwZQYDVR0g"
                                   "BF4wXDBaBgpghkgBhvhFAQc2MEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1j"
                                   "Yi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBh"
                                   "MB8GA1UdIwQYMBaAFA1EXBZTRMGCfh0gqyX0AWPYvnmlMCsGA1UdHwQkMCIwIKAe"
                                   "oByGGmh0dHA6Ly9zZC5zeW1jYi5jb20vc2QuY3JsMFcGCCsGAQUFBwEBBEswSTAf"
                                   "BggrBgEFBQcwAYYTaHR0cDovL3NkLnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0"
                                   "cDovL3NkLnN5bWNiLmNvbS9zZC5jcnQwDQYJKoZIhvcNAQEFBQADggEBAI2remqe"
                                   "3MpkWxARQ9ZFBhdrMudD7ZZofWGYxHaXBnmrHO70rGeXNIhjkGJMEuScseuqOBHp"
                                   "itIU+QfNbe60Bc7NZdByaTkA+js6OwbeO36CwWkxvOQJfPiz/57UokAXQmjAv5EL"
                                   "rMbu3JEzheDkQ/LYs12kM/fA6Ekmzz2mP8BAeA1iDaoQN74/INu+6u2ZHc22dSMD"
                                   "E8hNhsXFvf7VrTxaLVzJcmq1994cQaj4pyCHW2cAByxITiKzKBmIoOmlEcX3KRgp"
                                   "GFGplashi56WxTAVb65VMQccLDr5dddmi7L9R/7z6p7izeKS0CODzq8EthRRXmNl"
                                   "2tT3KIKcgjEVvCk="
                                   "-----END CERTIFICATE-----",
                                   @"-----BEGIN CERTIFICATE-----"
                                   "MIIF7DCCBNSgAwIBAgIQbsx6pacDIAm4zrz06VLUkTANBgkqhkiG9w0BAQUFADCB"
                                   "yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL"
                                   "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp"
                                   "U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW"
                                   "ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0"
                                   "aG9yaXR5IC0gRzUwHhcNMTAwMjA4MDAwMDAwWhcNMjAwMjA3MjM1OTU5WjCBtTEL"
                                   "MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW"
                                   "ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2UgYXQg"
                                   "aHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykxMDEvMC0GA1UEAxMmVmVy"
                                   "aVNpZ24gQ2xhc3MgMyBTZWN1cmUgU2VydmVyIENBIC0gRzMwggEiMA0GCSqGSIb3"
                                   "DQEBAQUAA4IBDwAwggEKAoIBAQCxh4QfwgxF9byrJZenraI+nLr2wTm4i8rCrFbG"
                                   "5btljkRPTc5v7QlK1K9OEJxoiy6Ve4mbE8riNDTB81vzSXtig0iBdNGIeGwCU/m8"
                                   "f0MmV1gzgzszChew0E6RJK2GfWQS3HRKNKEdCuqWHQsV/KNLO85jiND4LQyUhhDK"
                                   "tpo9yus3nABINYYpUHjoRWPNGUFP9ZXse5jUxHGzUL4os4+guVOc9cosI6n9FAbo"
                                   "GLSa6Dxugf3kzTU2s1HTaewSulZub5tXxYsU5w7HnO1KVGrJTcW/EbGuHGeBy0RV"
                                   "M5l/JJs/U0V/hhrzPPptf4H1uErT9YU3HLWm0AnkGHs4TvoPAgMBAAGjggHfMIIB"
                                   "2zA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLnZlcmlz"
                                   "aWduLmNvbTASBgNVHRMBAf8ECDAGAQH/AgEAMHAGA1UdIARpMGcwZQYLYIZIAYb4"
                                   "RQEHFwMwVjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL2Nw"
                                   "czAqBggrBgEFBQcCAjAeGhxodHRwczovL3d3dy52ZXJpc2lnbi5jb20vcnBhMDQG"
                                   "A1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jcmwudmVyaXNpZ24uY29tL3BjYTMtZzUu"
                                   "Y3JsMA4GA1UdDwEB/wQEAwIBBjBtBggrBgEFBQcBDARhMF+hXaBbMFkwVzBVFglp"
                                   "bWFnZS9naWYwITAfMAcGBSsOAwIaBBSP5dMahqyNjmvDz4Bq1EgYLHsZLjAlFiNo"
                                   "dHRwOi8vbG9nby52ZXJpc2lnbi5jb20vdnNsb2dvLmdpZjAoBgNVHREEITAfpB0w"
                                   "GzEZMBcGA1UEAxMQVmVyaVNpZ25NUEtJLTItNjAdBgNVHQ4EFgQUDURcFlNEwYJ+"
                                   "HSCrJfQBY9i+eaUwHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwDQYJ"
                                   "KoZIhvcNAQEFBQADggEBAAyDJO/dwwzZWJz+NrbrioBL0aP3nfPMU++CnqOh5pfB"
                                   "WJ11bOAdG0z60cEtBcDqbrIicFXZIDNAMwfCZYP6j0M3m+oOmmxw7vacgDvZN/R6"
                                   "bezQGH1JSsqZxxkoor7YdyT3hSaGbYcFQEFn0Sc67dxIHSLNCwuLvPSxe/20majp"
                                   "dirhGi2HbnTTiN0eIsbfFrYrghQKlFzyUOyvzv9iNw2tZdMGQVPtAhTItVgooazg"
                                   "W+yzf5VK+wPIrSbb5mZ4EkrZn0L74ZjmQoObj49nJOhhGbXdzbULJgWOw27EyHW4"
                                   "Rs/iGAZeqa6ogZpHFt4MKGwlJ7net4RYxh84HqTEy2Y="
                                   "-----END CERTIFICATE-----",
                                   @"-----BEGIN CERTIFICATE-----"
                                   "MIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB"
                                   "yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL"
                                   "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp"
                                   "U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW"
                                   "ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0"
                                   "aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL"
                                   "MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW"
                                   "ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln"
                                   "biwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp"
                                   "U2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y"
                                   "aXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1"
                                   "nmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex"
                                   "t0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz"
                                   "SdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG"
                                   "BO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+"
                                   "rCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/"
                                   "NIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E"
                                   "BAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH"
                                   "BgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy"
                                   "aXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv"
                                   "MzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE"
                                   "p6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y"
                                   "5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK"
                                   "WE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ"
                                   "4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N"
                                   "hnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq"
                                   "-----END CERTIFICATE-----",
                                   @"-----BEGIN CERTIFICATE-----"
                                   "MIIIdzCCB1+gAwIBAgIQTusxCWM5To6gTnCcqR3NpjANBgkqhkiG9w0BAQUFADCB"
                                   "tTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL"
                                   "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2Ug"
                                   "YXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykxMDEvMC0GA1UEAxMm"
                                   "VmVyaVNpZ24gQ2xhc3MgMyBTZWN1cmUgU2VydmVyIENBIC0gRzMwHhcNMTQwOTI0"
                                   "MDAwMDAwWhcNMTUwOTI1MjM1OTU5WjCBhDELMAkGA1UEBhMCVVMxEzARBgNVBAgT"
                                   "CkNhbGlmb3JuaWExEjAQBgNVBAcUCVN1bm55dmFsZTETMBEGA1UEChQKWWFob28g"
                                   "SW5jLjEfMB0GA1UECxQWSW5mb3JtYXRpb24gVGVjaG5vbG9neTEWMBQGA1UEAxQN"
                                   "d3d3LnlhaG9vLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMuz"
                                   "z21vayNu67CPCq2qmLoa2SYeiFIycWPJecSCLsgitM0vBJ+VLYOpUiIHJABC7hgX"
                                   "B0YpcxiXxbhpBngicCLQE0oRhitTmklpxaJ3tCs78XX5pIONPo5l+xegrBR9h+3U"
                                   "plyZt8j03qBqE9kzQSdqcVTPwknUxoseLDvzHbzauxHB/gZinDsrv41Dy3t7UU+f"
                                   "9B/SmW+hJJtkZV8s0JWtmLZqAiQ/x/OtP0exV7/doMLt3aTho3QkG3Nfp46LCRC8"
                                   "6qYmqjxXc+Rq1lNvnKr4+Ju/IvZy1Z/+4OKjOI+30q2RIoI2weaug2RuBxaA91nE"
                                   "TfT0XsjeTWvmtTDqjw8CAwEAAaOCBLAwggSsMIIDYAYDVR0RBIIDVzCCA1OCDXd3"
                                   "dy55YWhvby5jb22CCXlhaG9vLmNvbYIOaHNyZC55YWhvby5jb22CDHVzLnlhaG9v"
                                   "LmNvbYIMZnIueWFob28uY29tggx1ay55YWhvby5jb22CDHphLnlhaG9vLmNvbYIM"
                                   "aWUueWFob28uY29tggxpdC55YWhvby5jb22CDGVzLnlhaG9vLmNvbYIMZGUueWFo"
                                   "b28uY29tggxjYS55YWhvby5jb22CDHFjLnlhaG9vLmNvbYIMYnIueWFob28uY29t"
                                   "ggxyby55YWhvby5jb22CDHNlLnlhaG9vLmNvbYIMYmUueWFob28uY29tgg9mci1i"
                                   "ZS55YWhvby5jb22CDGFyLnlhaG9vLmNvbYIMbXgueWFob28uY29tggxjbC55YWhv"
                                   "by5jb22CDGNvLnlhaG9vLmNvbYIMdmUueWFob28uY29tghFlc3Bhbm9sLnlhaG9v"
                                   "LmNvbYIMcGUueWFob28uY29tggxpbi55YWhvby5jb22CDHNnLnlhaG9vLmNvbYIM"
                                   "aWQueWFob28uY29tghJtYWxheXNpYS55YWhvby5jb22CDHBoLnlhaG9vLmNvbYIM"
                                   "dm4ueWFob28uY29tghFtYWt0b29iLnlhaG9vLmNvbYIUZW4tbWFrdG9vYi55YWhv"
                                   "by5jb22CD2NhLm15LnlhaG9vLmNvbYIMZ3IueWFob28uY29tgg1hdHQueWFob28u"
                                   "Y29tggxhdS55YWhvby5jb22CDG56LnlhaG9vLmNvbYIMdHcueWFob28uY29tggxo"
                                   "ay55YWhvby5jb22CDWJyYi55YWhvby5jb22CDG15LnlhaG9vLmNvbYIQYWRkLm15"
                                   "LnlhaG9vLmNvbYIVZXNwYW5vbC5hdHQueWFob28uY29tghJmcm9udGllci55YWhv"
                                   "by5jb22CEXZlcml6b24ueWFob28uY29tghNjYS5yb2dlcnMueWFob28uY29tghZm"
                                   "ci1jYS5yb2dlcnMueWFob28uY29tghR0YXRhZG9jb21vLnlhaG9vLmNvbYIQdGlr"
                                   "b25hLnlhaG9vLmNvbYIXaWRlYW5ldHNldHRlci55YWhvby5jb22CEm10c2luZGlh"
                                   "LnlhaG9vLmNvbYITc21hcnRmcmVuLnlhaG9vLmNvbTAJBgNVHRMEAjAAMA4GA1Ud"
                                   "DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwZQYDVR0g"
                                   "BF4wXDBaBgpghkgBhvhFAQc2MEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1j"
                                   "Yi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBh"
                                   "MB8GA1UdIwQYMBaAFA1EXBZTRMGCfh0gqyX0AWPYvnmlMCsGA1UdHwQkMCIwIKAe"
                                   "oByGGmh0dHA6Ly9zZC5zeW1jYi5jb20vc2QuY3JsMFcGCCsGAQUFBwEBBEswSTAf"
                                   "BggrBgEFBQcwAYYTaHR0cDovL3NkLnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0"
                                   "cDovL3NkLnN5bWNiLmNvbS9zZC5jcnQwDQYJKoZIhvcNAQEFBQADggEBAI2remqe"
                                   "3MpkWxARQ9ZFBhdrMudD7ZZofWGYxHaXBnmrHO70rGeXNIhjkGJMEuScseuqOBHp"
                                   "itIU+QfNbe60Bc7NZdByaTkA+js6OwbeO36CwWkxvOQJfPiz/57UokAXQmjAv5EL"
                                   "rMbu3JEzheDkQ/LYs12kM/fA6Ekmzz2mP8BAeA1iDaoQN74/INu+6u2ZHc22dSMD"
                                   "E8hNhsXFvf7VrTxaLVzJcmq1994cQaj4pyCHW2cAByxITiKzKBmIoOmlEcX3KRgp"
                                   "GFGplashi56WxTAVb65VMQccLDr5dddmi7L9R/7z6p7izeKS0CODzq8EthRRXmNl"
                                   "2tT3KIKcgjEVvCk="
                                   "-----END CERTIFICATE-----",
                                   @"-----BEGIN CERTIFICATE-----"
                                   "MIIF7DCCBNSgAwIBAgIQbsx6pacDIAm4zrz06VLUkTANBgkqhkiG9w0BAQUFADCB"
                                   "yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL"
                                   "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp"
                                   "U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW"
                                   "ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0"
                                   "aG9yaXR5IC0gRzUwHhcNMTAwMjA4MDAwMDAwWhcNMjAwMjA3MjM1OTU5WjCBtTEL"
                                   "MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW"
                                   "ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2UgYXQg"
                                   "aHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykxMDEvMC0GA1UEAxMmVmVy"
                                   "aVNpZ24gQ2xhc3MgMyBTZWN1cmUgU2VydmVyIENBIC0gRzMwggEiMA0GCSqGSIb3"
                                   "DQEBAQUAA4IBDwAwggEKAoIBAQCxh4QfwgxF9byrJZenraI+nLr2wTm4i8rCrFbG"
                                   "5btljkRPTc5v7QlK1K9OEJxoiy6Ve4mbE8riNDTB81vzSXtig0iBdNGIeGwCU/m8"
                                   "f0MmV1gzgzszChew0E6RJK2GfWQS3HRKNKEdCuqWHQsV/KNLO85jiND4LQyUhhDK"
                                   "tpo9yus3nABINYYpUHjoRWPNGUFP9ZXse5jUxHGzUL4os4+guVOc9cosI6n9FAbo"
                                   "GLSa6Dxugf3kzTU2s1HTaewSulZub5tXxYsU5w7HnO1KVGrJTcW/EbGuHGeBy0RV"
                                   "M5l/JJs/U0V/hhrzPPptf4H1uErT9YU3HLWm0AnkGHs4TvoPAgMBAAGjggHfMIIB"
                                   "2zA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLnZlcmlz"
                                   "aWduLmNvbTASBgNVHRMBAf8ECDAGAQH/AgEAMHAGA1UdIARpMGcwZQYLYIZIAYb4"
                                   "RQEHFwMwVjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL2Nw"
                                   "czAqBggrBgEFBQcCAjAeGhxodHRwczovL3d3dy52ZXJpc2lnbi5jb20vcnBhMDQG"
                                   "A1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jcmwudmVyaXNpZ24uY29tL3BjYTMtZzUu"
                                   "Y3JsMA4GA1UdDwEB/wQEAwIBBjBtBggrBgEFBQcBDARhMF+hXaBbMFkwVzBVFglp"
                                   "bWFnZS9naWYwITAfMAcGBSsOAwIaBBSP5dMahqyNjmvDz4Bq1EgYLHsZLjAlFiNo"
                                   "dHRwOi8vbG9nby52ZXJpc2lnbi5jb20vdnNsb2dvLmdpZjAoBgNVHREEITAfpB0w"
                                   "GzEZMBcGA1UEAxMQVmVyaVNpZ25NUEtJLTItNjAdBgNVHQ4EFgQUDURcFlNEwYJ+"
                                   "HSCrJfQBY9i+eaUwHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwDQYJ"
                                   "KoZIhvcNAQEFBQADggEBAAyDJO/dwwzZWJz+NrbrioBL0aP3nfPMU++CnqOh5pfB"
                                   "WJ11bOAdG0z60cEtBcDqbrIicFXZIDNAMwfCZYP6j0M3m+oOmmxw7vacgDvZN/R6"
                                   "bezQGH1JSsqZxxkoor7YdyT3hSaGbYcFQEFn0Sc67dxIHSLNCwuLvPSxe/20majp"
                                   "dirhGi2HbnTTiN0eIsbfFrYrghQKlFzyUOyvzv9iNw2tZdMGQVPtAhTItVgooazg"
                                   "W+yzf5VK+wPIrSbb5mZ4EkrZn0L74ZjmQoObj49nJOhhGbXdzbULJgWOw27EyHW4"
                                   "Rs/iGAZeqa6ogZpHFt4MKGwlJ7net4RYxh84HqTEy2Y="
                                   "-----END CERTIFICATE-----",
                                   nil]
                     expectedPins:[NSArray arrayWithObjects:
                                   @"pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"",
                                   @"pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\"",
                                   nil]];
    
    [NSThread sleepForTimeInterval:5.0];
    XCTAssert(YES, @"Pass");
}

- (void)testSimpleBackgroundReporter {
    
    //just try a simple valid case to see if we can post this to the server
    TSKSimpleBackgroundReporter *reporter = [[TSKSimpleBackgroundReporter alloc] initWithAppBundleId:@"com.example.ABC" appVersion:@"1.0"];
    
    [reporter pinValidationFailed:@"example.com"
                   serverHostname:@"mail.example.com"
                       serverPort:[NSNumber numberWithInt:443]
                     reportingURL:@"http://localhost:3000"
                includeSubdomains:YES
                 certificateChain:[NSArray arrayWithObjects:
                                   @"-----BEGIN CERTIFICATE-----"
                                   "MIIIdzCCB1+gAwIBAgIQTusxCWM5To6gTnCcqR3NpjANBgkqhkiG9w0BAQUFADCB"
                                   "tTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL"
                                   "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2Ug"
                                   "YXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykxMDEvMC0GA1UEAxMm"
                                   "VmVyaVNpZ24gQ2xhc3MgMyBTZWN1cmUgU2VydmVyIENBIC0gRzMwHhcNMTQwOTI0"
                                   "MDAwMDAwWhcNMTUwOTI1MjM1OTU5WjCBhDELMAkGA1UEBhMCVVMxEzARBgNVBAgT"
                                   "CkNhbGlmb3JuaWExEjAQBgNVBAcUCVN1bm55dmFsZTETMBEGA1UEChQKWWFob28g"
                                   "SW5jLjEfMB0GA1UECxQWSW5mb3JtYXRpb24gVGVjaG5vbG9neTEWMBQGA1UEAxQN"
                                   "d3d3LnlhaG9vLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMuz"
                                   "z21vayNu67CPCq2qmLoa2SYeiFIycWPJecSCLsgitM0vBJ+VLYOpUiIHJABC7hgX"
                                   "B0YpcxiXxbhpBngicCLQE0oRhitTmklpxaJ3tCs78XX5pIONPo5l+xegrBR9h+3U"
                                   "plyZt8j03qBqE9kzQSdqcVTPwknUxoseLDvzHbzauxHB/gZinDsrv41Dy3t7UU+f"
                                   "9B/SmW+hJJtkZV8s0JWtmLZqAiQ/x/OtP0exV7/doMLt3aTho3QkG3Nfp46LCRC8"
                                   "6qYmqjxXc+Rq1lNvnKr4+Ju/IvZy1Z/+4OKjOI+30q2RIoI2weaug2RuBxaA91nE"
                                   "TfT0XsjeTWvmtTDqjw8CAwEAAaOCBLAwggSsMIIDYAYDVR0RBIIDVzCCA1OCDXd3"
                                   "dy55YWhvby5jb22CCXlhaG9vLmNvbYIOaHNyZC55YWhvby5jb22CDHVzLnlhaG9v"
                                   "LmNvbYIMZnIueWFob28uY29tggx1ay55YWhvby5jb22CDHphLnlhaG9vLmNvbYIM"
                                   "aWUueWFob28uY29tggxpdC55YWhvby5jb22CDGVzLnlhaG9vLmNvbYIMZGUueWFo"
                                   "b28uY29tggxjYS55YWhvby5jb22CDHFjLnlhaG9vLmNvbYIMYnIueWFob28uY29t"
                                   "ggxyby55YWhvby5jb22CDHNlLnlhaG9vLmNvbYIMYmUueWFob28uY29tgg9mci1i"
                                   "ZS55YWhvby5jb22CDGFyLnlhaG9vLmNvbYIMbXgueWFob28uY29tggxjbC55YWhv"
                                   "by5jb22CDGNvLnlhaG9vLmNvbYIMdmUueWFob28uY29tghFlc3Bhbm9sLnlhaG9v"
                                   "LmNvbYIMcGUueWFob28uY29tggxpbi55YWhvby5jb22CDHNnLnlhaG9vLmNvbYIM"
                                   "aWQueWFob28uY29tghJtYWxheXNpYS55YWhvby5jb22CDHBoLnlhaG9vLmNvbYIM"
                                   "dm4ueWFob28uY29tghFtYWt0b29iLnlhaG9vLmNvbYIUZW4tbWFrdG9vYi55YWhv"
                                   "by5jb22CD2NhLm15LnlhaG9vLmNvbYIMZ3IueWFob28uY29tgg1hdHQueWFob28u"
                                   "Y29tggxhdS55YWhvby5jb22CDG56LnlhaG9vLmNvbYIMdHcueWFob28uY29tggxo"
                                   "ay55YWhvby5jb22CDWJyYi55YWhvby5jb22CDG15LnlhaG9vLmNvbYIQYWRkLm15"
                                   "LnlhaG9vLmNvbYIVZXNwYW5vbC5hdHQueWFob28uY29tghJmcm9udGllci55YWhv"
                                   "by5jb22CEXZlcml6b24ueWFob28uY29tghNjYS5yb2dlcnMueWFob28uY29tghZm"
                                   "ci1jYS5yb2dlcnMueWFob28uY29tghR0YXRhZG9jb21vLnlhaG9vLmNvbYIQdGlr"
                                   "b25hLnlhaG9vLmNvbYIXaWRlYW5ldHNldHRlci55YWhvby5jb22CEm10c2luZGlh"
                                   "LnlhaG9vLmNvbYITc21hcnRmcmVuLnlhaG9vLmNvbTAJBgNVHRMEAjAAMA4GA1Ud"
                                   "DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwZQYDVR0g"
                                   "BF4wXDBaBgpghkgBhvhFAQc2MEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1j"
                                   "Yi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBh"
                                   "MB8GA1UdIwQYMBaAFA1EXBZTRMGCfh0gqyX0AWPYvnmlMCsGA1UdHwQkMCIwIKAe"
                                   "oByGGmh0dHA6Ly9zZC5zeW1jYi5jb20vc2QuY3JsMFcGCCsGAQUFBwEBBEswSTAf"
                                   "BggrBgEFBQcwAYYTaHR0cDovL3NkLnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0"
                                   "cDovL3NkLnN5bWNiLmNvbS9zZC5jcnQwDQYJKoZIhvcNAQEFBQADggEBAI2remqe"
                                   "3MpkWxARQ9ZFBhdrMudD7ZZofWGYxHaXBnmrHO70rGeXNIhjkGJMEuScseuqOBHp"
                                   "itIU+QfNbe60Bc7NZdByaTkA+js6OwbeO36CwWkxvOQJfPiz/57UokAXQmjAv5EL"
                                   "rMbu3JEzheDkQ/LYs12kM/fA6Ekmzz2mP8BAeA1iDaoQN74/INu+6u2ZHc22dSMD"
                                   "E8hNhsXFvf7VrTxaLVzJcmq1994cQaj4pyCHW2cAByxITiKzKBmIoOmlEcX3KRgp"
                                   "GFGplashi56WxTAVb65VMQccLDr5dddmi7L9R/7z6p7izeKS0CODzq8EthRRXmNl"
                                   "2tT3KIKcgjEVvCk="
                                   "-----END CERTIFICATE-----",
                                    nil]
                     expectedPins:[NSArray arrayWithObjects:
                                   @"pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"",
                                   @"pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\"",
                                   nil]];
    
    XCTAssert(YES, @"Pass");
}


- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

@end
