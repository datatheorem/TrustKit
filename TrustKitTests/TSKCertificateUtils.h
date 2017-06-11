/*
 
 TSKCertificateUtils.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

@import Foundation;

@interface TSKCertificateUtils : NSObject

+ (SecCertificateRef)createCertificateFromPem:(NSString *)pemFilename;

+ (SecCertificateRef)createCertificateFromDer:(NSString *)derFilename;

+ (SecTrustRef)createTrustWithCertificates:(const void **)certArray
                               arrayLength:(NSInteger)certArrayLength
                        anchorCertificates:(const void **)anchorCertificates
                               arrayLength:(NSInteger)anchorArrayLength;

@end
