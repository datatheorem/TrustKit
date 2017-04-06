/*
 
 TSKSPKIHashCache.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKPublicKeyAlgorithm.h"

@import Foundation;
@import Security;

// Each key is a raw certificate data (for easy lookup) and each value is the certificate's raw SPKI data
typedef NSMutableDictionary<NSData *, NSData *> SpkiCacheDictionnary;

@interface TSKSPKIHashCache : NSObject

- (NSData *)hashSubjectPublicKeyInfoFromCertificate:(SecCertificateRef)certificate publicKeyAlgorithm:(TSKPublicKeyAlgorithm)publicKeyAlgorithm;

- (NSMutableDictionary<NSNumber *, SpkiCacheDictionnary *> *)getSpkiCache;
- (NSMutableDictionary<NSNumber *, SpkiCacheDictionnary *> *)getSpkiCacheFromFileSystem;

@end
