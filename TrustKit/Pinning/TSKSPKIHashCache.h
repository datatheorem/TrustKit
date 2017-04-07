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

NS_ASSUME_NONNULL_BEGIN

// Each key is a raw certificate data (for easy lookup) and each value is the certificate's raw SPKI data
typedef NSMutableDictionary<NSData *, NSData *> SpkiCacheDictionnary;

@interface TSKSPKIHashCache : NSObject

- (instancetype)new NS_UNAVAILABLE;
- (instancetype)init NS_UNAVAILABLE;

/**
 Create a new cache of SPKI hashes. The identifier is required to ensure that multiple cache
 instances do not attempt to use the same file on disk for persistence. If nil, persistence
 will be disabled (not recommended).

 @param uniqueIdentifier A unique identifier that is stable across app launches/instance creation
 @return An initialized hash cache.
 */
- (instancetype _Nullable)initWithIdentifier:(NSString * _Nullable)uniqueIdentifier NS_DESIGNATED_INITIALIZER;

- (NSData *)hashSubjectPublicKeyInfoFromCertificate:(SecCertificateRef)certificate publicKeyAlgorithm:(TSKPublicKeyAlgorithm)publicKeyAlgorithm;

- (NSMutableDictionary<NSNumber *, SpkiCacheDictionnary *> *)getSpkiCache;

- (NSMutableDictionary<NSNumber *, SpkiCacheDictionnary *> *)getSpkiCacheFromFileSystem;

@end

NS_ASSUME_NONNULL_END
