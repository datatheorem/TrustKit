/*
 
 TSKSPKIHashCache.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKSPKIHashCache.h"
#import "../TSKLog.h"
#import <CommonCrypto/CommonDigest.h>


#pragma mark Missing ASN1 SPKI Headers

// These are the ASN1 headers for the Subject Public Key Info section of a certificate
// TODO(AD): Are they returned by the new iOS API https://developer.apple.com/documentation/security/2963103-seccertificatecopykey ?
static const unsigned char rsa2048Asn1Header[] =
{
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
};

static const unsigned char rsa4096Asn1Header[] =
{
    0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00
};

static const unsigned char ecDsaSecp256r1Asn1Header[] =
{
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00
};

static const unsigned char ecDsaSecp384r1Asn1Header[] =
{
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00
};


static BOOL isKeySupported(NSString *publicKeyType, NSNumber *publicKeySize)
{
    if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeRSA]) && ([publicKeySize integerValue] == 2048))
    {
        return YES;
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeRSA]) && ([publicKeySize integerValue] == 4096))
    {
        return YES;
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeECSECPrimeRandom]) && ([publicKeySize integerValue] == 256))
    {
        return YES;
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeECSECPrimeRandom]) && ([publicKeySize integerValue] == 384))
    {
        return YES;
    }
    return NO;
}


static char *getAsn1HeaderBytes(NSString *publicKeyType, NSNumber *publicKeySize)
{
    if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeRSA]) && ([publicKeySize integerValue] == 2048))
    {
        return (char *)rsa2048Asn1Header;
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeRSA]) && ([publicKeySize integerValue] == 4096))
    {
        return (char *)rsa4096Asn1Header;
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeECSECPrimeRandom]) && ([publicKeySize integerValue] == 256))
    {
        return (char *)ecDsaSecp256r1Asn1Header;
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeECSECPrimeRandom]) && ([publicKeySize integerValue] == 384))
    {
        return (char *)ecDsaSecp384r1Asn1Header;
    }
    
    @throw([NSException exceptionWithName:@"Unsupported public key algorithm" reason:@"Tried to generate the SPKI hash for an unsupported key algorithm" userInfo:nil]);
}

static unsigned int getAsn1HeaderSize(NSString *publicKeyType, NSNumber *publicKeySize)
{
    if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeRSA]) && ([publicKeySize integerValue] == 2048))
    {
        return sizeof(rsa2048Asn1Header);
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeRSA]) && ([publicKeySize integerValue] == 4096))
    {
        return sizeof(rsa4096Asn1Header);
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeECSECPrimeRandom]) && ([publicKeySize integerValue] == 256))
    {
        return sizeof(ecDsaSecp256r1Asn1Header);
    }
    else if (([publicKeyType isEqualToString:(NSString *)kSecAttrKeyTypeECSECPrimeRandom]) && ([publicKeySize integerValue] == 384))
    {
        return sizeof(ecDsaSecp384r1Asn1Header);
    }
    
    @throw([NSException exceptionWithName:@"Unsupported public key algorithm" reason:@"Tried to generate the SPKI hash for an unsupported key algorithm" userInfo:nil]);
}


@interface TSKSPKIHashCache ()

// Dictionnary to cache SPKI hashes instead of having to compute them on every connection
@property (nonatomic) SPKICacheDictionnary *spkiCache;
@property (nonatomic) dispatch_queue_t lockQueue;
@property (nonatomic) NSString *spkiCacheFilename;


/**
 Load the SPKI cache from the filesystem. This triggers blocking file I/O.
 */
- (SPKICacheDictionnary *)loadSPKICacheFromFileSystem;

@end


@implementation TSKSPKIHashCache

- (instancetype)initWithIdentifier:(NSString *)uniqueIdentifier
{
    self = [super init];
    if (self) {
        // Initialize our locks
        _lockQueue = dispatch_queue_create("TSKSPKIHashLock", DISPATCH_QUEUE_CONCURRENT);

        // Ensure a non-nil identifier was provided
        NSAssert(uniqueIdentifier, @"TSKSPKIHashCache initializer must be passed a unique identifier");
        _spkiCacheFilename = uniqueIdentifier;
        
        // First try to load a cached version from the filesystem
        _spkiCache = [self loadSPKICacheFromFileSystem];
        TSKLog(@"Loaded %lu SPKI cache entries from the filesystem", (unsigned long)_spkiCache.count);
        if (_spkiCache == nil)
        {
            _spkiCache = [NSMutableDictionary new];
        }
    }
    return self;
}

- (NSData *)hashSubjectPublicKeyInfoFromCertificate:(SecCertificateRef)certificate
{
    __block NSData *cachedSubjectPublicKeyInfo;
    
    // Have we seen this certificate before? Look for the SPKI in the cache
    NSData *certificateData = (__bridge_transfer NSData *)(SecCertificateCopyData(certificate));
    
    dispatch_sync(_lockQueue, ^{
        cachedSubjectPublicKeyInfo = self->_spkiCache[certificateData];
    });
    
    if (cachedSubjectPublicKeyInfo)
    {
        TSKLog(@"Subject Public Key Info hash was found in the cache");
        return cachedSubjectPublicKeyInfo;
    }
    
    // We didn't this certificate in the cache so we need to generate its SPKI hash
    TSKLog(@"Generating Subject Public Key Info hash...");
    
    // First extract the public key
    SecKeyRef publicKey = [self copyPublicKeyFromCertificate:certificate];
    
    // Obtain the public key bytes from the key reference
    NSData *publicKeyData = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(publicKey, NULL);
    if (publicKeyData == nil)
    {
        TSKLog(@"Error - could not extract the public key bytes");
        CFRelease(publicKey);
        return nil;
    }
    
    // Obtain the SPKI header based on the key's algorithm
    CFDictionaryRef publicKeyAttributes = SecKeyCopyAttributes(publicKey);
    NSString *publicKeyType = CFDictionaryGetValue(publicKeyAttributes, kSecAttrKeyType);
    NSNumber *publicKeysize = CFDictionaryGetValue(publicKeyAttributes, kSecAttrKeySizeInBits);
    CFRelease(publicKeyAttributes);
    
    if (!isKeySupported(publicKeyType, publicKeysize))
    {
        TSKLog(@"Error - public key algorithm or length is not supported");
        CFRelease(publicKey);
        return nil;
    }
    
    char *asn1HeaderBytes = getAsn1HeaderBytes(publicKeyType, publicKeysize);
    unsigned int asn1HeaderSize = getAsn1HeaderSize(publicKeyType, publicKeysize);
    
    CFRelease(publicKey);
    
    // Generate a hash of the subject public key info
    NSMutableData *subjectPublicKeyInfoHash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX shaCtx;
    CC_SHA256_Init(&shaCtx);
    
    // Add the missing ASN1 header for public keys to re-create the subject public key info
    CC_SHA256_Update(&shaCtx, asn1HeaderBytes, asn1HeaderSize);
    
    
    // Add the public key
    CC_SHA256_Update(&shaCtx, [publicKeyData bytes], (unsigned int)[publicKeyData length]);
    CC_SHA256_Final((unsigned char *)[subjectPublicKeyInfoHash bytes], &shaCtx);
    
    
    // Store the hash in our memory cache
    dispatch_barrier_sync(_lockQueue, ^{
        self->_spkiCache[certificateData] = subjectPublicKeyInfoHash;
    });
    
    // Update the cache on the filesystem
    if (self.spkiCacheFilename.length > 0)
    {
        NSData *serializedSpkiCache = [NSKeyedArchiver archivedDataWithRootObject:_spkiCache requiringSecureCoding:YES error:nil];
        if ([serializedSpkiCache writeToURL:[self SPKICachePath] atomically:YES] == NO)
        {
            NSAssert(false, @"Failed to write cache");
            TSKLog(@"Could not persist SPKI cache to the filesystem");
        }
    }
    
    return subjectPublicKeyInfoHash;
}

- (SPKICacheDictionnary *)loadSPKICacheFromFileSystem
{
    NSMutableDictionary *spkiCache = nil;
    NSData *serializedSpkiCache = [NSData dataWithContentsOfURL:[self SPKICachePath]];
    if (serializedSpkiCache) {
        NSError *decodingError = nil;
        spkiCache = [NSKeyedUnarchiver unarchivedObjectOfClasses:[NSSet setWithArray:@[[SPKICacheDictionnary class], [NSData class]]] fromData:serializedSpkiCache error:&decodingError];
        if (decodingError)
        {
            TSKLog(@"Could not retrieve SPKI cache from the filesystem: %@", decodingError);
        }
    }
    return spkiCache;
}


#pragma mark Public Key Converter - iOS 10.0+, macOS 10.12+, watchOS 3.0, tvOS 10.0

- (SecKeyRef)copyPublicKeyFromCertificate:(SecCertificateRef)certificate
{
    // Create an X509 trust using the using the certificate
    SecTrustRef trust;
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustCreateWithCertificates(certificate, policy, &trust);
    
    // Get a public key reference for the certificate from the trust
    SecTrustResultType result;
    SecTrustEvaluate(trust, &result);
    SecKeyRef publicKey = SecTrustCopyPublicKey(trust);
    CFRelease(policy);
    CFRelease(trust);
    return publicKey;
}

- (NSURL *)SPKICachePath
{
    NSURL *cachesDirUrl = [NSFileManager.defaultManager URLsForDirectory:NSCachesDirectory
                                                               inDomains:NSUserDomainMask].firstObject;
    return [cachesDirUrl URLByAppendingPathComponent:self.spkiCacheFilename];
}

@end


@implementation TSKSPKIHashCache (TestSupport)

- (void)resetSubjectPublicKeyInfoDiskCache
{
    // Discard SPKI cache
    [NSFileManager.defaultManager removeItemAtURL:[self SPKICachePath] error:nil];
}


- (SPKICacheDictionnary *)getSubjectPublicKeyInfoHashesCache
{
    return _spkiCache;
}

@end
