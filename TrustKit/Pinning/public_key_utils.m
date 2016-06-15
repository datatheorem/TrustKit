/*
 
 public_key_utils.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */


#import "public_key_utils.h"
#include <pthread.h>
#import <CommonCrypto/CommonDigest.h>
#import "TrustKit+Private.h"


#pragma mark Global Cache for SPKI Hashes

// Dictionnary to cache SPKI hashes instead of having to compute them on every connection
// Each key is a raw certificate data and each value is the certificate's raw SPKI data
NSMutableDictionary<NSData *, NSData *> *_subjectPublicKeyInfoHashesCache;

// Used to lock access to our SPKI cache
static pthread_mutex_t _spkiCacheLock;

// File name for persisting the cache in the filesystem
static NSString *_spkiCacheFilename = @"TrustKitSpkiCache.plist";

#pragma mark Missing ASN1 SPKI Headers

// These are the ASN1 headers for the Subject Public Key Info section of a certificate
static unsigned char rsa2048Asn1Header[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
};

static unsigned char rsa4096Asn1Header[] = {
    0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00
};

static unsigned char ecDsaSecp256r1Asn1Header[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00
};

// Careful with the order... must match how TSKPublicKeyAlgorithm is defined
static unsigned char *asn1HeaderBytes[3] = { rsa2048Asn1Header, rsa4096Asn1Header, ecDsaSecp256r1Asn1Header };
static unsigned int asn1HeaderSizes[3] = { sizeof(rsa2048Asn1Header), sizeof(rsa4096Asn1Header), sizeof(ecDsaSecp256r1Asn1Header) };



#if TARGET_OS_IPHONE

#pragma mark Public Key Converter - iOS

static const NSString *kTSKKeychainPublicKeyTag = @"TSKKeychainPublicKeyTag"; // Used to add and find the public key in the Keychain

static pthread_mutex_t _keychainLock; // Used to lock access to our Keychain item


// The one and only way to get a key's data in a buffer on iOS is to put it in the Keychain and then ask for the data back...
static NSData *getPublicKeyDataFromCertificate(SecCertificateRef certificate)
{
    NSData *publicKeyData = nil;
    OSStatus resultAdd, resultDel = noErr;
    SecKeyRef publicKey;
    SecTrustRef tempTrust;
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    
    // Get a public key reference from the certificate
    SecTrustCreateWithCertificates(certificate, policy, &tempTrust);
    SecTrustEvaluate(tempTrust, NULL);
    publicKey = SecTrustCopyPublicKey(tempTrust);
    CFRelease(policy);
    CFRelease(tempTrust);
    
    
    // Extract the actual bytes from the key reference using the Keychain
    // Prepare the dictionary to add the key
    NSMutableDictionary *peerPublicKeyAdd = [[NSMutableDictionary alloc] init];
    [peerPublicKeyAdd setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [peerPublicKeyAdd setObject:kTSKKeychainPublicKeyTag forKey:(__bridge id)kSecAttrApplicationTag];
    [peerPublicKeyAdd setObject:(__bridge id)(publicKey) forKey:(__bridge id)kSecValueRef];
    
    // Avoid issues with background fetching while the device is locked
    [peerPublicKeyAdd setObject:(__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly forKey:(__bridge id)kSecAttrAccessible];
    
    // Request the key's data to be returned
    [peerPublicKeyAdd setObject:(__bridge id)(kCFBooleanTrue) forKey:(__bridge id)kSecReturnData];
    
    // Prepare the dictionary to retrieve and delete the key
    NSMutableDictionary * publicKeyGet = [[NSMutableDictionary alloc] init];
    [publicKeyGet setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKeyGet setObject:(kTSKKeychainPublicKeyTag) forKey:(__bridge id)kSecAttrApplicationTag];
    [publicKeyGet setObject:(__bridge id)(kCFBooleanTrue) forKey:(__bridge id)kSecReturnData];
    
    
    // Get the key bytes from the Keychain atomically
    pthread_mutex_lock(&_keychainLock);
    {
        resultAdd = SecItemAdd((__bridge CFDictionaryRef) peerPublicKeyAdd, (void *)&publicKeyData);
        resultDel = SecItemDelete((__bridge CFDictionaryRef)(publicKeyGet));
    }
    pthread_mutex_unlock(&_keychainLock);
    
    CFRelease(publicKey);
    if ((resultAdd != errSecSuccess) || (resultDel != errSecSuccess))
    {
        // Something went wrong with the Keychain we won't know if we did get the right key data
        TSKLog(@"Keychain error");
        publicKeyData = nil;
    }
    
    return publicKeyData;
}

#else

#pragma mark Public Key Converter - OS X

static NSData *getPublicKeyDataFromCertificate(SecCertificateRef certificate)
{
    NSData *publicKeyData = nil;
    CFErrorRef error = NULL;
    
    // SecCertificateCopyValues() is OS X only
    NSArray *oids = [NSArray arrayWithObject:(__bridge id)(kSecOIDX509V1SubjectPublicKey)];
    CFDictionaryRef certificateValues = SecCertificateCopyValues(certificate, (__bridge CFArrayRef)(oids), &error);
    if (certificateValues == NULL)
    {
        CFStringRef errorDescription = CFErrorCopyDescription(error);
        TSKLog(@"SecCertificateCopyValues() error: %@", errorDescription);
        CFRelease(errorDescription);
        CFRelease(error);
        return nil;
    }
    
    for (NSString* fieldName in (__bridge NSDictionary *)certificateValues)
    {
        NSDictionary *fieldDict = CFDictionaryGetValue(certificateValues, (__bridge const void *)(fieldName));
        if ([fieldDict[(__bridge __strong id)(kSecPropertyKeyLabel)] isEqualToString:@"Public Key Data"])
        {
            publicKeyData = fieldDict[(__bridge __strong id)(kSecPropertyKeyValue)];
        }
    }
    CFRelease(certificateValues);
    return publicKeyData;
}

#endif


#pragma mark SPKI Hashing Function

NSData *hashSubjectPublicKeyInfoFromCertificate(SecCertificateRef certificate, TSKPublicKeyAlgorithm publicKeyAlgorithm)
{
    NSData *cachedSubjectPublicKeyInfo = NULL;
    
    // Have we seen this certificate before? Look for the SPKI in the cache
    NSData *certificateData = (__bridge NSData *)(SecCertificateCopyData(certificate));
    
    NSMutableData *certificateDataWithAlgorithm = [NSMutableData dataWithData:certificateData];
    [certificateDataWithAlgorithm appendData:[NSData dataWithBytes:&publicKeyAlgorithm length:sizeof(int)]];

    pthread_mutex_lock(&_spkiCacheLock);
    {
        cachedSubjectPublicKeyInfo = _subjectPublicKeyInfoHashesCache[certificateDataWithAlgorithm];
    }
    pthread_mutex_unlock(&_spkiCacheLock);
    
    if (cachedSubjectPublicKeyInfo)
    {
        TSKLog(@"Subject Public Key Info hash was found in the cache");
        CFRelease((__bridge CFTypeRef)(certificateData));
        return cachedSubjectPublicKeyInfo;
    }
    
    // We didn't this certificate in the cache so we need to generate its SPKI hash
    TSKLog(@"Generating Subject Public Key Info hash...");
    
    // First extract the public key bytes
    NSData *publicKeyData = getPublicKeyDataFromCertificate(certificate);
    if (publicKeyData == nil)
    {
        TSKLog(@"Error - could not extract the public key bytes");
        CFRelease((__bridge CFTypeRef)(certificateData));
        return nil;
    }
    
    
    // Generate a hash of the subject public key info
    NSMutableData *subjectPublicKeyInfoHash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX shaCtx;
    CC_SHA256_Init(&shaCtx);
    
    // Add the missing ASN1 header for public keys to re-create the subject public key info
    CC_SHA256_Update(&shaCtx, asn1HeaderBytes[publicKeyAlgorithm], asn1HeaderSizes[publicKeyAlgorithm]);
    
    // Add the public key
    CC_SHA256_Update(&shaCtx, [publicKeyData bytes], (unsigned int)[publicKeyData length]);
    CC_SHA256_Final((unsigned char *)[subjectPublicKeyInfoHash bytes], &shaCtx);
    

    // Store the hash in our memory cache
    pthread_mutex_lock(&_spkiCacheLock);
    {
        _subjectPublicKeyInfoHashesCache[certificateDataWithAlgorithm] = subjectPublicKeyInfoHash;
    }
    pthread_mutex_unlock(&_spkiCacheLock);
    
    // Update the cache on the filesystem
    NSString *spkiCachePath = [[NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) objectAtIndex:0] stringByAppendingPathComponent:_spkiCacheFilename];
    NSData *serializedSpkiCache = [NSKeyedArchiver archivedDataWithRootObject:_subjectPublicKeyInfoHashesCache];
    if ([serializedSpkiCache writeToFile:spkiCachePath atomically:YES] == NO)
    {
        TSKLog(@"Could not persist SPKI cache to the filesystem");
    }
    
    CFRelease((__bridge CFTypeRef)(certificateData));
    return subjectPublicKeyInfoHash;
}



void initializeSubjectPublicKeyInfoCache(void)
{
    // Initialize our cache of SPKI hashes
    // First try to load a cached version from the filesystem
    _subjectPublicKeyInfoHashesCache = getSpkiCacheFromFileSystem();
    TSKLog(@"Loaded %d SPKI cache entries from the filesystem", [_subjectPublicKeyInfoHashesCache count]);
    if (_subjectPublicKeyInfoHashesCache == nil)
    {
        _subjectPublicKeyInfoHashesCache = [[NSMutableDictionary alloc]init];
    }
    
    // Initialize our locks
    pthread_mutex_init(&_spkiCacheLock, NULL);
    
#if TARGET_OS_IPHONE
    pthread_mutex_init(&_keychainLock, NULL);
    // Cleanup the Keychain in case the App previously crashed
    NSMutableDictionary * publicKeyGet = [[NSMutableDictionary alloc] init];
    [publicKeyGet setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKeyGet setObject:(kTSKKeychainPublicKeyTag) forKey:(__bridge id)kSecAttrApplicationTag];
    [publicKeyGet setObject:(__bridge id)(kCFBooleanTrue) forKey:(__bridge id)kSecReturnData];
    pthread_mutex_lock(&_keychainLock);
    {
        SecItemDelete((__bridge CFDictionaryRef)(publicKeyGet));
    }
    pthread_mutex_unlock(&_keychainLock);
#endif
}

void resetSubjectPublicKeyInfoCache(void)
{
    // This is only used for tests
    // Destroy our locks
    pthread_mutex_destroy(&_spkiCacheLock);
    
#if TARGET_OS_IPHONE
    pthread_mutex_destroy(&_keychainLock);
#endif
    
    // Discard SPKI cache
    _subjectPublicKeyInfoHashesCache = nil;
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSString *spkiCachePath = [[NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) objectAtIndex:0] stringByAppendingPathComponent:_spkiCacheFilename];
    [fileManager removeItemAtPath:spkiCachePath error:nil];
}


NSMutableDictionary<NSData *, NSData *> *getSpkiCacheFromFileSystem(void)
{
    NSMutableDictionary *spkiCache;
    NSString *spkiCachePath = [[NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) objectAtIndex:0] stringByAppendingPathComponent:_spkiCacheFilename];
    NSData *serializedSpkiCache = [NSData dataWithContentsOfFile:spkiCachePath];
    spkiCache = [NSKeyedUnarchiver unarchiveObjectWithData:serializedSpkiCache];
    return spkiCache;
}


