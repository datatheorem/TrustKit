//
//  public_key_utils.h
//  TrustKit
//
//  Created by Alban Diquet on 4/7/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import "public_key_utils.h"
#include <pthread.h>
#import <CommonCrypto/CommonDigest.h>
#import "TrustKit+Private.h"


#pragma mark Global Cache for SPKI Hashes

// One dictionnary cache per TSKPublicKeyAlgorithm defined
// We use these to cache SPKI hashes instead of having to compute them on every connection
NSMutableDictionary *_subjectPublicKeyInfoHashesCache[3] = {nil, nil, nil};

static pthread_mutex_t _spkiCacheLock; // Used to lock access to our SPKI caches


#pragma mark Missing ASN1 SPKI Headers

// These are the ASN1 headers for the Subject Public Key Info section of a certificate
static unsigned char Rsa2048Asn1Header[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
};

static unsigned char Rsa4096Asn1Header[] = {
    0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00
};

static unsigned char ecDsaSecp256r1Asn1Header[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};

// Careful with the order... must match how TSKPublicKeyAlgorithm is defined
static unsigned char *asn1HeaderBytes[3] = { Rsa2048Asn1Header, Rsa4096Asn1Header, ecDsaSecp256r1Asn1Header };
static unsigned int asn1HeaderSizes[3] = { sizeof(Rsa2048Asn1Header), sizeof(Rsa4096Asn1Header), sizeof(ecDsaSecp256r1Asn1Header) };



#if TARGET_OS_IPHONE

#pragma mark Public Key Converter - iOS

static const NSString *TrustKitPublicKeyTag = @"TSKPublicKeyTag"; // Used to add and find the public key in the Keychain

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
    
    
    // Extract the actual bytes from the key reference using the Keychain
    // Prepare the dictionnary to add the key
    NSMutableDictionary *peerPublicKeyAdd = [[NSMutableDictionary alloc] init];
    [peerPublicKeyAdd setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [peerPublicKeyAdd setObject:TrustKitPublicKeyTag forKey:(__bridge id)kSecAttrApplicationTag];
    [peerPublicKeyAdd setObject:(__bridge id)(publicKey) forKey:(__bridge id)kSecValueRef];
    // Request the key's data to be returned
    [peerPublicKeyAdd setObject:(__bridge id)(kCFBooleanTrue) forKey:(__bridge id)kSecReturnData];
    
    // Prepare the dictionnary to retrieve the key
    NSMutableDictionary * publicKeyGet = [[NSMutableDictionary alloc] init];
    [publicKeyGet setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKeyGet setObject:(TrustKitPublicKeyTag) forKey:(__bridge id)kSecAttrApplicationTag];
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
    NSDictionary *certificateValues = nil;
    CFErrorRef *error = NULL;
    
    // SecCertificateCopyValues() is OS X only
    certificateValues = (__bridge NSDictionary *)(SecCertificateCopyValues(certificate, NULL, error));
    if (certificateValues == NULL)
    {
        TSKLog(@"SecCertificateCopyValues() error");
        return nil;
    }
    
    for (NSString* fieldName in certificateValues)
    {
        NSDictionary *fieldDict = certificateValues[fieldName];
        if ([fieldDict[(__bridge __strong id)(kSecPropertyKeyLabel)] isEqualToString:@"Public Key Data"])
        {
            publicKeyData = fieldDict[(__bridge __strong id)(kSecPropertyKeyValue)];
        }
    }
    return publicKeyData;
}

#endif


#pragma mark SPKI Hashing Function

NSData *hashSubjectPublicKeyInfoFromCertificate(SecCertificateRef certificate, TSKPublicKeyAlgorithm publicKeyAlgorithm)
{
    int algorithm = publicKeyAlgorithm;
    NSData *cachedSubjectPublicKeyInfo = NULL;
    
    // Have we seen this certificate before? Look for the SPKI in the cache
    NSData *certificateData = (__bridge NSData *)(SecCertificateCopyData(certificate));

    pthread_mutex_lock(&_spkiCacheLock);
    {
        cachedSubjectPublicKeyInfo = _subjectPublicKeyInfoHashesCache[algorithm][certificateData];
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
    
    
    // Generate a hash of the subject public key info
    NSMutableData *subjectPublicKeyInfoHash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX shaCtx;
    CC_SHA256_Init(&shaCtx);
    
    // Add the missing ASN1 header for public keys to re-create the subject public key info
    CC_SHA256_Update(&shaCtx, asn1HeaderBytes[publicKeyAlgorithm], asn1HeaderSizes[publicKeyAlgorithm]);
    
    // Add the public key
    CC_SHA256_Update(&shaCtx, [publicKeyData bytes], (unsigned int)[publicKeyData length]);
    CC_SHA256_Final((unsigned char *)[subjectPublicKeyInfoHash bytes], &shaCtx);
    

    // Store the hash in our cache
    pthread_mutex_lock(&_spkiCacheLock);
    {
        _subjectPublicKeyInfoHashesCache[algorithm][certificateData] = subjectPublicKeyInfoHash;
    }
    pthread_mutex_unlock(&_spkiCacheLock);
    
    
    CFRelease((__bridge CFTypeRef)(certificateData));
    return subjectPublicKeyInfoHash;
}



void initializeSubjectPublicKeyInfoCache(void)
{
    // Initialize our caches of SPKI hashes; we have one per type of public keys to make it convenient
    _subjectPublicKeyInfoHashesCache[TSKPublicKeyAlgorithmRsa2048] = [[NSMutableDictionary alloc]init];
    _subjectPublicKeyInfoHashesCache[TSKPublicKeyAlgorithmRsa4096] = [[NSMutableDictionary alloc]init];
    _subjectPublicKeyInfoHashesCache[TSKPublicKeyAlgorithmEcDsaSecp256r1] = [[NSMutableDictionary alloc]init];
    
    // Initialize our locks
    pthread_mutex_init(&_spkiCacheLock, NULL);
    
#if TARGET_OS_IPHONE
    pthread_mutex_init(&_keychainLock, NULL);
    // Cleanup the Keychain in case the App previously crashed
    NSMutableDictionary * publicKeyGet = [[NSMutableDictionary alloc] init];
    [publicKeyGet setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKeyGet setObject:(TrustKitPublicKeyTag) forKey:(__bridge id)kSecAttrApplicationTag];
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
    _subjectPublicKeyInfoHashesCache[TSKPublicKeyAlgorithmRsa2048] = nil;
    _subjectPublicKeyInfoHashesCache[TSKPublicKeyAlgorithmRsa4096] = nil;
    _subjectPublicKeyInfoHashesCache[TSKPublicKeyAlgorithmEcDsaSecp256r1] = nil;
}

