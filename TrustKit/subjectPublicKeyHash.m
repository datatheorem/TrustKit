//
//  subjectPublicKeyHash.m
//  TrustKit
//
//  Created by Alban Diquet on 4/7/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import "subjectPublicKeyHash.h"
#import <Foundation/Foundation.h>
#include <pthread.h>
#import <CommonCrypto/CommonDigest.h>

#pragma mark Global Cache for Subject Public Key Info Hashes

NSMutableDictionary *_subjectPublicKeyInfoHashesCache[3];


#pragma mark Public Key Converter

static const NSString *TrustKitPublicKeyTag = @"TSKPublicKeyTag"; // Used to add and find the public key in the Keychain

static pthread_mutex_t _keychainLock; // Used to lock access to our Keychain item


// The one and only way to get a key's data in a buffer on iOS is to put it in the Keychain and then ask for the data back...
static NSData *getPublicKeyBits(SecKeyRef publicKey)
{
    NSData *publicKeyData = nil;
    OSStatus resultAdd, resultDel = noErr;
    
    
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
    
    // TODO: Check the result returned by SecItemXXX()
    
    return publicKeyData;
}



NSData *hashSubjectPublicKeyInfoFromCertificate(SecCertificateRef certificate, TSKPublicKeyAlgorithm publicKeyAlgorithm)
{
    // Have we seen this certificate before? Look for the SPKI in the cache
    NSData *certificateData = (__bridge NSData *)(SecCertificateCopyData(certificate));
    int algorithm = publicKeyAlgorithm;
    
    NSData *cachedSubjectPublicKeyInfo = _subjectPublicKeyInfoHashesCache[algorithm][certificateData];
    if (cachedSubjectPublicKeyInfo)
    {
        NSLog(@"Subject Public Key Info hash was found in the cache");
        return cachedSubjectPublicKeyInfo;
    }
    NSLog(@"Generating Subject Public Key Info hash...");
    
    // New certificate; we need to generate the hash
    // First extract the public key
    SecTrustRef tempTrust;
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustCreateWithCertificates(certificate, policy, &tempTrust);
    SecTrustEvaluate(tempTrust, NULL);
    SecKeyRef publicKey = SecTrustCopyPublicKey(tempTrust);
    NSData *publicKeyData = getPublicKeyBits(publicKey);
    
    
    // Generate a hash of the subject public key info
    // TODO: error checking
    NSMutableData *subjectPublicKeyInfoHash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX shaCtx;
    CC_SHA256_Init(&shaCtx);
    
    // Add the missing ASN1 header for public keys to re-create the subject public key info
    CC_SHA256_Update(&shaCtx,
                     getAsn1HeaderBytesForPublicKeyAlgorithm(publicKeyAlgorithm),
                     getAsn1HeaderSizeForPublicKeyAlgorithm(publicKeyAlgorithm));
    
    // Add the public key
    CC_SHA256_Update(&shaCtx, [publicKeyData bytes], (unsigned int)[publicKeyData length]);
    CC_SHA256_Final((unsigned char *)[subjectPublicKeyInfoHash bytes], &shaCtx);
    CFRelease(publicKey);
    
    // Store the hash in our cache
    _subjectPublicKeyInfoHashesCache[algorithm][certificateData] = subjectPublicKeyInfoHash;
    
    return subjectPublicKeyInfoHash;
}



void initializeKeychain(void)
{
    // Initialize our caches of SPKI hashes; we have one per type of public keys to make it convenient
    _subjectPublicKeyInfoHashesCache[TSKPublicKeyAlgorithmRsa2048] = [[NSMutableDictionary alloc]init];
    _subjectPublicKeyInfoHashesCache[TSKPublicKeyAlgorithmRsa4096] = [[NSMutableDictionary alloc]init];
    _subjectPublicKeyInfoHashesCache[TSKPublicKeyAlgorithmEcDsaSecp256r1] = [[NSMutableDictionary alloc]init];
    
    // Initialize our Keychain lock
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
}

void resetKeychain(void)
{
    // This is only used for tests
    pthread_mutex_destroy(&_keychainLock);
    
    // Discard SPKI cache
    
    // Initialize our caches of SPKI hashes
    _subjectPublicKeyInfoHashesCache[TSKPublicKeyAlgorithmRsa2048] = nil;
    _subjectPublicKeyInfoHashesCache[TSKPublicKeyAlgorithmRsa4096] = nil;
    _subjectPublicKeyInfoHashesCache[TSKPublicKeyAlgorithmEcDsaSecp256r1] = nil;
}

