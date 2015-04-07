//
//  TrustKit.m
//  TrustKit
//
//  Created by Alban Diquet on 2/9/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import "TrustKit.h"
#import "TrustKit+Private.h"
#import <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <pthread.h>
#import "fishhook/fishhook.h"


// Info.plist key we read the public key hashes from
static const NSString *TrustKitInfoDictionnaryKey = @"TSKPublicKeyPins";


#pragma mark TrustKit Global State
// Global dictionnary for storing the public key hashes and domains
static NSDictionary *_subjectPublicKeyInfoPins = nil;

// Global preventing multiple initializations (double function interposition, etc.)
static BOOL _isTrustKitInitialized = NO;


#pragma mark Public Key Converter

static NSData *_defaultRsaAsn1Header = nil;

// The ASN1 data for a public key returned by iOS lacks the following ASN1 header
unsigned char defaultRsaAsn1HeaderBytes[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
};

static const NSString *TrustKitPublicKeyTag = @"TSKPublicKeyTag"; // Used to add and find the public key in the Keychain

static pthread_mutex_t _keychainLock; // Used to lock access to our Keychain item


// The one and only way to get a key's data in a buffer on iOS is to put it in the Keychain and then ask for the data back...
NSData *getPublicKeyBits(SecKeyRef publicKey)
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


#pragma mark SSL Pin Validator


BOOL verifyPublicKeyPin(SecTrustRef serverTrust, NSString *serverName)
{
    if ((serverTrust == NULL) || (serverName == NULL))
    {
        return NO;
    }
    
    // First re-check the certificate chain using the default SSL validation in case it was disabled
    // This gives us revocation (only for EV certs I think?) and also ensures the certificate chain is sane
    // And also gives us the exact path that successfully validated the chain
    SecTrustResultType trustResult;
    SecTrustEvaluate(serverTrust, &trustResult);
    if ((trustResult != kSecTrustResultUnspecified) && (trustResult != kSecTrustResultProceed))
    {
        // Default SSL validation failed
        NSLog(@"Error: default SSL validation failed");
        return NO;
    }
    
    // Let's find at least one of the pins in the certificate chain
    NSSet *serverPins = [_subjectPublicKeyInfoPins objectForKey:serverName];
    

    // Check each certificate in the server's certificate chain (the trust object)
    CFIndex certificateChainLen = SecTrustGetCertificateCount(serverTrust);
    for(int i=0;i<certificateChainLen;i++)
    {
        // Extract the certificate
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        
        // Extract the public key
        SecTrustRef tempTrust;
        SecPolicyRef policy = SecPolicyCreateBasicX509();
        SecTrustCreateWithCertificates(certificate, policy, &tempTrust);
        SecTrustEvaluate(tempTrust, NULL);
        SecKeyRef publicKey = SecTrustCopyPublicKey(tempTrust);
        NSData *publicKeyData = getPublicKeyBits(publicKey);
        
        
        // Generate a hash of the subject public key info
        // TODO: error checking and better support for different ASN1 headers
        NSMutableData *subjectPublicKeyInfoHash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
        CC_SHA256_CTX shaCtx;
        CC_SHA256_Init(&shaCtx);
        
        // Add the missing ASN1 header for RSA public keys to re-create the subject public key info
        CC_SHA256_Update(&shaCtx, [[TKSettings defaultRsaAsn1Header] bytes], (unsigned int)[[TKSettings defaultRsaAsn1Header] length]);
        
        // Add the public key
        CC_SHA256_Update(&shaCtx, [publicKeyData bytes], (unsigned int)[publicKeyData length]);
        CC_SHA256_Final((unsigned char *)[subjectPublicKeyInfoHash bytes], &shaCtx);
        CFRelease(publicKey);

        
        // Is the generated hash in our set of pinned hashes ?
        NSLog(@"Testing SSL Pin %@", subjectPublicKeyInfoHash);
        if ([serverPins containsObject:subjectPublicKeyInfoHash])
        {
            NSLog(@"SSL Pin found");
            return YES;
        }
    }
    
    // If we get here, we didn't find any matching certificate in the chain
    NSLog(@"Error: SSL Pin not found");
    return NO;
}



#pragma mark SSLHandshake Hook

static OSStatus (*original_SSLHandshake)(SSLContextRef context);

static OSStatus replaced_SSLHandshake(SSLContextRef context)
{
    OSStatus result = original_SSLHandshake(context);
    if (result == noErr)
    {
        // The handshake was sucessful, let's do our additional checks on the server certificate
        char *serverName = NULL;
        size_t serverNameLen = 0;
        // TODO: error handling
        
        // Get the server's domain name
        SSLGetPeerDomainNameLength (context, &serverNameLen);
        serverName = malloc(serverNameLen+1);
        SSLGetPeerDomainName(context, serverName, &serverNameLen);
        serverName[serverNameLen] = '\0';
        NSLog(@"Result %d - %s", result, serverName);
        
        NSString *serverNameStr = [NSString stringWithUTF8String:serverName];
        free(serverName);
        
        
        if (_subjectPublicKeyInfoPins == NULL)
        {   // TODO: return an error
            NSLog(@"Error: pin not initialized?");
            return NO;
        }
        
        
        // Is this domain name pinned ?
        BOOL wasPinValidationSuccessful = NO;
        if ([_subjectPublicKeyInfoPins objectForKey:serverNameStr])
        {
            // Let's check the certificate chain with our SSL pins
            NSLog(@"Server IS pinned");
            SecTrustRef serverTrust;
            SSLCopyPeerTrust(context, &serverTrust);
            wasPinValidationSuccessful = verifyPublicKeyPin(serverTrust, serverNameStr);
        }
        else
        {
            // No SSL pinning and regular SSL validation was already done by SSLHandshake and was sucessful
            NSLog(@"Server not pinned");
            wasPinValidationSuccessful = YES;
        }
        
        if (wasPinValidationSuccessful == NO)
        {
            // The certificate chain did not contain the expected pins; force an error
            result = errSSLXCertChainInvalid;
        }
    }
    
    return result;
}


#pragma mark Framework Initialization 


static NSDictionary *convertPublicKeyPinsFromStringToData(NSDictionary *publicKeyPins)
{
    // Convert public key hashes/pins from an NSSArray of NSStrings (as provided by the user) to an NSSet of NSData (as needed by TrustKit)
    NSMutableDictionary *convertedPins = [[NSMutableDictionary alloc]init];
    
    for (NSString *serverName in publicKeyPins)
    {
        NSArray *serverSslPinsString = publicKeyPins[serverName];
        NSMutableArray *serverSslPinsData = [[NSMutableArray alloc] init];
        
        NSLog(@"Loading SSL pins for %@", serverName);
        for (NSString *pinnedCertificateHash in serverSslPinsString) {
            NSMutableData *pinnedCertificateHashData = [NSMutableData dataWithCapacity:CC_SHA256_DIGEST_LENGTH];
            
            // Convert the hex string to data
            if ([pinnedCertificateHash length] != CC_SHA256_DIGEST_LENGTH * 2) {
                // The public key hash doesn't have a valid size; store a null hash to make all connections fail
                NSLog(@"Bad hash for %@", serverName);
                [pinnedCertificateHashData resetBytesInRange:NSMakeRange(0, CC_SHA256_DIGEST_LENGTH)];
            }
            else {
                // Convert the hash from NSString to NSData
                char output[CC_SHA256_DIGEST_LENGTH];
                const char *input = [pinnedCertificateHash UTF8String];
                
                for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
                    sscanf(input + i * 2, "%2hhx", output + i);
                }
                [pinnedCertificateHashData replaceBytesInRange:NSMakeRange(0, CC_SHA256_DIGEST_LENGTH) withBytes:output];
            }
            
            [serverSslPinsData addObject:pinnedCertificateHashData];
        }
        
        // Save the public key hashes for this server as an NSSet
        convertedPins[serverName] = [NSSet setWithArray:serverSslPinsData];
    }
    
    return convertedPins;
}


static void initializeTrustKit(NSDictionary *publicKeyPins)
{
    if (_isTrustKitInitialized == YES)
    {
        // TrustKit should only be initialized once so we don't double interpose SecureTransport or get into anything unexpected
        [NSException raise:@"TrustKit already initialized" format:@"TrustKit was already initialized with the following SSL pins: %@", _subjectPublicKeyInfoPins];
    }
    
    if ([publicKeyPins count] > 0)
    {
        // Initialize our Keychain lock
        pthread_mutex_init(&_keychainLock, NULL);
        
        // Convert and store the SSL pins in our global variable
        _subjectPublicKeyInfoPins = [[NSDictionary alloc]initWithDictionary:convertPublicKeyPinsFromStringToData(publicKeyPins)];
        
        // Hook SSLHandshake()
        char functionToHook[] = "SSLHandshake";
        original_SSLHandshake = dlsym(RTLD_DEFAULT, functionToHook);
        rebind_symbols((struct rebinding[1]){{(char *)functionToHook, (void *)replaced_SSLHandshake}}, 1);
        
        _isTrustKitInitialized = YES;
        NSLog(@"TrustKit initialized with pins %@", _subjectPublicKeyInfoPins);
    }
}


#pragma mark Framework Initialization When Statically Linked

@implementation TrustKit


+ (void) initializeWithSslPins:(NSDictionary *)publicKeyPins
{
    NSLog(@"TrustKit started statically in App %@", CFBundleGetValueForInfoDictionaryKey(CFBundleGetMainBundle(), (__bridge CFStringRef)@"CFBundleIdentifier"));
    initializeTrustKit(publicKeyPins);
}

@end


#pragma mark Framework Initialization When Dynamically Linked

__attribute__((constructor)) static void initialize(int argc, const char **argv)
{
    // TrustKit just got injected in the App
    CFBundleRef appBundle = CFBundleGetMainBundle();
    NSLog(@"TrustKit started dynamically in App %@", CFBundleGetValueForInfoDictionaryKey(appBundle, (__bridge CFStringRef)@"CFBundleIdentifier"));
    
    // Retrieve the SSL pins from the App's Info.plist file
    NSDictionary *publicKeyPinsFromInfoPlist = CFBundleGetValueForInfoDictionaryKey(appBundle, (__bridge CFStringRef)TrustKitInfoDictionnaryKey);

    initializeTrustKit(publicKeyPinsFromInfoPlist);
}


#pragma mark Private Configuration Class For Tests

@implementation TKSettings


+ (void)initialize
{
    _defaultRsaAsn1Header = [NSData dataWithBytes:defaultRsaAsn1HeaderBytes length:sizeof(defaultRsaAsn1HeaderBytes)];
}


+ (NSDictionary *)publicKeyPins
{
    return [NSDictionary dictionaryWithDictionary:_subjectPublicKeyInfoPins];
}


+ (BOOL)setPublicKeyPins:(NSDictionary *)publicKeyPins
{
    _subjectPublicKeyInfoPins = [[NSDictionary alloc]initWithDictionary:convertPublicKeyPinsFromStringToData(publicKeyPins)];
    return YES;
}

+ (NSData *)defaultRsaAsn1Header
{
    return _defaultRsaAsn1Header;
}

+ (void)setDefaultRsaAsn1Header:(NSData *)defaultRsaAsn1Header
{
    _defaultRsaAsn1Header = defaultRsaAsn1Header;
}

@end



