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
#import "fishhook/fishhook.h"


// Info.plist key we read the public key hashes from
static const NSString *TrustKitInfoDictionnaryKey = @"TSKPublicKeyPins";


// Global storing the public key hashes and domains
static NSMutableDictionary *_subjectPublicKeyInfoPins = nil;

#pragma mark Public Key Converter

static NSData *_defaultRsaAsn1Header = nil;

// The ASN1 data for a public key returned by iOS lacks the following ASN1 header
unsigned char defaultRsaAsn1HeaderBytes[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
};

static const NSString *TrustKitPublicKeyTag = @"TSKPublicKeyTag"; // Used to add and find the public key in the Keychain

// The one and only way to get a key's data in a buffer on iOS is to put it in the Keychain and then ask for the data back...
NSData *getPublicKeyBits(SecKeyRef publicKey)
{
    NSData *publicKeyData = nil;
    OSStatus resultAdd, resultGet, resultDel = noErr;
    
    
    // Prepare the dictionnary to add the key
    NSMutableDictionary *peerPublicKeyAdd = [[NSMutableDictionary alloc] init];
    [peerPublicKeyAdd setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [peerPublicKeyAdd setObject:TrustKitPublicKeyTag forKey:(__bridge id)kSecAttrApplicationTag];
    [peerPublicKeyAdd setObject:(__bridge id)(publicKey) forKey:(__bridge id)kSecValueRef];
    
    // Prepare the dictionnary to retrieve the key
    NSMutableDictionary * publicKeyGet = [[NSMutableDictionary alloc] init];
    [publicKeyGet setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKeyGet setObject:(TrustKitPublicKeyTag) forKey:(__bridge id)kSecAttrApplicationTag];
    [publicKeyGet setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    
    // Get the key bytes from the Keychain atomically
    @synchronized(_subjectPublicKeyInfoPins)
    {
        resultAdd = SecItemAdd((__bridge CFDictionaryRef) peerPublicKeyAdd, NULL);
        resultGet = SecItemCopyMatching((__bridge CFDictionaryRef)publicKeyGet, (void *)&publicKeyData);
        resultDel = SecItemDelete((__bridge CFDictionaryRef)(publicKeyGet));
    }
    
    //NSLog(@"RESULT %d", result);
    
    return publicKeyData;
}


#pragma mark Certificate Pin Validator

BOOL verifyCertificatePin(SecTrustRef serverTrust, NSString *serverName)
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
    NSArray *serverPins = [_subjectPublicKeyInfoPins objectForKey:serverName];
    
    
    // For each pinned certificate, check if it is part of the server's cert trust chain
    // We only need one of the pinned certificates to be in the server's trust chain
    for (NSData *pinnedSubjectPublicKeyInfoHash in serverPins)
    {
        // Check each certificate in the server's certificate chain (the trust object)
        CFIndex certificateChainLen = SecTrustGetCertificateCount(serverTrust);
        for(int i=0;i<certificateChainLen;i++) {
            
            // Extract the certificate
            SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
            
            // Extract the public key
            SecTrustRef tempTrust;
            SecPolicyRef policy = SecPolicyCreateBasicX509();
            SecTrustCreateWithCertificates(certificate, policy, &tempTrust);
            SecTrustEvaluate(tempTrust, NULL);
            SecKeyRef publicKey = SecTrustCopyPublicKey(tempTrust);
            NSData *publicKeyData = getPublicKeyBits(publicKey);
            
            // Add the missing ASN1 header for RSA public keys to re-create the subject public key info
            NSMutableData *subjectPublicKeyInfoData = [NSMutableData dataWithData:[TKSettings defaultRsaAsn1Header]];
            [subjectPublicKeyInfoData appendData:publicKeyData];
            //NSLog(@"%@ SUBJECT KEY DATA %@", serverName, subjectPublicKeyInfoData);
            
            
            // Hash the public key
            NSMutableData *subjectPublicKeyInfoHash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
            CC_SHA256(subjectPublicKeyInfoData.bytes, (unsigned int)subjectPublicKeyInfoData.length,  subjectPublicKeyInfoHash.mutableBytes);
            CFRelease(publicKey);
            NSLog(@"PinE %@  PinF %@", pinnedSubjectPublicKeyInfoHash, subjectPublicKeyInfoHash);
            
            // Compare the two hashes
            if ([pinnedSubjectPublicKeyInfoHash isEqualToData:subjectPublicKeyInfoHash])
            {
                NSLog(@"OK: Found SSL Pin");
                return YES;
            }
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
            wasPinValidationSuccessful = verifyCertificatePin(serverTrust, serverNameStr);
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

#pragma mark Configuration class TKSettings

//Set up public keys of pinned certificates
@implementation TKSettings


+ (void)initialize
{
    _defaultRsaAsn1Header = [NSData dataWithBytes:defaultRsaAsn1HeaderBytes length:sizeof(defaultRsaAsn1HeaderBytes)];
}


+ (void)_addPublicKeyPinsFromDictionary:(NSDictionary *)publicKeyPins
{
    // Convert public key hashes/pins from NSString to NSData and store them in the _subjectPublicKeyInfoPins global variable
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
        
        // Save the public key hashes for this server
        _subjectPublicKeyInfoPins[serverName] = serverSslPinsData;
    }
}


+ (NSDictionary *)publicKeyPins
{
    return [NSDictionary dictionaryWithDictionary:_subjectPublicKeyInfoPins];
}


+ (BOOL)setPublicKeyPins:(NSDictionary *)publicKeyPins shouldOverwrite:(BOOL)overwritePins
{
    if (overwritePins == YES)
        [_subjectPublicKeyInfoPins removeAllObjects];
    
    [TKSettings _addPublicKeyPinsFromDictionary:publicKeyPins];
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


#pragma mark Framework Initialization

__attribute__((constructor)) static void initialize(int argc, const char **argv)
{
    // TrustKit just got injected in the App
    CFBundleRef appBundle = CFBundleGetMainBundle();
    NSLog(@"TrustKit started in App %@", CFBundleGetValueForInfoDictionaryKey(appBundle, (__bridge CFStringRef)@"CFBundleIdentifier"));
    
    // Initialize the global var where we will store our SSL pins
    _subjectPublicKeyInfoPins = [[NSMutableDictionary alloc]init];
    
    // Retrieve the SSL pins from the App's Info.plist file
    NSDictionary *publicKeyPinsFromInfoPlist = CFBundleGetValueForInfoDictionaryKey(appBundle, (__bridge CFStringRef)TrustKitInfoDictionnaryKey);
    
    // Store the SSL pins
    [TKSettings _addPublicKeyPinsFromDictionary:publicKeyPinsFromInfoPlist];
    
    NSLog(@"PINS %@", _subjectPublicKeyInfoPins);
    
    
    // Hook SSLHandshake()
    char functionToHook[] = "SSLHandshake";
    original_SSLHandshake = dlsym(RTLD_DEFAULT, functionToHook);
    rebind_symbols((struct rebinding[1]){{(char *)functionToHook, (void *)replaced_SSLHandshake}}, 1);
}