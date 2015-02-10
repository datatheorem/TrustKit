//
//  TrustKit.m
//  TrustKit
//
//  Created by Alban Diquet on 2/9/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import "TrustKit.h"
#import <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#import "fishhook/fishhook.h"

static NSMutableDictionary *certificatePins = NULL;


#pragma mark Certificate Pin Validator

static BOOL verifyCertificatePin(SecTrustRef serverTrust, NSString *serverName)
{
    if ((serverTrust == NULL) || (serverName == NULL))
    {
        return NO;
    }
    
    // First re-check the certificate chain using the default SSL validation in case it was disabled
    // This gives us revocation (only for EV certs I think?) and also ensures the certificate chain is sane
    SecTrustResultType trustResult;
    SecTrustEvaluate(serverTrust, &trustResult);
    if ((trustResult != kSecTrustResultUnspecified) && (trustResult != kSecTrustResultProceed))
    {
        // Default SSL validation failed
        NSLog(@"Error: default SSL validation failed");
        return NO;
    }
    
    // Let's find at least one of the pins in the certificate chain
    NSArray *serverPins = [certificatePins objectForKey:serverName];

    
    // For each pinned certificate, check if it is part of the server's cert trust chain
    // We only need one of the pinned certificates to be in the server's trust chain
    for (NSData *pinnedCertificateHash in serverPins)
    {
        // Check each certificate in the server's certificate chain (the trust object)
        CFIndex certificateChainLen = SecTrustGetCertificateCount(serverTrust);
        for(int i=0;i<certificateChainLen;i++) {
            
            // Extract the certificate
            SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
            NSData* certificateAsDer = (__bridge NSData*) SecCertificateCopyData(certificate);
            
            // Hash the certificate
            NSMutableData *certificateHash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
            CC_SHA256(certificateAsDer.bytes, (unsigned int)certificateAsDer.length,  certificateHash.mutableBytes);
            NSLog(@"PinE %@  PinF %@", pinnedCertificateHash, certificateHash);
            
            // Compare the two hashes
            if ([pinnedCertificateHash isEqualToData:certificateHash])
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
        
        
        if (certificatePins == NULL)
        {   // TODO: return an error
            NSLog(@"Error: pin not initialized?");
            return NO;
        }
        
        
        // Is this domain name pinned ?
        BOOL isPinInCertificateChain = NO;
        if ([certificatePins objectForKey:serverNameStr])
        {
            // Let's check the certificate chain with our SSL pins
            NSLog(@"Server IS pinned");
            SecTrustRef serverTrust;
            SSLCopyPeerTrust(context, &serverTrust);
            isPinInCertificateChain = verifyCertificatePin(serverTrust, serverNameStr);
        }
        else
        {
            // No SSL pinning and regular SSL validation was already done by SSLHandshake and was sucessful
            NSLog(@"Server not pinned");
            isPinInCertificateChain = YES;
        }
        
        if (isPinInCertificateChain == NO)
        {
            // The certificate chain did not contain the expected pins; force an error
            result = errSSLXCertChainInvalid;
        }
    }
    
    return result;
}




#pragma mark Framework Constructor

__attribute__((constructor)) static void initialize(int argc, const char **argv)
{
    NSString *appName = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleIdentifier"];
    NSLog(@"TrustKit started in %@", appName);
    
    certificatePins = [[NSMutableDictionary alloc]init];
    NSDictionary *certificatePinsFromPlist = @{ @"www.yahoo.com" : @[ @"thing 2",
                                               @"lol"],
                         @"www.datatheorem.com" : @[ @"d495962735cd1ca16b6e72ec5e18ae5a9d71f4bf1aec83e5a551d56a49893ca0"]};
    
    
    // Convert the certificates hashes/pins to NSData and store them in the certificatePins variable
    [certificatePinsFromPlist enumerateKeysAndObjectsUsingBlock:^void(id key, id obj, BOOL *stop)
    {
        NSString *serverName = key;
        NSArray *serverSslPinsString = obj;
        NSMutableArray *serverSslPinsData = [[NSMutableArray alloc]init];
        
        for (NSString *pinnedCertificateHash in serverSslPinsString)
        {
            NSMutableData *pinnedCertificateHashData = [NSMutableData dataWithCapacity:CC_SHA256_DIGEST_LENGTH];
            
            // Convert the hex string to data
            if ([pinnedCertificateHash length] != CC_SHA256_DIGEST_LENGTH*2)
            {
                // The certificate hash doesn't have a valid size; store a null hash to make all connections fail
                NSLog(@"Bad hash for %@", serverName);
                [pinnedCertificateHashData resetBytesInRange:NSMakeRange(0, CC_SHA256_DIGEST_LENGTH)];
            }
            else
            {
                // Convert the hash from NSString to NSData
                char output[CC_SHA256_DIGEST_LENGTH];
                const char *input = [pinnedCertificateHash UTF8String];
                
                for (int i=0;i<CC_SHA256_DIGEST_LENGTH;i++)
                {
                    sscanf(input+i*2, "%2hhx", output+i);
                }
                [pinnedCertificateHashData replaceBytesInRange:NSMakeRange(0, CC_SHA256_DIGEST_LENGTH) withBytes:output];
            }
            
            [serverSslPinsData addObject:pinnedCertificateHashData];
        }
        
        [certificatePins setObject:serverSslPinsData forKey:serverName];
    }];
    
    NSLog(@"PINS %@", certificatePins);

    
    
    // Hook SSLHandshake()
    char functionToHook[] = "SSLHandshake";
    original_SSLHandshake = dlsym(RTLD_DEFAULT, functionToHook);
    rebind_symbols((struct rebinding[1]){{(char *)functionToHook, (void *)replaced_SSLHandshake}}, 1);
}

