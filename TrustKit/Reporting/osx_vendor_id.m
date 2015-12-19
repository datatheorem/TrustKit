/*
 
 osx_vendor_id.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */
#import "osx_vendor_id.h"
#import <IOKit/IOKitLib.h>
#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>


static CFDataRef copy_mac_address(void);


NSString *osx_identifier_for_vendor(NSString *bundleId)
{
    // Get the mac address
    NSData *macAddress = (__bridge_transfer NSData *)(copy_mac_address());
    
    // Append the bundle ID
    NSMutableData *dataToHash = [NSMutableData dataWithData:macAddress];
    [dataToHash appendData:[bundleId dataUsingEncoding:NSUTF8StringEncoding]];
    
    // Generate a SHA1 Hash
    unsigned char hashedData[CC_SHA1_DIGEST_LENGTH];
    if (!CC_SHA1([dataToHash bytes], (unsigned int)[dataToHash length], hashedData))
    {
        // Hashing failed somehow
        return @"could-not-generate-osx-idfv";
    }
    
    // Generate a UUID - it will only use the first 128 bits of the SHA1 hash
    NSUUID *idfv = [[NSUUID alloc]initWithUUIDBytes:hashedData];
    return [idfv UUIDString];
}


// Taken from Apple's Receipt Validation Programming Guide
// https://developer.apple.com/library/mac/releasenotes/General/ValidateAppStoreReceipt/Chapters/ValidateLocally.html#//apple_ref/doc/uid/TP40010573-CH1-SW14
// Returns a CFData object, containing the computer's GUID.
static CFDataRef copy_mac_address(void)
{
    kern_return_t             kernResult;
    mach_port_t               master_port;
    CFMutableDictionaryRef    matchingDict;
    io_iterator_t             iterator;
    io_object_t               service;
    CFDataRef                 macAddress = nil;
    
    kernResult = IOMasterPort(MACH_PORT_NULL, &master_port);
    if (kernResult != KERN_SUCCESS) {
        printf("IOMasterPort returned %d\n", kernResult);
        return nil;
    }
    
    matchingDict = IOBSDNameMatching(master_port, 0, "en0");
    if (!matchingDict) {
        printf("IOBSDNameMatching returned empty dictionary\n");
        return nil;
    }
    
    kernResult = IOServiceGetMatchingServices(master_port, matchingDict, &iterator);
    if (kernResult != KERN_SUCCESS) {
        printf("IOServiceGetMatchingServices returned %d\n", kernResult);
        return nil;
    }
    
    while((service = IOIteratorNext(iterator)) != 0) {
        io_object_t parentService;
        
        kernResult = IORegistryEntryGetParentEntry(service, kIOServicePlane,
                                                   &parentService);
        if (kernResult == KERN_SUCCESS) {
            if (macAddress) CFRelease(macAddress);
            
            macAddress = (CFDataRef) IORegistryEntryCreateCFProperty(parentService,
                                                                     CFSTR("IOMACAddress"), kCFAllocatorDefault, 0);
            IOObjectRelease(parentService);
        } else {
            printf("IORegistryEntryGetParentEntry returned %d\n", kernResult);
        }
        
        IOObjectRelease(service);
    }
    IOObjectRelease(iterator);
    
    return macAddress;
}
