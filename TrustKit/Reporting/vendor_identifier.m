//
//  vendor_identifier.m
//  TrustKit
//
//  Created by Alban Diquet on 8/24/16.
//  Copyright © 2016 TrustKit. All rights reserved.
//

#import "vendor_identifier.h"


#if TARGET_OS_IPHONE && !TARGET_OS_WATCH

#pragma mark Vendor identifier - macOS, tvOS

@import UIKit; // For accessing the IDFV

NSString *identifier_for_vendor(void)
{
    return [[[UIDevice currentDevice] identifierForVendor]UUIDString];
}

#else

#pragma mark Vendor identifier - macOS, watchOS

#include <pthread.h>

static NSString * const kTSKVendorIdentifierKey = @"TSKVendorIdentifier";


NSString *identifier_for_vendor(void)
{
    // Try to retrieve the vendor ID from the preferences
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    NSString *vendorId = [preferences stringForKey:kTSKVendorIdentifierKey];
    if (vendorId == nil)
    {
        // Generate and store a new UUID
        vendorId = [[NSUUID UUID] UUIDString];
        
        [preferences setObject:vendorId forKey:kTSKVendorIdentifierKey];
        [preferences synchronize];
    }
    return vendorId;
}

#endif

