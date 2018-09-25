/*
 
 vendor_identifier.m
 TrustKit
 
 Copyright 2016 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "vendor_identifier.h"

#if TARGET_OS_IPHONE && !TARGET_OS_WATCH

#pragma mark Vendor identifier - iOS, tvOS

// for accessing the IDFV
#if __has_feature(modules)
@import UIKit;
#else
#import <UIKit/UIKit.h>
#endif

NSString *identifier_for_vendor(void)
{
    return UIDevice.currentDevice.identifierForVendor.UUIDString;
}

#else

#pragma mark Vendor identifier - macOS, watchOS


static NSString * const kTSKVendorIdentifierKey = @"TSKVendorIdentifier";


NSString *identifier_for_vendor(void)
{
    // Try to retrieve the vendor ID from the preferences
    NSUserDefaults *preferences = NSUserDefaults.standardUserDefaults;
    NSString *vendorId = [preferences stringForKey:kTSKVendorIdentifierKey];
    if (vendorId == nil)
    {
        // Generate and store a new UUID
        vendorId = NSUUID.UUID.UUIDString;
        [preferences setObject:vendorId forKey:kTSKVendorIdentifierKey];
        [preferences synchronize];
    }
    return vendorId;
}


#endif

