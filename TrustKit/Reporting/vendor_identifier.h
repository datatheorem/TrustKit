//
//  vendor_identifier.h
//  TrustKit
//
//  Created by Alban Diquet on 8/24/16.
//  Copyright © 2016 TrustKit. All rights reserved.
//

#import <Foundation/Foundation.h>


// Will return the IDFV on platforms that support it (iOS, tvOS) and a randomly generated UUID on other platforms (macOS, watchOS)
NSString *identifier_for_vendor(void);
