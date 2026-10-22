/*
 
 TSKSPKIHashCache.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */
#import <objc/runtime.h>
#import <objc/message.h>
#import "TSKSPKIHashCache.h"
#import "../TSKLog.h"
#import <CommonCrypto/CommonDigest.h>
#import "pinning_utils.h"

@interface TSKSPKIHashCache ()

// Dictionnary to cache SPKI hashes instead of having to compute them on every connection
@property (nonatomic) SPKICacheDictionnary *spkiCache;
@property (nonatomic) dispatch_queue_t lockQueue;
@property (nonatomic) dispatch_queue_t persistenceQueue;
@property (nonatomic) BOOL persistenceScheduled;
@property (nonatomic) NSString *spkiCacheFilename;


/**
 Load the SPKI cache from the filesystem. This triggers blocking file I/O.
 */
- (SPKICacheDictionnary *)loadSPKICacheFromFileSystem;

@end


@implementation TSKSPKIHashCache

// Must not block: it runs while holding lockQueue, and waiting on the main queue there can deadlock
static void isProtectedDataAvailableAsync(dispatch_queue_t callbackQueue, void (^callback)(BOOL available))
{
    NSCParameterAssert(callbackQueue);
    NSCParameterAssert(callback);

    void (^callbackOnQueue)(BOOL) = ^(BOOL available) {
        dispatch_async(callbackQueue, ^{
            callback(available);
        });
    };

    if (NSThread.isMainThread || !objc_getClass("UIApplication")) {
        callbackOnQueue(_isProtectedDataAvailable());
    } else {
        dispatch_async(dispatch_get_main_queue(), ^{
            callbackOnQueue(_isProtectedDataAvailable());
        });
    }
}

static BOOL _isProtectedDataAvailable(void) {
    Class uiApplicationClass = objc_getClass("UIApplication");
    if (uiApplicationClass) {
        SEL sharedApplicationSelector = sel_registerName("sharedApplication");
        SEL isProtectedDataAvailableSelector = sel_registerName("isProtectedDataAvailable");
        id sharedApp = ((id (*)(id, SEL))objc_msgSend)(uiApplicationClass, sharedApplicationSelector);
        if (sharedApp && [sharedApp respondsToSelector:isProtectedDataAvailableSelector]) {
            return (((BOOL (*)(id, SEL))objc_msgSend)(sharedApp, isProtectedDataAvailableSelector));
        }
    }
    
    return YES;
}

- (instancetype)initWithIdentifier:(NSString *)uniqueIdentifier
{
    self = [super init];
    if (self) {
        // Initialize our locks
        _lockQueue = dispatch_queue_create("TSKSPKIHashLock", DISPATCH_QUEUE_SERIAL);
        _persistenceQueue = dispatch_queue_create("TSKSPKIHashPersistence",
                                                  dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_UTILITY, 0));

        // Ensure a non-nil identifier was provided
        NSAssert(uniqueIdentifier, @"TSKSPKIHashCache initializer must be passed a unique identifier");
        _spkiCacheFilename = uniqueIdentifier;
        
        // First try to load a cached version from the filesystem
        _spkiCache = [self loadSPKICacheFromFileSystem];
        os_log_debug(TSKLogHandle(), "Loaded %lu SPKI cache entries from the filesystem", (unsigned long)_spkiCache.count);
        if (_spkiCache == nil)
        {
            _spkiCache = [NSMutableDictionary new];
        }
    }
    return self;
}

- (NSData *)hashSubjectPublicKeyInfoFromCertificate:(SecCertificateRef)certificate {
    __block NSData *hash = nil;
    
    dispatch_sync(self.lockQueue, ^{
        hash = [self _hashSubjectPublicKeyInfoFromCertificate:certificate];
    });
    
    return hash;
}

- (NSData *)_hashSubjectPublicKeyInfoFromCertificate:(SecCertificateRef)certificate
{
    // Have we seen this certificate before? Look for the SPKI in the cache
    NSData *certificateData = (__bridge_transfer NSData *)(SecCertificateCopyData(certificate));
    NSData *cachedSubjectPublicKeyInfo = self->_spkiCache[certificateData];
    
    if (cachedSubjectPublicKeyInfo)
    {
        os_log_debug(TSKLogHandle(), "Subject Public Key Info hash was found in the cache");
        return cachedSubjectPublicKeyInfo;
    }
    
    // We didn't this certificate in the cache so we need to generate its SPKI hash
    os_log_debug(TSKLogHandle(), "Generating Subject Public Key Info hash...");
    
    NSData *subjectPublicKeyInfo = getSubjectPublicKeyInfo(certificateData);
    if (subjectPublicKeyInfo == nil)
    {
        os_log_error(TSKLogHandle(), "Could not read the Subject Public Key Info from the certificate");
        return nil;
    }
    
    NSMutableData *subjectPublicKeyInfoHash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256([subjectPublicKeyInfo bytes], (CC_LONG)[subjectPublicKeyInfo length], [subjectPublicKeyInfoHash mutableBytes]);
    
    // Store the hash in our memory cache
    self->_spkiCache[certificateData] = subjectPublicKeyInfoHash;
    
    // Update the cache on the filesystem
    [self schedulePersistence];
    
    return subjectPublicKeyInfoHash;
}

- (void)schedulePersistence
{
    if (!self.spkiCacheFilename.length || self.persistenceScheduled) {
        return;
    }
    self.persistenceScheduled = YES;
    
    isProtectedDataAvailableAsync(self.persistenceQueue, ^(BOOL available) {
        __block SPKICacheDictionnary *snapshot = nil;
        dispatch_sync(self.lockQueue, ^{
            self.persistenceScheduled = NO;
            if (available) {
                snapshot = [self.spkiCache mutableCopy];
            }
        });
    
        if (snapshot == nil) {
            os_log_info(TSKLogHandle(), "Protected data not available, skipping SPKI cache persistence");
            return;
        }
    
        NSData *serializedSpkiCache = [NSKeyedArchiver archivedDataWithRootObject:snapshot
                                                            requiringSecureCoding:YES
                                                                            error:nil];
        NSURL *cachePath = [self SPKICachePath];
        if (!cachePath || ![serializedSpkiCache writeToURL:cachePath atomically:YES]) {
            NSAssert(false, @"Failed to write cache");
            os_log_error(TSKLogHandle(), "Could not persist SPKI cache to the filesystem");
        }
    });
}

- (SPKICacheDictionnary *)loadSPKICacheFromFileSystem
{
    NSMutableDictionary *spkiCache = nil;
    NSData *serializedSpkiCache = [NSData dataWithContentsOfURL:[self SPKICachePath]];
    if (serializedSpkiCache) {
        NSError *decodingError = nil;
        spkiCache = [NSKeyedUnarchiver unarchivedObjectOfClasses:[NSSet setWithArray:@[[SPKICacheDictionnary class], [NSData class]]] fromData:serializedSpkiCache error:&decodingError];
        if (decodingError)
        {
            os_log_error(TSKLogHandle(), "Could not retrieve SPKI cache from the filesystem: %{public}@", decodingError);
        }
    }
    return spkiCache;
}

- (NSURL *)SPKICachePath
{
    NSURL *cachesDirUrl = [NSFileManager.defaultManager URLsForDirectory:NSCachesDirectory
                                                               inDomains:NSUserDomainMask].firstObject;
    return [cachesDirUrl URLByAppendingPathComponent:self.spkiCacheFilename];
}

@end


@implementation TSKSPKIHashCache (TestSupport)

- (void)resetSubjectPublicKeyInfoDiskCache
{
    // Discard SPKI cache
    [self waitForPendingSubjectPublicKeyInfoDiskWrites];
    [NSFileManager.defaultManager removeItemAtURL:[self SPKICachePath] error:nil];
}

- (void)waitForPendingSubjectPublicKeyInfoDiskWrites
{
    dispatch_sync(self.persistenceQueue, ^{});
}


- (SPKICacheDictionnary *)getSubjectPublicKeyInfoHashesCache
{
    return _spkiCache;
}

@end
