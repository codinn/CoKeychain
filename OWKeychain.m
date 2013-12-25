/*Copyright (c) 2013 Codinn Studio. <yang@codinnstudio.com>
 
 Permission is hereby granted, free of charge, to any person
 obtaining a copy of this software and associated documentation
 files (the "Software"), to deal in the Software without
 restriction, including without limitation the rights to use,
 copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following
 conditions:
 
 The above copyright notice and this permission notice shall be
 included in all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
 */

#import "OWKeychain.h"

#pragma mark OWKeychainItem

@interface OWKeychainItem()

@property NSMutableDictionary   *attributes;
@property NSDictionary          *returnAttributes;

@end

@implementation OWKeychainItem

#pragma mark Accessors

- (CFTypeRef)accessible
{
    return (__bridge CFTypeRef)(self.returnAttributes[(__bridge id)kSecAttrAccessible]);
}

- (NSString *)accessGroup
{
    return self.returnAttributes[(__bridge id)kSecAttrAccessGroup];
}

- (BOOL)isExist
{
    return self.returnAttributes!=nil;
}

- (CFTypeRef)returnRef
{
    return (__bridge CFTypeRef)(self.returnAttributes[(__bridge id)kSecValueRef]);
}
- (NSData *)returnPersistentRef
{
    return self.returnAttributes[(__bridge id)kSecValuePersistentRef];
}

#pragma mark NSObject

- (void)dealloc
{
    
}

#pragma mark Privates

- (BOOL)checkExistence
{
    NSMutableDictionary *query = [self.attributes copy];
    query[(__bridge id)kSecReturnAttributes] = @YES;
    query[(__bridge id)kSecReturnRef] = @YES;
    query[(__bridge id)kSecReturnPersistentRef] = @YES;
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &result);
    if (status != errSecSuccess) {
        return NO;
    }
    
    self.returnAttributes = CFBridgingRelease(result);
    return YES;
}

@end

#pragma mark - OWBasePasswordKeychainItem

@implementation OWBasePasswordKeychainItem

- (instancetype)initWithClass:(CFTypeRef)secClass service:(NSString *)service account:(NSString *)account
{
    self = [super init];
    if (self) {
        self.attributes = [@{
                        (__bridge id)kSecAttrService  : service,
                        (__bridge id)kSecAttrAccount  : account,
                        } mutableCopy];
    }
    return self;
}
- (instancetype)initWithClass:(CFTypeRef)secClass service:(NSString *)service account:(NSString *)account description:(NSString *)description comment:(NSString *)comment
{
    self = [super init];
    if (self) {
        self.attributes = [@{
                        (__bridge id)kSecAttrService      : service,
                        (__bridge id)kSecAttrAccount      : account,
                        (__bridge id)kSecAttrDescription  : description,
                        (__bridge id)kSecAttrComment      : comment,
                        } mutableCopy];
    }
    return self;
}
- (instancetype)initWithClass:(CFTypeRef)secClass service:(NSString *)service account:(NSString *)account description:(NSString *)description comment:(NSString *)comment creator:(NSString *)creator type:(NSString *)type label:(NSString *)label invisible:(BOOL)isInvisible negative:(BOOL)isNegative
{
    self = [super init];
    if (self) {
        self.attributes = [@{
                        (__bridge id)kSecAttrService      : service,
                        (__bridge id)kSecAttrAccount      : account,
                        (__bridge id)kSecAttrDescription  : description,
                        (__bridge id)kSecAttrComment      : comment,
                        (__bridge id)kSecAttrCreator      : creator,
                        (__bridge id)kSecAttrType         : type,
                        (__bridge id)kSecAttrLabel        : label,
                        (__bridge id)kSecAttrIsInvisible  : @(isInvisible),
                        (__bridge id)kSecAttrIsNegative   : @(isNegative),
                        } mutableCopy];
    }
    return self;
}
- (instancetype)initWithClass:(CFTypeRef)secClass service:(NSString *)service account:(NSString *)account description:(NSString *)description comment:(NSString *)comment creator:(NSString *)creator type:(NSString *)type label:(NSString *)label invisible:(BOOL)isInvisible negative:(BOOL)isNegative accessGroup:(NSString *)accessGroup accessible:(CFTypeRef) accessible
{
    self = [super init];
    if (self) {
        self.attributes = [@{
                        (__bridge id)kSecAttrService      : service,
                        (__bridge id)kSecAttrAccount      : account,
                        (__bridge id)kSecAttrDescription  : description,
                        (__bridge id)kSecAttrComment      : comment,
                        (__bridge id)kSecAttrCreator      : creator,
                        (__bridge id)kSecAttrType         : type,
                        (__bridge id)kSecAttrLabel        : label,
                        (__bridge id)kSecAttrIsInvisible  : @(isInvisible),
                        (__bridge id)kSecAttrIsNegative   : @(isNegative),
                        (__bridge id)kSecAttrAccessGroup  : accessGroup,
                        (__bridge id)kSecAttrAccessible   : (__bridge id)accessible
                        } mutableCopy];
    }
    return self;
}

- (void)setPassword:(NSString *)password error:(NSError **)error
{
    return [self setPasswordData:[password dataUsingEncoding:NSUTF8StringEncoding] error:error];
}

- (void)setPasswordData:(NSData *)data error:(NSError **)error
{
    OSStatus status;
    
    if (self.isExist) {
        NSMutableDictionary *searchDictionary = [self.attributes copy];
        NSDictionary *updateDictionary = @{
                                           (__bridge id)kSecValueData : data
                                           };
        
        status = SecItemUpdate((__bridge CFDictionaryRef)searchDictionary,
                               (__bridge CFDictionaryRef)updateDictionary);
    } else {
        NSMutableDictionary *dictionary = [self.attributes copy];
        dictionary[(__bridge id)kSecValueData] = data;
        dictionary[(__bridge id)kSecReturnAttributes] = @YES;
        dictionary[(__bridge id)kSecReturnRef] = @YES;
        dictionary[(__bridge id)kSecReturnPersistentRef] = @YES;
        
        CFTypeRef result = NULL;
        
        status = SecItemAdd((__bridge CFDictionaryRef)dictionary, &result);
        
        self.returnAttributes = CFBridgingRelease(result);
    }
    
    if (status != errSecSuccess && error != NULL) {
        self.returnAttributes = nil;
        *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
    }
}

//+ (CFTypeRef *)fetch:(NSDictionary *)query error:(NSError **)error
//{
//    CFTypeRef result = NULL;
//    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &result);
//    if (status != errSecSuccess && error != NULL) {
//        *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:returnStatus userInfo:nil];
//    }
//}
//
//- (NSArray *)fetchAll:(NSDictionary *)query (NSError **)error {
//    OSStatus status = SSKeychainErrorBadArguments;
//    NSMutableDictionary *query = [self query];
//    [query setObject:@YES forKey:(__bridge id)kSecReturnAttributes];
//    [query setObject:(__bridge id)kSecMatchLimitAll forKey:(__bridge id)kSecMatchLimit];
//    
//    CFTypeRef result = NULL;
//    status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
//    if (status != errSecSuccess && error != NULL) {
//        *error = [[self class] errorWithCode:status];
//        return nil;
//    }
//    
//    return (__bridge_transfer NSArray *)result;
//}

#pragma mark - Accessors

- (NSString *)secService
{
    return self.returnAttributes[(__bridge id)kSecAttrService];
}
- (NSString *)secAccount
{
    return self.returnAttributes[(__bridge id)kSecAttrAccount];
}
- (NSString *)secDescription
{
    return self.returnAttributes[(__bridge id)kSecAttrDescription];
}
- (NSString *)secComment
{
    return self.returnAttributes[(__bridge id)kSecAttrComment];
}
- (NSString *)secCreator
{
    return self.returnAttributes[(__bridge id)kSecAttrCreator];
}

- (NSDate *)secCreationDate
{
    return self.returnAttributes[(__bridge id)kSecAttrCreationDate];
}
- (NSDate *)secModificationDate
{
    return self.returnAttributes[(__bridge id)kSecAttrModificationDate];
}
- (NSString *)secType
{
    return self.returnAttributes[(__bridge id)kSecAttrType];
}
- (NSString *)secLabel
{
    return self.returnAttributes[(__bridge id)kSecAttrLabel];
}
- (BOOL)secInvisible
{
    return [self.returnAttributes[(__bridge id)kSecAttrIsInvisible] boolValue];
}
- (BOOL)secNegative
{
    return [self.returnAttributes[(__bridge id)kSecAttrIsNegative] boolValue];
}

@end

#pragma mark - OWGenericKeychainItem

@interface OWGenericKeychainItem()

@end

@implementation OWGenericKeychainItem

- (instancetype)initWithService:(NSString *)service account:(NSString *)account generic:(NSString *)generic
{
    self = [super initWithClass:kSecClassGenericPassword service:service account:account];
    if (self) {
        [self finishInitWithGeneric:generic];
    }
    return self;
}
- (instancetype)initWithService:(NSString *)service account:(NSString *)account generic:(NSString *)generic description:(NSString *)description comment:(NSString *)comment
{
    self = [super initWithClass:kSecClassGenericPassword service:service account:account description:description comment:comment];
    if (self) {
        [self finishInitWithGeneric:generic];
    }
    return self;
}
- (instancetype)initWithService:(NSString *)service account:(NSString *)account generic:(NSString *)generic description:(NSString *)description comment:(NSString *)comment creator:(NSString *)creator type:(NSString *)type label:(NSString *)label invisible:(BOOL)isInvisible negative:(BOOL)isNegative
{
    self = [super initWithClass:kSecClassGenericPassword service:service account:account description:description comment:comment creator:creator type:type label:label invisible:isInvisible negative:isNegative];
    if (self) {
        [self finishInitWithGeneric:generic];
    }
    return self;
}
- (instancetype)initWithService:(NSString *)service account:(NSString *)account generic:(NSString *)generic description:(NSString *)description comment:(NSString *)comment creator:(NSString *)creator type:(NSString *)type label:(NSString *)label invisible:(BOOL)isInvisible negative:(BOOL)isNegative accessGroup:(NSString *)accessGroup accessible:(CFTypeRef) accessible
{
    self = [super initWithClass:kSecClassGenericPassword service:service account:account description:description comment:comment creator:creator type:type label:label invisible:isInvisible negative:isNegative accessGroup:accessGroup accessible:accessible];
    if (self) {
        [self finishInitWithGeneric:generic];
    }
    return self;
}

#pragma mark Private

- (void)finishInitWithGeneric:(NSString *)generic
{
    self.attributes[(__bridge id)kSecClass]       = (__bridge id)kSecClassGenericPassword;
    self.attributes[(__bridge id)kSecAttrGeneric] = generic;
    
    [self checkExistence];
}
@end

#pragma mark - OWInternetKeychainItem

@implementation OWInternetKeychainItem

- (instancetype)initWithService:(NSString *)service account:(NSString *)account protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path
{
    self = [super initWithClass:kSecClassInternetPassword service:service account:account];
    if (self) {
        [self finishInitWithProtocol:protocol port:port path:path];
    }
    return self;
}
- (instancetype)initWithService:(NSString *)service account:(NSString *)account protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path description:(NSString *)description comment:(NSString *)comment
{
    self = [super initWithClass:kSecClassInternetPassword service:service account:account description:description comment:comment];
    if (self) {
        [self finishInitWithProtocol:protocol port:port path:path];
    }
    return self;
}
- (instancetype)initWithService:(NSString *)service account:(NSString *)account protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path description:(NSString *)description comment:(NSString *)comment creator:(NSString *)creator type:(NSString *)type label:(NSString *)label invisible:(BOOL)isInvisible negative:(BOOL)isNegative
{
    self = [super initWithClass:kSecClassInternetPassword service:service account:account description:description comment:comment creator:creator type:type label:label invisible:isInvisible negative:isNegative];
    if (self) {
        [self finishInitWithProtocol:protocol port:port path:path];
    }
    return self;
}
- (instancetype)initWithService:(NSString *)service account:(NSString *)account protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path description:(NSString *)description comment:(NSString *)comment creator:(NSString *)creator type:(NSString *)type label:(NSString *)label invisible:(BOOL)isInvisible negative:(BOOL)isNegative accessGroup:(NSString *)accessGroup accessible:(CFTypeRef) accessible
{
    self = [super initWithClass:kSecClassInternetPassword service:service account:account description:description comment:comment creator:creator type:type label:label invisible:isInvisible negative:isNegative accessGroup:accessGroup accessible:accessible];
    if (self) {
        [self finishInitWithProtocol:protocol port:port path:path];
    }
    return self;
}

#pragma mark Private

- (void)finishInitWithProtocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path
{
    self.attributes[(__bridge id)kSecClass]         = (__bridge id)kSecClassInternetPassword;
    self.attributes[(__bridge id)kSecAttrProtocol]  = (__bridge id)protocol;
    self.attributes[(__bridge id)kSecAttrPort]      = @(port);
    self.attributes[(__bridge id)kSecAttrPath]      = path;
    
    [self checkExistence];
}
@end

