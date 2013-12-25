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

@property (readonly) NSMutableDictionary *updateDictionary;
@property NSDictionary                   *resultDictionary;

@end

@implementation OWKeychainItem

- (instancetype)initWithResultDictionary:resultDicionary
{
    self = [super init];
    if (self) {
        self.resultDictionary = resultDicionary;
        _updateDictionary = [@{} mutableCopy];
    }
    return self;
}

- (BOOL)deleteFromKeychain
{
    
    NSDictionary *queryDictionary = @{
                                      (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
                                      (__bridge id)kSecValueRef   : (__bridge id)self.secRef
                                      };
    
    SecItemDelete((__bridge CFDictionaryRef)(queryDictionary));
    
    return YES;
}

#pragma mark Sec Readonly Attributes / Return Values

- (NSString *)secAccessGroup
{
    return self.resultDictionary[(__bridge id)kSecAttrAccessGroup];
}

- (CFTypeRef)secRef
{
    return (__bridge CFTypeRef)(self.resultDictionary[(__bridge id)kSecValueRef]);
}
- (NSData *)secPersistentRef
{
    return self.resultDictionary[(__bridge id)kSecValuePersistentRef];
}

#pragma mark Sec Readwrite Attributes / Return Values

- (CFTypeRef)secAccessible
{
    CFTypeRef accessible = (__bridge CFTypeRef)(self.updateDictionary[(__bridge id)kSecAttrAccessible]);
    
    if (!accessible) {
        accessible = (__bridge CFTypeRef)(self.resultDictionary[(__bridge id)kSecAttrAccessible]);
    }
    
    return accessible;
}
- (void)setSecAccessible:(CFTypeRef)accessible
{
    self.updateDictionary[(__bridge id)kSecAttrAccessible] = (__bridge id)accessible;
}

#pragma mark Item Existence

- (BOOL)isExist
{
    return self.resultDictionary.count > 0;
}

+ (NSDictionary *)fetchResultWithQueryDictionary:(NSDictionary *)queryDictionary
{
    NSMutableDictionary *query = [queryDictionary mutableCopy];
    query[(__bridge id)kSecReturnAttributes] = @YES;
    query[(__bridge id)kSecReturnRef] = @YES;
    query[(__bridge id)kSecReturnPersistentRef] = @YES;
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &result);
    if (status != errSecSuccess) {
        return nil;
    }
    
    return CFBridgingRelease(result);
}

+ (NSDictionary *)addWithQueryDictionary:(NSDictionary *)queryDictionary
{
    NSMutableDictionary *query = [queryDictionary mutableCopy];
    query[(__bridge id)kSecReturnAttributes] = @YES;
    query[(__bridge id)kSecReturnRef] = @YES;
    query[(__bridge id)kSecReturnPersistentRef] = @YES;
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)(query), &result);
    if (status != errSecSuccess) {
        return nil;
    }
    
    return CFBridgingRelease(result);
}

#pragma mark Commit / Reset Changes / Delete

- (void)commit:(NSError **)error
{
    if (! self.hasUncommittedChanges) {
        return;
    }
    
    NSDictionary *queryDictionary = @{
                                      (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
                                      (__bridge id)kSecValueRef   : (__bridge id)self.secRef
                                      };
    
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)queryDictionary,
                               (__bridge CFDictionaryRef)self.updateDictionary);
    
    if (status != errSecSuccess && error != NULL) {
        self.resultDictionary = nil;
        *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
    }

    
    [self.updateDictionary removeAllObjects];
}

- (void)reset
{
    if (! self.hasUncommittedChanges) {
        return;
    }
    
    [self.updateDictionary removeAllObjects];
}

- (BOOL)hasUncommittedChanges
{
    return self.updateDictionary.count > 0;
}

#pragma mark NSObject

- (void)dealloc
{
    
}

@end

#pragma mark - OWBasePasswordKeychainItem

@implementation OWBasePasswordKeychainItem

#pragma mark Sec Readonly Attributes / Return Values

- (NSString *)secAccount
{
    return (self.resultDictionary[(__bridge id)kSecAttrAccount]);
}

- (NSDate *)secCreationDate
{
    return self.resultDictionary[(__bridge id)kSecAttrCreationDate];
}

- (NSDate *)secModificationDate
{
    return self.resultDictionary[(__bridge id)kSecAttrModificationDate];
}

#pragma mark Sec Readwrite Attributes / Return Values

- (NSString *)secDescription
{
    NSString * description = self.updateDictionary[(__bridge id)kSecAttrDescription];
    
    if (!description) {
        description = self.resultDictionary[(__bridge id)kSecAttrDescription];
    }
    
    return description;
}
- (void)setSecDescription:(NSString *)description
{
    self.updateDictionary[(__bridge id)kSecAttrDescription] = description;
}

- (NSString *)secComment
{
    NSString * comment = self.updateDictionary[(__bridge id)kSecAttrComment];
    
    if (!comment) {
        comment = self.resultDictionary[(__bridge id)kSecAttrComment];
    }
    
    return comment;
}
- (void)setSecComment:(NSString *)comment
{
    self.updateDictionary[(__bridge id)kSecAttrComment] = comment;
}

- (NSNumber *)secCreator
{
    NSNumber * creator = self.updateDictionary[(__bridge id)kSecAttrCreator];
    
    if (!creator) {
        creator = self.resultDictionary[(__bridge id)kSecAttrCreator];
    }
    
    return creator;
}
- (void)setSecCreator:(NSNumber *)creator
{
    self.updateDictionary[(__bridge id)kSecAttrCreator] = creator;
}

- (NSNumber *)secType
{
    NSNumber * type = self.updateDictionary[(__bridge id)kSecAttrType];
    
    if (!type) {
        type = self.resultDictionary[(__bridge id)kSecAttrType];
    }
    
    return type;
}
- (void)setSecType:(NSNumber *)type
{
    self.updateDictionary[(__bridge id)kSecAttrType] = type;
}

- (NSString *)secLabel
{
    NSString * label = self.updateDictionary[(__bridge id)kSecAttrLabel];
    
    if (!label) {
        label = self.resultDictionary[(__bridge id)kSecAttrLabel];
    }
    
    return label;
}
- (void)setSecLabel:(NSString *)label
{
    self.updateDictionary[(__bridge id)kSecAttrLabel] = label;
}

- (BOOL)secIsInvisible
{
    NSNumber * isInvisible = self.updateDictionary[(__bridge id)kSecAttrIsInvisible];
    
    if (!isInvisible) {
        isInvisible = self.resultDictionary[(__bridge id)kSecAttrIsInvisible];
    }
    
    return [isInvisible boolValue];
}
- (void)setSecIsInvisible:(BOOL)isInvisible
{
    self.updateDictionary[(__bridge id)kSecAttrIsInvisible] = @(isInvisible);
}

- (BOOL)secIsNegative
{
    NSNumber *isNegative = self.updateDictionary[(__bridge id)kSecAttrIsNegative];
    
    if (!isNegative) {
        isNegative = self.resultDictionary[(__bridge id)kSecAttrIsNegative];
    }
    
    return [isNegative boolValue];
}
- (void)setSecIsNegative:(BOOL)isNegative
{
    self.updateDictionary[(__bridge id)kSecAttrIsNegative] = @(isNegative);
}

// For security, set password will be committed immediately
- (NSString *)password
{
    if ([self.passwordData length]) {
        return [[NSString alloc] initWithData:self.passwordData encoding:NSUTF8StringEncoding];
    }
    return nil;
}
- (void)setPassword:(NSString *)password
{
        self.passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
}

- (NSData *)passwordData
{
    NSDictionary *queryDictionary = @{
                                      (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
                                      (__bridge id)kSecValueRef   : (__bridge id)self.secRef,
                                      (__bridge id)kSecReturnData : @YES,
                                      };
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(queryDictionary), &result);
    if (status != errSecSuccess) {
        return nil;
    }
    
    NSData *passwordData = (__bridge_transfer NSData *)result;
    return passwordData;
}
- (void)setPasswordData:(NSData *)data
{
    self.updateDictionary[(__bridge id)kSecValueData] = data;
}

@end

#pragma mark - OWGenericKeychainItem

@interface OWGenericKeychainItem()

@end

@implementation OWGenericKeychainItem

+ (instancetype)genericKeychainItemWithService:(NSString *)service account:(NSString *)account
{
    return [OWGenericKeychainItem genericKeychainItemWithService:service account:account accessGroup:nil];
}
+ (instancetype)genericKeychainItemWithService:(NSString *)service account:(NSString *)account accessGroup:(NSString *)accessGroup __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0)
{
    NSDictionary *queryDictionary = @{
                                      (__bridge id)kSecMatchLimit      : (__bridge id)kSecMatchLimitOne,
                                      (__bridge id)kSecClass           : (__bridge id)kSecClassGenericPassword,
                                      (__bridge id)kSecAttrService     : service,
                                      (__bridge id)kSecAttrAccount     : account,
                                      (__bridge id)kSecAttrAccessGroup : accessGroup,
                                      };
    
    NSDictionary * resultDicionary = [OWInternetKeychainItem fetchResultWithQueryDictionary:queryDictionary];
    
    if (!resultDicionary) {
        return nil;
    }
    
    return [[OWGenericKeychainItem alloc] initWithResultDictionary:resultDicionary];
}

+ (instancetype)addGenericKeychainItemWithService:(NSString *)service account:(NSString *)account password:(NSString *)password
{
    return [OWGenericKeychainItem addGenericKeychainItemWithService:service account:account password:password accessGroup:nil];
}
+ (instancetype)addGenericKeychainItemWithService:(NSString *)service account:(NSString *)account password:(NSString *)password accessGroup:(NSString *)accessGroup __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0)
{
    NSDictionary *queryDictionary = @{
                                      (__bridge id)kSecMatchLimit      : (__bridge id)kSecMatchLimitOne,
                                      (__bridge id)kSecClass           : (__bridge id)kSecClassGenericPassword,
                                      (__bridge id)kSecAttrService     : service,
                                      (__bridge id)kSecAttrAccount     : account,
                                      (__bridge id)kSecValueData       : [password dataUsingEncoding:NSUTF8StringEncoding],
                                      (__bridge id)kSecAttrAccessGroup : accessGroup,
                                      };
    
    NSDictionary * resultDicionary = [OWGenericKeychainItem addWithQueryDictionary:queryDictionary];
    
    if (!resultDicionary) {
        return nil;
    }
    
    return [[OWGenericKeychainItem alloc] initWithResultDictionary:resultDicionary];
}

#pragma mark Sec Readonly Attributes / Return Values

- (NSString *)secService
{
   return self.resultDictionary[(__bridge id)kSecAttrService];
}

#pragma mark Sec Readwrite Attributes / Return Values

- (NSString *)secGeneric
{
    NSString * generic = self.updateDictionary[(__bridge id)kSecAttrGeneric];
    
    if (!generic) {
        generic = self.resultDictionary[(__bridge id)kSecAttrGeneric];
    }
    
    return generic;
}
- (void)setSecGeneric:(NSString *)generic
{
    self.updateDictionary[(__bridge id)kSecAttrGeneric] = generic;
}

@end

#pragma mark - OWInternetKeychainItem

@implementation OWInternetKeychainItem


+ (instancetype)internetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port path:(NSString *)path
{
    return [OWInternetKeychainItem internetKeychainItemWithServer:(NSString *)server account:account protocol:protocol port:port path:path authenticationType:NULL securityDomain:nil accessGroup:nil];
}
+ (instancetype)internetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port path:(NSString *)path authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain
{
    return [OWInternetKeychainItem internetKeychainItemWithServer:(NSString *)server account:account protocol:protocol port:port path:path authenticationType:authenticationType securityDomain:securityDomain accessGroup:nil];
}
+ (instancetype)internetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port path:(NSString *)path authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain accessGroup:(NSString *)accessGroup __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0)
{
    NSDictionary *queryDictionary = @{
                                     (__bridge id)kSecMatchLimit    : (__bridge id)kSecMatchLimitOne,
                                     (__bridge id)kSecClass         : @(kSecInternetPasswordItemClass),
                                     (__bridge id)kSecAttrServer    : server,
                                     (__bridge id)kSecAttrAccount   : account,
                                     (__bridge id)kSecAttrProtocol  : @(protocol),
                                     (__bridge id)kSecAttrPort      : @(port),
                                     (__bridge id)kSecAttrPath      : path,
                                     (__bridge id)kSecAttrAccessGroup        : accessGroup,
                                     (__bridge id)kSecAttrSecurityDomain     : securityDomain,
                                     (__bridge id)kSecAttrAuthenticationType : (__bridge id)(authenticationType),
                                     };
    
    NSDictionary * resultDicionary = [OWInternetKeychainItem fetchResultWithQueryDictionary:queryDictionary];
    
    if (!resultDicionary) {
        return nil;
    }
    
    return [[OWInternetKeychainItem alloc] initWithResultDictionary:resultDicionary];
}


+ (instancetype)addInternetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port path:(NSString *)path password:(NSString *)password
{
    return [OWInternetKeychainItem addInternetKeychainItemWithServer:(NSString *)server account:account protocol:protocol port:port path:path password:(NSString *)password authenticationType:NULL securityDomain:nil accessGroup:nil];
}
+ (instancetype)addInternetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port path:(NSString *)path password:(NSString *)password authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain
{
    return [OWInternetKeychainItem addInternetKeychainItemWithServer:(NSString *)server account:account protocol:protocol port:port path:path password:(NSString *)password authenticationType:authenticationType securityDomain:securityDomain accessGroup:nil];
}
+ (instancetype)addInternetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port path:(NSString *)path password:(NSString *)password authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain accessGroup:(NSString *)accessGroup __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0)
{
    NSDictionary *queryDictionary = @{
                                      (__bridge id)kSecMatchLimit    : (__bridge id)kSecMatchLimitOne,
                                      (__bridge id)kSecClass         : @(kSecInternetPasswordItemClass),
                                      (__bridge id)kSecAttrServer    : server,
                                      (__bridge id)kSecAttrAccount   : account,
                                      (__bridge id)kSecAttrProtocol  : @(protocol),
                                      (__bridge id)kSecAttrPort      : @(port),
                                      (__bridge id)kSecAttrPath      : path,
                                      (__bridge id)kSecValueData     : [password dataUsingEncoding:NSUTF8StringEncoding],
                                      (__bridge id)kSecAttrAccessGroup        : accessGroup,
                                      (__bridge id)kSecAttrSecurityDomain     : securityDomain,
                                      (__bridge id)kSecAttrAuthenticationType : (__bridge id)(authenticationType),
                                      };
    
    NSDictionary * resultDicionary = [OWInternetKeychainItem addWithQueryDictionary:queryDictionary];
    
    if (!resultDicionary) {
        return nil;
    }
    
    return [[OWInternetKeychainItem alloc] initWithResultDictionary:resultDicionary];
}

#pragma mark Sec Readonly Attributes / Return Values

- (CFTypeRef)secProtocol
{
    return (__bridge CFTypeRef)((self.resultDictionary[(__bridge id)kSecAttrProtocol]));
}

- (NSUInteger)secPort
{
    return [self.resultDictionary[(__bridge id)kSecAttrPort] integerValue];
}

- (NSString *)secPath
{
    return self.resultDictionary[(__bridge id)kSecAttrService];
}

- (CFTypeRef)secAuthenticationType
{
    return (__bridge CFTypeRef)(self.resultDictionary[(__bridge id)kSecAttrAuthenticationType]);
}

- (NSString *)secSecurityDomain
{
    return self.resultDictionary[(__bridge id)kSecAttrSecurityDomain];
}

@end

