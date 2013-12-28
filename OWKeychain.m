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

+ (instancetype)keychainItemWithSecItemRef:(SecKeychainItemRef)secItemRef
{
    NSDictionary *query = @{
                            (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
                            (__bridge id)kSecValueRef   : (__bridge id)secItemRef,
                            } ;
    
    NSDictionary * resultDictionary = [OWKeychainItem fetchResultWithQueryDictionary:query error:nil];
    
    if (!resultDictionary) {
        return nil;
    }
    
    return [OWKeychainItem keychainItemFromResultDictionary:resultDictionary];
}
+ (instancetype)keychainItemWithSecPersistentRef:(NSData *)secPersistentRef
{
    NSDictionary *query = @{
                            (__bridge id)kSecMatchLimit         : (__bridge id)kSecMatchLimitOne,
                            (__bridge id)kSecValuePersistentRef : secPersistentRef,
                            } ;
    
    NSDictionary * resultDictionary = [OWKeychainItem fetchResultWithQueryDictionary:query error:nil];
    
    if (!resultDictionary) {
        return nil;
    }
    
    return [OWKeychainItem keychainItemFromResultDictionary:resultDictionary];
}
+ (instancetype)keychainItemFromResultDictionary:resultDictionary
{
    Class keychainItemClass = nil;
    CFTypeRef secClass = (__bridge CFTypeRef)(resultDictionary[(__bridge id)kSecClass]);
    
    if (secClass==kSecClassGenericPassword) {
        keychainItemClass = [OWGenericKeychainItem class];
    } else if (secClass==kSecClassInternetPassword) {
        keychainItemClass = [OWInternetKeychainItem class];
    }
    
    if (keychainItemClass) {
        return [[keychainItemClass alloc] initWithResultDictionary:resultDictionary];
    }
    
    return nil;
}

- (instancetype)initWithResultDictionary:resultDictionary
{
    self = [super init];
    if (self) {
        self.resultDictionary = resultDictionary;
        _updateDictionary = [@{} mutableCopy];
    }
    return self;
}

#pragma mark Sec Readonly Attributes / Return Values

- (CFTypeRef)secClass
{
    return (__bridge CFTypeRef)(self.resultDictionary[(__bridge id)kSecClass]);
}
- (SecKeychainItemRef)secItemRef
{
    return (__bridge SecKeychainItemRef)(self.resultDictionary[(__bridge id)kSecValueRef]);
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

- (NSString *)secAccessGroup
{
    return self.resultDictionary[(__bridge id)kSecAttrAccessGroup];
}
- (void)setSecAccessGroup:(NSString *)group
{
    self.updateDictionary[(__bridge id)kSecAttrAccessGroup] = group;
}

#pragma mark Item Existence

- (BOOL)isExist
{
    return self.resultDictionary.count > 0;
}

+ (NSDictionary *)fetchResultWithQueryDictionary:(NSDictionary *)queryDictionary error:(NSError *__autoreleasing *)error
{
    NSMutableDictionary *query = [queryDictionary mutableCopy];
    query[(__bridge id)kSecReturnAttributes] = @YES;
    query[(__bridge id)kSecReturnRef] = @YES;
    query[(__bridge id)kSecReturnPersistentRef] = @YES;
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &result);
    
    if (status != errSecSuccess && error != NULL) {
        *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
    }
    
    return CFBridgingRelease(result);
}

+ (NSDictionary *)addItemAndFetchResultWithQueryDictionary:(NSDictionary *)queryDictionary error:(NSError *__autoreleasing *)error
{
    NSMutableDictionary *query = [queryDictionary mutableCopy];
    query[(__bridge id)kSecReturnAttributes] = @YES;
    query[(__bridge id)kSecReturnRef] = @YES;
    query[(__bridge id)kSecReturnPersistentRef] = @YES;
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)(query), &result);
    
    if (status != errSecSuccess && error != NULL) {
        *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
    }
    
    return CFBridgingRelease(result);
}

#pragma mark Commit / Reset Changes / Delete

- (NSError *)commit
{
    NSError *error = nil;
    if (! self.hasUncommittedChanges) {
        return error;
    }
    
    NSDictionary *queryDictionary = @{
                                      (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
                                      (__bridge id)kSecValueRef   : (__bridge id)self.secItemRef
                                      };
    
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)queryDictionary,
                               (__bridge CFDictionaryRef)self.updateDictionary);
    
    if (status != errSecSuccess) {
        error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
    }
    
    // reset update dictionary to make password swept from memory
    [self reset];
    return error;
}

- (void)reset
{
    [self.updateDictionary removeAllObjects];
}

- (BOOL)hasUncommittedChanges
{
    return self.updateDictionary.count > 0;
}

- (NSError *)delete
{
    NSError *error = nil;
    NSDictionary *queryDictionary = @{
                                      (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
                                      (__bridge id)kSecValueRef   : (__bridge id)self.secItemRef
                                      };
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)(queryDictionary));
    
    if (status != errSecSuccess && error != NULL) {
        self.resultDictionary = nil;
        error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
    }
    
    return error;
}

@end

#pragma mark - OWBasePasswordKeychainItem

@implementation OWBasePasswordKeychainItem

#pragma mark Sec Readonly Attributes / Return Values

- (NSDate *)secCreationDate
{
    return self.resultDictionary[(__bridge id)kSecAttrCreationDate];
}

- (NSDate *)secModificationDate
{
    return self.resultDictionary[(__bridge id)kSecAttrModificationDate];
}

#pragma mark Sec Readwrite Attributes / Return Values

- (NSString *)secAccount
{
    return (self.resultDictionary[(__bridge id)kSecAttrAccount]);
}
- (void)setSecAccount:(NSString *)account
{
    self.updateDictionary[(__bridge id)kSecAttrAccount] = account;
}

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
                                      (__bridge id)kSecValueRef   : (__bridge id)self.secItemRef,
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
+ (instancetype)genericKeychainItemWithService:(NSString *)service account:(NSString *)account accessGroup:(NSString *)accessGroup
{
    NSMutableDictionary *query = [@{
                                    (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
                                    (__bridge id)kSecClass      : (__bridge id)kSecClassGenericPassword,
                                    } mutableCopy];
    
    if (service)     query[ (__bridge id)kSecAttrService] = service;
    if (account)     query[ (__bridge id)kSecAttrAccount] = account;
    if (accessGroup) query[ (__bridge id)kSecAttrAccessGroup] = accessGroup;
    
    NSDictionary * resultDictionary = [OWInternetKeychainItem fetchResultWithQueryDictionary:query error:nil];
    
    if (!resultDictionary) {
        return nil;
    }
    
    return [[OWGenericKeychainItem alloc] initWithResultDictionary:resultDictionary];
}

+ (instancetype)addGenericKeychainItemWithService:(NSString *)service account:(NSString *)account password:(NSString *)password
{
    return [OWGenericKeychainItem addGenericKeychainItemWithService:service account:account password:password accessGroup:nil];
}
+ (instancetype)addGenericKeychainItemWithService:(NSString *)service account:(NSString *)account password:(NSString *)password accessGroup:(NSString *)accessGroup
{
    NSMutableDictionary *query = [@{
                                    (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
                                    (__bridge id)kSecClass      : (__bridge id)kSecClassGenericPassword,
                                    } mutableCopy];
    
    if (service)     query[ (__bridge id)kSecAttrService] = service;
    if (account)     query[ (__bridge id)kSecAttrAccount] = account;
    if (accessGroup) query[ (__bridge id)kSecAttrAccessGroup] = accessGroup;
    if (password)    query[ (__bridge id)kSecValueData] = [password dataUsingEncoding:NSUTF8StringEncoding];
    
    NSDictionary * resultDictionary = [OWGenericKeychainItem addItemAndFetchResultWithQueryDictionary:query error:nil];
    
    if (!resultDictionary) {
        return nil;
    }
    
    return [[OWGenericKeychainItem alloc] initWithResultDictionary:resultDictionary];
}

#pragma mark Sec Readwrite Attributes / Return Values

- (NSString *)secService
{
    return self.resultDictionary[(__bridge id)kSecAttrService];
}
- (void)setSecService:(NSString *)service
{
    self.updateDictionary[(__bridge id)kSecAttrService] = service;
}

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


+ (instancetype)internetKeychainItemWithServer:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path account:(NSString *)account
{
    return [OWInternetKeychainItem internetKeychainItemWithServer:(NSString *)server protocol:protocol port:port path:path account:account accessGroup:nil authenticationType:NULL securityDomain:nil];
}
+ (instancetype)internetKeychainItemWithServer:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path account:(NSString *)account accessGroup:(NSString *)accessGroup
{
    return [OWInternetKeychainItem internetKeychainItemWithServer:(NSString *)server protocol:protocol port:port path:path account:account accessGroup:accessGroup authenticationType:NULL securityDomain:nil];
}
+ (instancetype)internetKeychainItemWithServer:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path account:(NSString *)account accessGroup:(NSString *)accessGroup authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain
{
    NSMutableDictionary *query = [@{
                                    (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
                                    (__bridge id)kSecClass      : (__bridge id)kSecClassInternetPassword,
                                    } mutableCopy];
    
    if (server)             query[ (__bridge id)kSecAttrServer] = server;
    if (account)            query[ (__bridge id)kSecAttrAccount] = account;
    if (protocol)           query[ (__bridge id)kSecAttrProtocol] = (__bridge id)(protocol);
    if (port)               query[ (__bridge id)kSecAttrPort] = @(port);
    if (path)               query[ (__bridge id)kSecAttrPath] = path;
    if (accessGroup)        query[ (__bridge id)kSecAttrAccessGroup] = accessGroup;
    if (securityDomain)     query[ (__bridge id)kSecAttrSecurityDomain] = securityDomain;
    if (authenticationType) query[ (__bridge id)kSecAttrAuthenticationType] = (__bridge id)(authenticationType);
    
    NSDictionary * resultDictionary = [OWInternetKeychainItem fetchResultWithQueryDictionary:query error:nil];
    
    if (!resultDictionary) {
        return nil;
    }
    
    return [[OWInternetKeychainItem alloc] initWithResultDictionary:resultDictionary];
}


+ (instancetype)addInternetKeychainItemWithServer:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path account:(NSString *)account password:(NSString *)password
{
    return [OWInternetKeychainItem addInternetKeychainItemWithServer:(NSString *)server protocol:protocol port:port path:path account:account password:(NSString *)password accessGroup:nil authenticationType:NULL securityDomain:nil];
}
+ (instancetype)addInternetKeychainItemWithServer:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path account:(NSString *)account password:(NSString *)password accessGroup:(NSString *)accessGroup
{
    return [OWInternetKeychainItem addInternetKeychainItemWithServer:(NSString *)server protocol:protocol port:port path:path account:account password:(NSString *)password accessGroup:accessGroup authenticationType:NULL securityDomain:nil];
}
+ (instancetype)addInternetKeychainItemWithServer:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path account:(NSString *)account password:(NSString *)password accessGroup:(NSString *)accessGroup authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain
{
    NSMutableDictionary *query = [@{
                                    (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
                                    (__bridge id)kSecClass      : (__bridge id)kSecClassInternetPassword,
                                    } mutableCopy];
    
    if (server)             query[ (__bridge id)kSecAttrServer] = server;
    if (account)            query[ (__bridge id)kSecAttrAccount] = account;
    if (protocol)           query[ (__bridge id)kSecAttrProtocol] = (__bridge id)(protocol);
    if (port)               query[ (__bridge id)kSecAttrPort] = @(port);
    if (path)               query[ (__bridge id)kSecAttrPath] = path;
    if (password)           query[ (__bridge id)kSecValueData] = [password dataUsingEncoding:NSUTF8StringEncoding];
    if (accessGroup)        query[ (__bridge id)kSecAttrAccessGroup] = accessGroup;
    if (securityDomain)     query[ (__bridge id)kSecAttrSecurityDomain] = securityDomain;
    if (authenticationType) query[ (__bridge id)kSecAttrAuthenticationType] = (__bridge id)(authenticationType);
    
    NSDictionary * resultDictionary = [OWInternetKeychainItem addItemAndFetchResultWithQueryDictionary:query error:nil];
    
    if (!resultDictionary) {
        return nil;
    }
    
    return [[OWInternetKeychainItem alloc] initWithResultDictionary:resultDictionary];
}

#pragma mark Sec Readonly Attributes / Return Values

- (CFTypeRef)secProtocol
{
    return (__bridge CFTypeRef)((self.resultDictionary[(__bridge id)kSecAttrProtocol]));
}
- (void)setSecProtocol:(CFTypeRef)protocol
{
    self.updateDictionary[(__bridge id)kSecAttrProtocol] = (__bridge id)protocol;
}

- (NSUInteger)secPort
{
    return [self.resultDictionary[(__bridge id)kSecAttrPort] integerValue];
}
- (void)setSecPort:(NSUInteger)port
{
    self.updateDictionary[(__bridge id)kSecAttrPort] = @(port);
}

- (NSString *)secPath
{
    return self.resultDictionary[(__bridge id)kSecAttrService];
}
- (void)setSecPath:(NSString *)path
{
    self.updateDictionary[(__bridge id)kSecAttrPath] = path;
}

- (CFTypeRef)secAuthenticationType
{
    return (__bridge CFTypeRef)(self.resultDictionary[(__bridge id)kSecAttrAuthenticationType]);
}
- (void)setSecAuthenticationType:(CFTypeRef)authenticationType
{
    self.updateDictionary[(__bridge id)kSecAttrAuthenticationType] = (__bridge id)authenticationType;
}

- (NSString *)secSecurityDomain
{
    return self.resultDictionary[(__bridge id)kSecAttrSecurityDomain];
}
- (void)setSecSecurityDomain:(NSString *)securityDomain
{
    self.updateDictionary[(__bridge id)kSecAttrSecurityDomain] = securityDomain;
}

@end

