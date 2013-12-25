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

@property (readonly) NSMutableDictionary *queryDictionary;
@property (readonly) NSMutableDictionary *updateDictionary;
@property NSDictionary                   *resultDictionary;

@end

@implementation OWKeychainItem

- (instancetype)init
{
    self = [super init];
    if (self) {
        // limit query to match one result
        _queryDictionary = [@{
                              (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne}
                            mutableCopy];
        
        _updateDictionary = [@{} mutableCopy];
    }
    return self;
}

#pragma mark Sec Readonly Attributes / Return Values

- (NSString *)secAccessGroup
{
    NSString *accessGroup = self.queryDictionary[(__bridge id)kSecAttrAccessGroup];
    
    if (!accessGroup) {
        accessGroup = self.resultDictionary[(__bridge id)kSecAttrAccessGroup];
    }
    
    return accessGroup;
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

- (BOOL)fetchResultFromKeychain
{
    NSMutableDictionary *query = [self.queryDictionary copy];
    query[(__bridge id)kSecReturnAttributes] = @YES;
    query[(__bridge id)kSecReturnRef] = @YES;
    query[(__bridge id)kSecReturnPersistentRef] = @YES;
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &result);
    if (status != errSecSuccess) {
        return NO;
    }
    
    self.resultDictionary = CFBridgingRelease(result);
    return YES;
}

#pragma mark Apply / Revert Changes

- (void)commit:(NSError **)error
{
    if (! self.hasUncommittedChanges) {
        return;
    }
    
    OSStatus status;
    
    if (self.isExist) {
        status = SecItemUpdate((__bridge CFDictionaryRef)self.queryDictionary,
                               (__bridge CFDictionaryRef)self.updateDictionary);
    } else {
        NSMutableDictionary *dictionary = [self.queryDictionary copy];
        
        // merge from updateDictionary
        [dictionary addEntriesFromDictionary:self.updateDictionary];
        
        dictionary[(__bridge id)kSecReturnAttributes] = @YES;
        dictionary[(__bridge id)kSecReturnRef] = @YES;
        dictionary[(__bridge id)kSecReturnPersistentRef] = @YES;
        
        CFTypeRef result = NULL;
        
        status = SecItemAdd((__bridge CFDictionaryRef)dictionary, &result);
        
        self.resultDictionary = CFBridgingRelease(result);
    }
    
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

- (instancetype)initWithClass:(CFTypeRef)secClass account:(NSString *)account
{
    self = [super init];
    if (self) {
        self.queryDictionary[(__bridge id)kSecClass] = (__bridge id)secClass;
        self.queryDictionary[(__bridge id)kSecAttrAccount] = account;
    }
    return self;
}
- (instancetype)initWithClass:(CFTypeRef)secClass account:(NSString *)account accessGroup:(NSString *)accessGroup
{
    self = [super init];
    if (self) {
        self.queryDictionary[(__bridge id)kSecClass] = (__bridge id)secClass;
        self.queryDictionary[(__bridge id)kSecAttrAccount] = account;
        self.queryDictionary[(__bridge id)kSecAttrAccessGroup] = accessGroup;
    }
    return self;
}

#pragma mark Sec Readonly Attributes / Return Values

- (NSString *)secAccount
{
    NSString *account = (self.queryDictionary[(__bridge id)kSecAttrAccount]);
    
    if (!account) {
        account = (self.resultDictionary[(__bridge id)kSecAttrAccount]);
    }
    
    return account;
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
    NSMutableDictionary *query = [self.queryDictionary copy];
    query[(__bridge id)kSecReturnData] = @YES;
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &result);
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
    return [[OWGenericKeychainItem alloc] initWithService:service account:account];
}
+ (instancetype)genericKeychainItemWithService:(NSString *)service account:(NSString *)account accessGroup:(NSString *)accessGroup __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0)
{
    return [[OWGenericKeychainItem alloc] initWithService:service account:account accessGroup:accessGroup];
}

- (instancetype)initWithService:(NSString *)service account:(NSString *)account
{
    self = [super initWithClass:kSecClassGenericPassword account:account];
    if (self) {
        [self finishInitWithService:service];
    }
    return self;
}
- (instancetype)initWithService:(NSString *)service account:(NSString *)account accessGroup:(NSString *)accessGroup
{
    self = [super initWithClass:kSecClassGenericPassword account:account accessGroup:accessGroup];
    if (self) {
        [self finishInitWithService:service];
    }
    return self;
}

#pragma mark Sec Readonly Attributes / Return Values

- (NSString *)secService
{
    NSString *service = (self.queryDictionary[(__bridge id)kSecAttrService]);
    
    if (!service) {
        service = (self.resultDictionary[(__bridge id)kSecAttrService]);
    }
    
    return service;
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

#pragma mark Private

- (void)finishInitWithService:(NSString *)service
{
    self.queryDictionary[(__bridge id)kSecAttrService] = service;
    [self fetchResultFromKeychain];
}
@end

#pragma mark - OWInternetKeychainItem

@implementation OWInternetKeychainItem


+ (instancetype)internetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port
{
    return [[OWInternetKeychainItem alloc] initWithServer:(NSString *)server account:account protocol:protocol port:port path:nil authenticationType:NULL securityDomain:nil accessGroup:nil];
}
+ (instancetype)internetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port path:(NSString *)path authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain
{
    return [[OWInternetKeychainItem alloc] initWithServer:(NSString *)server account:account protocol:protocol port:port path:path authenticationType:authenticationType securityDomain:nil accessGroup:nil];
}
+ (instancetype)internetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port path:(NSString *)path authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain accessGroup:(NSString *)accessGroup __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0)
{
    return [[OWInternetKeychainItem alloc] initWithServer:(NSString *)server account:account protocol:protocol port:port path:path authenticationType:authenticationType securityDomain:securityDomain accessGroup:accessGroup];
}

- (instancetype)initWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port path:(NSString *)path authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain accessGroup:(NSString *)accessGroup
{
    self = [super initWithClass:kSecClassInternetPassword account:account accessGroup:accessGroup];
    if (self) {
        self.queryDictionary[(__bridge id)kSecAttrServer]    = server;
        self.queryDictionary[(__bridge id)kSecAttrProtocol]  = @(protocol);
        self.queryDictionary[(__bridge id)kSecAttrPort]      = @(port);
        self.queryDictionary[(__bridge id)kSecAttrPath]      = path;
        self.queryDictionary[(__bridge id)kSecAttrAuthenticationType] = (__bridge id)(authenticationType);
        self.queryDictionary[(__bridge id)kSecAttrSecurityDomain]     = securityDomain;
        
        [self fetchResultFromKeychain];
    }
    return self;
}

#pragma mark Sec Readonly Attributes / Return Values

- (CFTypeRef)secProtocol
{
    CFTypeRef value = (__bridge CFTypeRef)((self.queryDictionary[(__bridge id)kSecAttrProtocol]));
    
    if (!value) {
        value = (__bridge CFTypeRef)((self.resultDictionary[(__bridge id)kSecAttrProtocol]));
    }
    
    return value;
}

- (NSUInteger)secPort
{
    NSNumber *value = self.queryDictionary[(__bridge id)kSecAttrPort];
    
    if (!value) {
        value = self.resultDictionary[(__bridge id)kSecAttrPort];
    }
    
    return [value integerValue];
}

- (NSString *)secPath
{
    NSString *value = self.queryDictionary[(__bridge id)kSecAttrPath];
    
    if (!value) {
        value = self.resultDictionary[(__bridge id)kSecAttrService];
    }
    
    return value;
}

- (CFTypeRef)secAuthenticationType
{
    CFTypeRef value = (__bridge CFTypeRef)(self.queryDictionary[(__bridge id)kSecAttrAuthenticationType]);
    
    if (!value) {
        value = (__bridge CFTypeRef)(self.resultDictionary[(__bridge id)kSecAttrAuthenticationType]);
    }
    
    return value;
}

- (NSString *)secSecurityDomain
{
    NSString *value = self.queryDictionary[(__bridge id)kSecAttrSecurityDomain];
    
    if (!value) {
        value = self.resultDictionary[(__bridge id)kSecAttrSecurityDomain];
    }
    
    return value;
}

@end

