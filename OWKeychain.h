/*Copyright (c) 2013 Codinn. <yang@codinn.com>
 
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


#import <Cocoa/Cocoa.h>
#import <Security/Security.h>

@interface OWKeychainItem : NSObject

@property (readonly) BOOL isExist;

@property (readonly)  CFTypeRef secClass;
@property (readonly)  SecKeychainItemRef secItemRef;
@property (readonly)  NSData    *secPersistentRef;

@property (readwrite) CFTypeRef secAccessible;
@property (readwrite) NSString  *secAccessGroup;

+ (instancetype)keychainItemWithSecItemRef:(SecKeychainItemRef)secItemRef;
+ (instancetype)keychainItemWithSecPersistentRef:(NSData *)secPersistentRef;

// make changes, then save to keychain
- (NSError *)commit;

// make changes, then save to keychain
- (void)reset;

@property (readonly) BOOL hasUncommittedChanges;

- (NSError *)delete;

@end

@interface OWBasePasswordKeychainItem : OWKeychainItem

@property (readonly) NSDate    *secCreationDate;
@property (readonly) NSDate    *secModificationDate;

@property (readwrite) NSString *secAccount;
@property (readwrite) NSString *secDescription;
@property (readwrite) NSString *secComment;
@property (readwrite) NSNumber *secCreator;
@property (readwrite) NSNumber *secType;
@property (readwrite) NSString *secLabel;
@property (readwrite) BOOL     secIsInvisible;
@property (readwrite) BOOL     secIsNegative;

@property (readwrite) NSString *password;
@property (readwrite) NSData   *passwordData;

@end

@interface OWGenericKeychainItem : OWBasePasswordKeychainItem

@property (readwrite) NSString *secService;
@property (readwrite) NSString *secGeneric;

+ (instancetype)genericKeychainItemWithService:(NSString *)service account:(NSString *)account;
+ (instancetype)genericKeychainItemWithService:(NSString *)service account:(NSString *)account accessGroup:(NSString *)accessGroup;

+ (instancetype)addGenericKeychainItemWithService:(NSString *)service account:(NSString *)account password:(NSString *)password;
+ (instancetype)addGenericKeychainItemWithService:(NSString *)service account:(NSString *)account password:(NSString *)password accessGroup:(NSString *)accessGroup;

@end

@interface OWInternetKeychainItem : OWBasePasswordKeychainItem

@property (readwrite) CFTypeRef  secProtocol;
@property (readwrite) NSUInteger secPort;
@property (readwrite) NSString   *secPath;
@property (readwrite) CFTypeRef  authenticationType;
@property (readwrite) NSString   *secSecurityDomain;

+ (instancetype)internetKeychainItemWithServer:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path account:(NSString *)account;
+ (instancetype)internetKeychainItemWithServer:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path account:(NSString *)account accessGroup:(NSString *)accessGroup;
+ (instancetype)internetKeychainItemWithServer:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path account:(NSString *)account accessGroup:(NSString *)accessGroup authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain;

+ (instancetype)addInternetKeychainItemWithServer:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path account:(NSString *)account password:(NSString *)password;
+ (instancetype)addInternetKeychainItemWithServer:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path account:(NSString *)account password:(NSString *)password accessGroup:(NSString *)accessGroup;
+ (instancetype)addInternetKeychainItemWithServer:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path account:(NSString *)account password:(NSString *)password accessGroup:(NSString *)accessGroup authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain;
@end
