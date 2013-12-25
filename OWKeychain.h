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


#import <Cocoa/Cocoa.h>
#import <Security/Security.h>

@interface OWKeychainItem : NSObject

@property (readonly) BOOL isExist;

@property (readonly)  CFTypeRef secClass;
@property (readonly)  NSString  *secAccessGroup __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0);
@property (readonly)  CFTypeRef secRef;
@property (readonly)  NSData    *secPersistentRef;

@property (readwrite) CFTypeRef secAccessible   __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0);

// make changes, then save to keychain
- (void)commit:(NSError **)error;

// make changes, then save to keychain
- (void)reset;

@property (readonly) BOOL hasUncommittedChanges;

@end

@interface OWBasePasswordKeychainItem : OWKeychainItem

@property (readonly) NSString  *secAccount;
@property (readonly) NSDate    *secCreationDate;
@property (readonly) NSDate    *secModificationDate;

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

@property (readonly) NSString  *secService;
@property (readwrite) NSString *secGeneric;

+ (instancetype)genericKeychainItemWithService:(NSString *)service account:(NSString *)account;
+ (instancetype)genericKeychainItemWithService:(NSString *)service account:(NSString *)account accessGroup:(NSString *)accessGroup __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0);

+ (instancetype)addGenericKeychainItemWithService:(NSString *)service account:(NSString *)account;
+ (instancetype)addGenericKeychainItemWithService:(NSString *)service account:(NSString *)account accessGroup:(NSString *)accessGroup __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0);

@end

@interface OWInternetKeychainItem : OWBasePasswordKeychainItem

@property (readonly) CFTypeRef  secProtocol;
@property (readonly) NSUInteger secPort;
@property (readonly) NSString   *secPath;
@property (readonly) CFTypeRef  authenticationType;
@property (readonly) NSString   *secSecurityDomain;

+ (instancetype)internetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port;
+ (instancetype)internetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port path:(NSString *)path authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain;
+ (instancetype)internetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port path:(NSString *)path authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain accessGroup:(NSString *)accessGroup __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0);

+ (instancetype)addInternetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port;
+ (instancetype)addInternetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port path:(NSString *)path authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain;
+ (instancetype)addInternetKeychainItemWithServer:(NSString *)server account:(NSString *)account protocol:(SecProtocolType)protocol port:(NSUInteger)port path:(NSString *)path authenticationType:(CFTypeRef)authenticationType securityDomain:(NSString *)securityDomain accessGroup:(NSString *)accessGroup __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0);
@end
