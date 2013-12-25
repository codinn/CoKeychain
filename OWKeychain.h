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

@property (readonly) CFTypeRef secClass;
@property (readonly) CFTypeRef secAccessible   __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0);
@property (readonly) NSString  *secAccessGroup __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0);
@property (readonly) CFTypeRef secRef;
@property (readonly) NSData    *secPersistentRef;

@end

@interface OWBasePasswordKeychainItem : OWKeychainItem

- (void)setPassword:(NSString *)password error:(NSError **)error;
- (void)setPasswordData:(NSData *)data error:(NSError **)error;

@property (readonly) NSString  *secService;
@property (readonly) NSString  *secAccount;
@property (readonly) NSString  *secDescription;
@property (readonly) NSString  *secComment;
@property (readonly) NSNumber  *secCreator;
@property (readonly) NSDate    *secCreationDate;
@property (readonly) NSDate    *secModificationDate;
@property (readonly) NSNumber  *secType;
@property (readonly) NSString  *secLabel;
@property (readonly) BOOL      secInvisible;
@property (readonly) BOOL      secNegative;

@end

@interface OWGenericKeychainItem : OWBasePasswordKeychainItem

@property (readonly) NSString  *secGeneric;

- (instancetype)initWithService:(NSString *)service account:(NSString *)account generic:(NSString *)generic;

- (instancetype)initWithService:(NSString *)service account:(NSString *)account generic:(NSString *)generic description:(NSString *)description comment:(NSString *)comment;

- (instancetype)initWithService:(NSString *)service account:(NSString *)account generic:(NSString *)generic description:(NSString *)description comment:(NSString *)comment creator:(NSString *)creator type:(NSString *)type label:(NSString *)label invisible:(BOOL)isInvisible negative:(BOOL)isNegative;

- (instancetype)initWithService:(NSString *)service account:(NSString *)account generic:(NSString *)generic description:(NSString *)description comment:(NSString *)comment creator:(NSString *)creator type:(NSString *)type label:(NSString *)label invisible:(BOOL)isInvisible negative:(BOOL)isNegative accessGroup:(NSString *)accessGroup accessible:(CFTypeRef) accessible __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0);

@end

@interface OWInternetKeychainItem : OWBasePasswordKeychainItem

@property (readonly) CFTypeRef  secProtocol;
@property (readonly) NSUInteger secPort;
@property (readonly) NSString   *secPath;

- (instancetype)initWithService:(NSString *)service account:(NSString *)account server:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path;

- (instancetype)initWithService:(NSString *)service account:(NSString *)account server:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path description:(NSString *)description comment:(NSString *)comment;

- (instancetype)initWithService:(NSString *)service account:(NSString *)account server:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path description:(NSString *)description comment:(NSString *)comment creator:(NSString *)creator type:(NSString *)type label:(NSString *)label invisible:(BOOL)isInvisible negative:(BOOL)isNegative;

- (instancetype)initWithService:(NSString *)service account:(NSString *)account server:(NSString *)server protocol:(CFTypeRef)protocol port:(NSUInteger)port path:(NSString *)path description:(NSString *)description comment:(NSString *)comment creator:(NSString *)creator type:(NSString *)type label:(NSString *)label invisible:(BOOL)isInvisible negative:(BOOL)isNegative accessGroup:(NSString *)accessGroup accessible:(CFTypeRef) accessible __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_4_0);
@end


