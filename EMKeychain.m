/*Copyright (c) 2007 Extendmac, LLC. <support@extendmac.com>
 
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

#import "EMKeychain.h"



// stolen from: http://opensource.apple.com/source/Security/Security-176/Keychain/SecKeychainAddIToolsPassword.c
static SecAccessRef createAccess(NSString *accessLabel, NSArray *trustedPaths)
{
	OSStatus err;
	SecAccessRef access=nil;
    SecTrustedApplicationRef myself = nil;
    SecTrustedApplicationRef someOther = nil;
	
	// use default access ("confirm access")
    // make an exception list of applications you want to trust,
    // which are allowed to access the item without requiring user confirmation
    
	CFMutableArrayRef trustedApplications = CFArrayCreateMutable(kCFAllocatorDefault,0,&kCFTypeArrayCallBacks);
    
    err = SecTrustedApplicationCreateFromPath(NULL, &myself);
    
    if (!err) {
        CFArrayAppendValue(trustedApplications,myself);
    }
    
    for (NSUInteger ix=0; ix<trustedPaths.count; ix++) {
        err = SecTrustedApplicationCreateFromPath([trustedPaths[ix] cStringUsingEncoding:NSUTF8StringEncoding], &someOther);
        
        if (!err) {
            CFArrayAppendValue(trustedApplications,someOther);
        }
    }
    
	err = SecAccessCreate((__bridge CFStringRef)(accessLabel), (CFArrayRef)trustedApplications, &access);
    if (err)
        return nil;
    
	return access;
}


@interface EMKeychainItem () {
    NSString *_label;
    NSString *_comment;
    NSString *_description;
}
- (BOOL)modifyAttributeWithTag:(SecItemAttr)attributeTag toBeString:(NSString *)newStringValue;

@property (readwrite) SecKeychainItemRef coreKeychainItem;
@property (readwrite) NSString *username;
@end

@implementation EMKeychainItem

+ (void)lockKeychain {
	SecKeychainLock(NULL);
}
+ (void)unlockKeychain {
	SecKeychainUnlock(NULL, 0, NULL, NO);
}

+ (void)removeKeychainItem:(EMKeychainItem *)keychainItem {
	[keychainItem remove];
}

- (id)initWithCoreKeychainItem:(SecKeychainItemRef)item username:(NSString *)username {
	if ((self = [super init])) 	{
		self.coreKeychainItem = item;
        self.username = username;
	}
	return self;
}

- (NSString *)password {
	UInt32 passwordLength = 0;
	char *password = nil;
    OSStatus returnStatus = SecKeychainItemCopyAttributesAndData(self.coreKeychainItem, NULL, NULL, NULL, &passwordLength, (void **)&password);
    
	if (returnStatus != noErr) {
//        CFStringRef errDesc = SecCopyErrorMessageString(returnStatus, NULL);
//		NSLog(@"Error (%@) - %@", NSStringFromSelector(_cmd), errDesc);
//        CFRelease(errDesc);
		return nil;
	}
	
	char passwordStore[1024];
	if (passwordLength > 1023) {
		passwordLength = 1023; // save room for trailing \0
	}
	strncpy (passwordStore, password, passwordLength);
	
	passwordStore[passwordLength] = '\0';
	NSString *passwordString = [NSString stringWithUTF8String:passwordStore];
    
	SecKeychainItemFreeAttributesAndData(NULL, password);
    return passwordString;
}

- (void)setPassword:(NSString *)newPasswordString {
	if (!newPasswordString)
		return;
	
	const char *newPassword = [newPasswordString UTF8String];
	OSStatus returnStatus = SecKeychainItemModifyAttributesAndData(self.coreKeychainItem, NULL, (UInt32)strlen(newPassword), (void *)newPassword);
    
	if (returnStatus != noErr) {
//        CFStringRef errDesc = SecCopyErrorMessageString(returnStatus, NULL);
//		NSLog(@"Error (%@) - %@", NSStringFromSelector(_cmd), errDesc);
//        CFRelease(errDesc);
	}
}

- (NSString *)label
{
    return _label;
}
- (void)setLabel:(NSString *)newLabel
{
    _label = newLabel;
    [self modifyAttributeWithTag:kSecLabelItemAttr toBeString:newLabel];
}

- (NSString *)comment {
    return _comment;
}
- (void)setComment:(NSString *)newComment
{
    _comment = newComment;
    [self modifyAttributeWithTag:kSecCommentItemAttr toBeString:newComment];
}

- (NSString *)description
{
    return _description;
}
- (void)setDescription:(NSString *)newDescription
{
    _description = newDescription;
    [self modifyAttributeWithTag:kSecDescriptionItemAttr toBeString:newDescription];
}

- (void)remove {
  	SecKeychainItemDelete(self.coreKeychainItem);
}
- (void)dealloc {
	if (self.coreKeychainItem) CFRelease(self.coreKeychainItem);
}

- (BOOL)modifyAttributeWithTag:(SecItemAttr)attributeTag toBeString:(NSString *)newStringValue
{
	const char *newValue = [newStringValue UTF8String];
	SecKeychainAttribute attributes[1];
	attributes[0].tag = attributeTag;
	attributes[0].length = (UInt32)strlen(newValue);
	attributes[0].data = (void *)newValue;
	
	SecKeychainAttributeList list;
	list.count = 1;
	list.attr = attributes;
	
	OSStatus returnStatus = SecKeychainItemModifyAttributesAndData(self.coreKeychainItem, &list, 0, NULL);
	return (returnStatus == noErr);
}

@end

@interface EMGenericKeychainItem()

@property (readwrite) NSString *service;

@end


@implementation EMGenericKeychainItem

+ (EMGenericKeychainItem *)genericKeychainItemForService:(NSString *)serviceNameString withUsername:(NSString *)usernameString
{
	if (!usernameString || [usernameString length] == 0)
		return nil;
	
	const char *serviceName = [serviceNameString UTF8String];
	const char *username = [usernameString UTF8String];
	
	SecKeychainItemRef item = nil;
	OSStatus returnStatus = SecKeychainFindGenericPassword(NULL, (UInt32)strlen(serviceName), serviceName, (UInt32)strlen(username), username, NULL, NULL, &item);
	
	if (returnStatus != noErr || !item) {
//        CFStringRef errDesc = SecCopyErrorMessageString(returnStatus, NULL);
//		NSLog(@"Error (%@) - %@", NSStringFromSelector(_cmd), errDesc);
//        CFRelease(errDesc);
		return nil;
	}
	
	return [[EMGenericKeychainItem alloc] initWithCoreKeychainItem:item serviceName:serviceNameString username:usernameString];
}

+ (EMGenericKeychainItem *)addGenericKeychainItemForService:(NSString *)serviceNameString withUsername:(NSString *)usernameString password:(NSString *)passwordString
{
    if (!usernameString || [usernameString length] == 0 || !serviceNameString || [serviceNameString length] == 0)
        return nil;
    
    const char *serviceName = [serviceNameString UTF8String];
    const char *username = [usernameString UTF8String];
    const char *password = [passwordString UTF8String];
    
    SecKeychainItemRef item = nil;
    OSStatus returnStatus = SecKeychainAddGenericPassword(NULL, (UInt32)strlen(serviceName), serviceName, (UInt32)strlen(username), username, (UInt32)strlen(password), (void *)password, &item);
    
    if (returnStatus != noErr || !item) {
        //        CFStringRef errDesc = SecCopyErrorMessageString(returnStatus, NULL);
        //		NSLog(@"Error (%@) - %@", NSStringFromSelector(_cmd), errDesc);
        //        CFRelease(errDesc);
        return nil;
    }
    return [[EMGenericKeychainItem alloc] initWithCoreKeychainItem:item serviceName:serviceNameString username:usernameString];
}

- (id)initWithCoreKeychainItem:(SecKeychainItemRef)item serviceName:(NSString *)serviceName username:(NSString *)username
{
	if ((self = [super initWithCoreKeychainItem:item username:username]))
    {
		self.service = serviceName;
	}
	return self;
}

@end

@interface EMInternetKeychainItem()

@property (readwrite) NSString *server;
@property (readwrite) NSString *path;
@property (readwrite) UInt16   port;
@property (readwrite) SecProtocolType   protocol;

@end

@implementation EMInternetKeychainItem

+ (EMInternetKeychainItem *)internetKeychainItemForServer:(NSString *)serverString withUsername:(NSString *)usernameString path:(NSString *)pathString port:(UInt16)port protocol:(SecProtocolType)protocol
{
	if (!usernameString || [usernameString length] == 0 || !serverString || [serverString length] == 0)
		return nil;
	
	const char *server = [serverString UTF8String];
	const char *username = [usernameString UTF8String];
	const char *path = [pathString UTF8String];
	
	if (!pathString || [pathString length] == 0)
		path = "";
		
	SecKeychainItemRef item = nil;
	OSStatus returnStatus = SecKeychainFindInternetPassword(NULL, (UInt32)strlen(server), server, 0, NULL, (UInt32)strlen(username), username, (UInt32)strlen(path), path, port, protocol, kSecAuthenticationTypeDefault, NULL, NULL, &item);
	
	if (returnStatus != noErr || !item) {
//        CFStringRef errDesc = SecCopyErrorMessageString(returnStatus, NULL);
//		NSLog(@"Error (%@) - %@", NSStringFromSelector(_cmd), errDesc);
//        CFRelease(errDesc);
		return nil;
	}
	
	return [[EMInternetKeychainItem alloc] initWithCoreKeychainItem:item server:serverString username:usernameString path:pathString port:port protocol:protocol];
}

+ (EMInternetKeychainItem *)addInternetKeychainItemForServer:(NSString *)serverString withUsername:(NSString *)usernameString password:(NSString *)passwordString path:(NSString *)pathString port:(UInt16)port protocol:(SecProtocolType)protocol {
    if (!usernameString || [usernameString length] == 0 || !serverString || [serverString length] == 0 || !passwordString || [passwordString length] == 0)
        return nil;
    
    const char *server = [serverString UTF8String];
    const char *username = [usernameString UTF8String];
    const char *password = [passwordString UTF8String];
    const char *path = [pathString UTF8String];
    
    if (!pathString || [pathString length] == 0)
        path = "";
    
    SecKeychainItemRef item = nil;
    OSStatus returnStatus = SecKeychainAddInternetPassword(NULL, (UInt32)strlen(server), server, 0, NULL, (UInt32)strlen(username), username, (UInt32)strlen(path), path, port, protocol, kSecAuthenticationTypeDefault, (UInt32)strlen(password), (void *)password, &item);
    
    if (returnStatus != noErr || !item) {
        //        CFStringRef errDesc = SecCopyErrorMessageString(returnStatus, NULL);
        //		NSLog(@"Error (%@) - %@", NSStringFromSelector(_cmd), errDesc);
        //        CFRelease(errDesc);
        return nil;
    }
    return [[EMInternetKeychainItem alloc] initWithCoreKeychainItem:item server:serverString username:usernameString path:pathString port:port protocol:protocol];
}

- (id)initWithCoreKeychainItem:(SecKeychainItemRef)item server:(NSString *)server username:(NSString *)username path:(NSString *)path port:(UInt16)port protocol:(SecProtocolType)protocol {
	if ((self = [super initWithCoreKeychainItem:item username:username])) {
        self.server = server;
        self.path = path;
        self.port = port;
        self.protocol = protocol;
	}
	return self;
}

@end
