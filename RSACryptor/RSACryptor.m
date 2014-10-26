//
//  RSACryptor.m
//  RSACryptor
//
//  Created by UQ Times on 13/03/05.
//  Copyright (c) 2013年 UQ Times. All rights reserved.
//

/**
 * 下記URLの "Certificate, Key, and Trust Services Tasks for iOS" を参考にしてあります。
 * http://developer.apple.com/library/ios/#DOCUMENTATION/Security/Conceptual/CertKeyTrustProgGuide/iPhone_Tasks/iPhone_Tasks.html#//apple_ref/doc/uid/TP40001358-CH208-SW13
 *
 * また、"CryptoExercise"というサンプルコードも参照しました。
 * https://developer.apple.com/library/ios/#samplecode/CryptoExercise/Introduction/Intro.html
 */

#import "RSACryptor.h"

@implementation RSACryptor

/**
 * 指定された平文を暗号化する
 */
- (NSString *)encryptString:(NSString *)plainText withPublicKey:(NSString *)keyPath {
    NSString *encryptedString = nil;  // 暗号化された文字列
    
    SecKeyRef publicKeyRef = [self loadPublicKey:keyPath];
    if (!publicKeyRef) {
        return nil;  // ファイルが無いか、その他のエラー
    }
    NSLog(@"SecKeyGetBlockSize() private = %lu", SecKeyGetBlockSize(publicKeyRef));
    
    /* 暗号化実行 */
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKeyRef);
    uint8_t *cipherBuffer = (uint8_t *)malloc(cipherBufferSize);
    OSStatus status = SecKeyEncrypt(publicKeyRef,
                                    kSecPaddingPKCS1,
                                    (const uint8_t *)[plainText UTF8String],
                                    [plainText length],
                                    cipherBuffer,
                                    &cipherBufferSize);
    NSLog(@"encryption result code: %ld (size: %lu)", status, cipherBufferSize);
    if (status != errSecSuccess)
    {
        NSLog(@"failed to SecKeyEncrypt(): keyPath=%@", keyPath);
    } else {
        /* 16進数のバイナリ文字列に変換 */
        encryptedString = [self asHex:cipherBuffer size:cipherBufferSize];
    }
    
    /* 使用済み変数のリリース */
    if (publicKeyRef) {
        CFRelease(publicKeyRef);
    }
    free(cipherBuffer);
    
    return encryptedString;
}

/**
 * 指定された暗号文字列を復号化する
 */
- (NSString *)decryptString:(NSString *)encryptedText
             withPrivateKey:(NSString *)keyPath
               withPassword:(NSString *)password {
    NSString *decryptedString = nil;  // 復号化された文字列
    
    SecKeyRef privateKeyRef = [self loadPrivateKey:keyPath withPassword:password];
    if (!privateKeyRef) {
        return nil;  // ファイルが無いか、その他のエラー
    }
    NSLog(@"SecKeyGetBlockSize() private = %lu", SecKeyGetBlockSize(privateKeyRef));
    
    /* 復号化実行 */
    /* 16進数のバイナリ文字列から変換 */
    NSData *encryptedData = [self asData:encryptedText];
    size_t plainBufferSize = SecKeyGetBlockSize(privateKeyRef);
    uint8_t *plainBuffer = (uint8_t *)malloc(plainBufferSize);
    OSStatus status = SecKeyDecrypt(privateKeyRef,
                                    kSecPaddingPKCS1,
                                    (const uint8_t *)[encryptedData bytes],
                                    [encryptedData length],
                                    plainBuffer,
                                    &plainBufferSize);
    NSLog(@"decryption result code: %ld (size: %lu)", status, plainBufferSize);
    if (status != errSecSuccess)
    {
        NSLog(@"failed to SecKeyDecrypt(): keyPath=%@", keyPath);
    } else {
        decryptedString = [[NSString alloc] initWithBytes:plainBuffer
                                                             length:plainBufferSize
                                                           encoding:NSASCIIStringEncoding];
    }
    
    /* 使用済み変数のリリース */
    if (privateKeyRef) {
        CFRelease(privateKeyRef);
    }
    free(plainBuffer);

    return decryptedString;
}

/********************************************************************************/
#pragma mark -
#pragma mark Private methods
/********************************************************************************/

/*
 * 指定されたパスから公開鍵を読み込む
 *
 * @param keyPath 公開鍵のパス
 * @return 公開鍵へのリファレンス
 */
- (SecKeyRef)loadPublicKey:(NSString *)keyPath {
    if (![[NSFileManager defaultManager] fileExistsAtPath:keyPath]) {
        return nil;  // ファイルが存在しない
    }
    NSData *certData = [NSData dataWithContentsOfFile:keyPath];
    SecCertificateRef certRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData);
    
    // 面倒だが、SecTrustCreateWithCertificates の第一引数は CFArrayRef
    SecCertificateRef certArray[1] = {certRef};
    CFArrayRef certArrayRef = CFArrayCreate(NULL, (void *)certArray, 1, NULL);
    
    SecKeyRef publicKeyRef = NULL;
    SecPolicyRef policyRef = SecPolicyCreateBasicX509();
    SecTrustRef trustRef = NULL;
    OSStatus status = SecTrustCreateWithCertificates(certArrayRef, policyRef, &trustRef);
    if (status == errSecSuccess)
    {
        SecTrustResultType trustResultType;
        status = SecTrustEvaluate(trustRef, &trustResultType);
        if (status == errSecSuccess)
        {
            publicKeyRef = SecTrustCopyPublicKey(trustRef);
            if (!publicKeyRef) {
                NSLog(@"failed to SecTrustCopyPublicKey(): keyPath=%@", keyPath);
            }
        } else {
            NSLog(@"failed to SecTrustEvaluate(): keyPath=%@", keyPath);
        }
    } else {
        NSLog(@"failed to SecTrustCreateWithCertificates(): keyPath=%@", keyPath);
    }
    
    /* 使用済み変数のリリース */
    if (certRef) {
        CFRelease(certRef);
    }
    if (certArrayRef) {
        CFRelease(certArrayRef);
    }
    if (policyRef) {
        CFRelease(policyRef);
    }
    if (trustRef) {
        CFRelease(trustRef);
    }
    
    return publicKeyRef;
}

/*
 * 指定されたパスから秘密鍵を読み込む
 *
 * @param keyPath 秘密鍵のパス
 * @param password 秘密鍵にかけてあるパスワードの文字列
 * @return 秘密鍵へのリファレンス
 */
- (SecKeyRef)loadPrivateKey:(NSString *)keyPath withPassword:(NSString *)password {
    if (![[NSFileManager defaultManager] fileExistsAtPath:keyPath]) {
        return nil;  // ファイルが存在しない
    }
    NSData *p12Data = [NSData dataWithContentsOfFile:keyPath];
    
    SecKeyRef privateKeyRef = NULL;
    SecIdentityRef identityRef = NULL;
    SecTrustRef trustRef = NULL;
    // 必要な情報を取得
    OSStatus status = extractIdentityAndTrust((__bridge CFDataRef)p12Data,
                                              &identityRef,
                                              &trustRef,
                                              (__bridge CFStringRef)password);
    if (status == errSecSuccess) {
        SecTrustResultType trustResultType;
        status = SecTrustEvaluate(trustRef, &trustResultType);
        if (status == errSecSuccess)
        {
            status = SecIdentityCopyPrivateKey(identityRef, &privateKeyRef);
            if (status != errSecSuccess) {
                NSLog(@"failed to SecIdentityCopyPrivateKey(): keyPath=%@, password=%@", keyPath, password);
            }
        } else
        {
            NSLog(@"failed to SecTrustEvaluate(): keyPath=%@, password=%@", keyPath, password);
        }
    } else {
        NSLog(@"failed to extractIdentityAndTrust(): keyPath=%@, password=%@", keyPath, password);
    }
    
    /* 使用済み変数のリリース */
    if (identityRef) {
        CFRelease(identityRef);
    }
    if (trustRef) {
        CFRelease(trustRef);
    }
    
    return privateKeyRef;
}

/*
 * p12ファイルを分離して、必要なデータを取り出す
 * 下記リファレンスから引用
 * http://developer.apple.com/library/ios/#DOCUMENTATION/Security/Conceptual/CertKeyTrustProgGuide/iPhone_Tasks/iPhone_Tasks.html#//apple_ref/doc/uid/TP40001358-CH208-SW13
 */
OSStatus extractIdentityAndTrust(CFDataRef inPKCS12Data, SecIdentityRef *outIdentity, SecTrustRef *outTrust, CFStringRef keyPassword) {
    OSStatus securityError = errSecSuccess;
    
    const void *keys[] = {kSecImportExportPassphrase};
    const void *values[] = {keyPassword};
    CFDictionaryRef optionsDictionary = NULL;
    
    /* Create a dictionary containing the passphrase if one
     was specified.  Otherwise, create an empty dictionary. */
    optionsDictionary = CFDictionaryCreate(NULL, keys,
                                           values, (keyPassword ? 1 : 0),
                                           NULL, NULL);
    
    CFArrayRef items = NULL;
    securityError = SecPKCS12Import(inPKCS12Data,
                                    optionsDictionary,
                                    &items);
    
    if (securityError == 0) {
        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemIdentity);
        CFRetain(tempIdentity);
        *outIdentity = (SecIdentityRef)tempIdentity;
        const void *tempTrust = NULL;
        tempTrust = CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemTrust);
        
        CFRetain(tempTrust);
        *outTrust = (SecTrustRef)tempTrust;
    }
    
    if (optionsDictionary) {
        CFRelease(optionsDictionary);
    }
    if (items) {
        CFRelease(items);
    }
    
    return securityError;
}

/*
 * Android版で利用している下記のURLでバイナリを文字列に変換していたので、iOS版も同じ手法で変換
 * http://49.212.136.83/svn/android_common/android_common_library_v2/src/jp/co/common/android/libs/CryptUtils.java
 *
 * @param bytes 変換前のバイナリ
 * @param bufSize バイナリ配列のサイズ
 * @return 97('a') => @"61"
 */
- (NSString *)asHex:(const uint8_t *)bytes size:(size_t)bufSize
{
    NSMutableString *hexStr = [NSMutableString string];
    
    for (int index = 0; index < bufSize; index++) {
        int bt = bytes[index] & 0xff;
        [hexStr appendFormat:@"%02X", bt];
    }
    return hexStr;
}

/*
 * asHexで変換した文字列をバイナリに戻す
 *
 * @note サービスで使われることを想定していないため脆弱です
 * @param hexString バイナリ文字列
 * @return @"61" => 97('a')
 */
- (NSData *)asData:(NSString *)hexString
{
    NSMutableData *bytes = [NSMutableData data];
    
    int i = 0, hexLength = [hexString length];
    NSString *hexChar = nil;
    int hexValue = 0;
    while (i < hexLength)
    {
        hexChar = [hexString substringWithRange:NSMakeRange(i, 2)];
        sscanf([hexChar cStringUsingEncoding:NSASCIIStringEncoding], "%X", &hexValue);
        uint8_t data = (uint8_t)hexValue;
        [bytes appendBytes:&data length:sizeof(data)];
        i += 2;
    }
    return bytes;
}

@end
