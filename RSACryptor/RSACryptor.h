//
//  RSACryptor.h
//  RSACryptor
//
//  Created by UQ Times on 13/03/05.
//  Copyright (c) 2013年 UQ Times. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSACryptor : NSObject

/**
 * 指定された平文を暗号化する
 *
 * @param plainText  暗号化前の平文
 * @param keyPath  公開鍵へのパス
 * @return  暗号化された文字列
 */
- (NSString *)encryptString:(NSString *)plainText withPublicKey:(NSString *)keyPath;

/**
 * 指定された暗号文字列を復号化する
 *
 * @note  テスト用であり、サービスで使われることは想定していません
 * @param encryptedText  暗号文字列
 * @param keyPath  秘密鍵へのパス
 * @param password  秘密鍵にかけられたパスワード文字列
 * @return  復号化された文字列
 */
- (NSString *)decryptString:(NSString *)encryptedText withPrivateKey:(NSString *)keyPath withPassword:(NSString *)password;

@end
