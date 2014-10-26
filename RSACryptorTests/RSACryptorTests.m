//
//  RSACryptorTests.m
//  RSACryptorTests
//
//  Created by UQ Times on 13/03/05.
//  Copyright (c) 2013年 UQ Times. All rights reserved.
//

#import "RSACryptorTests.h"
#import "RSACryptor.h"

@implementation RSACryptorTests

- (void)setUp
{
    [super setUp];
    
    // Set-up code here.
}

- (void)tearDown
{
    // Tear-down code here.
    
    [super tearDown];
}

- (void)testCrypt
{
    /* 公開鍵・秘密鍵のパス */
    NSString *publicKeyPath = [[NSBundle mainBundle] pathForResource:@"public-key" ofType:@"der"];
    NSString *privateKeyPath = [[NSBundle mainBundle] pathForResource:@"private-key" ofType:@"p12"];
    
    // 暗号化対象の文字列
    NSString *plainText = @"hogehoge: this is plain text.";
    
    RSACryptor *rsa = [[RSACryptor alloc] init];
    // 公開鍵を使った暗号化
    NSString *encryptedString = [rsa encryptString:plainText withPublicKey:publicKeyPath];
    NSLog(@"encryptedString:%@", encryptedString);
    // 秘密鍵を使った復号化 (サンプルのp12ファイルにパスワードはかけていない)
    NSString *decryptedString = [rsa decryptString:encryptedString withPrivateKey:privateKeyPath withPassword:@""];
    NSLog(@"decryptedString:%@", decryptedString);
    
    STAssertTrue([plainText isEqualToString:decryptedString], @"testCrypt failed.");
}

@end
