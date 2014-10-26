# 概要
iOS上で、公開鍵・秘密鍵を用いた暗号化・復号化の処理をするクラスです。
SecPKCS12Import() が4.3で動作しないので、検証中

# Androidとの違い
Android版では、下記のようなコマンドで作成した鍵を利用します。

	$ openssl genrsa -out private-key.pem 2048
	$ openssl rsa -in private-key.pem -pubout -out public-key.pem

しかし、iOS版では、上記ファイルをうまく扱うことができないため、下記のようにして鍵を生成します。
(もっと良い方法があるはずですが。。。)

	$ openssl genrsa -out private-key.pem 2048
	$ openssl req -new -key private-key.pem -out server.csr
	Country Name (2 letter code) [AU]:JP
	State or Province Name (full name) [Some-State]:Tokyo
	Locality Name (eg, city) []:Chiyoda-ku
	Organization Name (eg, company) [Internet Widgits Pty Ltd]:Individual
	Organizational Unit Name (eg, section) []:
	Common Name (eg, YOUR name) []:UQ Times
	Email Address []:uqtimes@gmail.com
	$ openssl x509 -req -days 3650 -in server.csr -signkey private-key.pem -out server.crt
	$ openssl x509 -in server.crt -inform PEM -out public-key.der -outform DER
	$ openssl pkcs12 -export -in server.crt -inkey private-key.pem -out private-key.p12

* 公開鍵: public-key.der
* 秘密鍵: private-key.p12

# 異なっている理由と経緯
## 以下を試してみたが、Android版と同じ鍵を使うことができなかった
** (やり方が悪いだけであるかもしれません） **

### opensslのライブラリ
* 最もポピュラーでAndroid版と同じように動作した
* しかし、opensslライブラリの libcrypt.a が 2.4MBもあったため却下
* 日本語では、 http://www.moonxseed.com/2012/03/12/ios-%E7%94%A8-openssl-%E3%83%A9%E3%82%A4%E3%83%96%E3%83%A9%E3%83%AA%E3%81%AE%E4%BD%9C%E6%88%90/ が参考になる

### SecItemAdd(), SecItemCopyMatching()関数
* 以下の公式リファレンスに書かれている方法が良さそうであったが、利用するためには SecKeyGeneratePair() を使い、Keychain Service に鍵情報を登録する必要があった
   * http://developer.apple.com/library/ios/#DOCUMENTATION/Security/Conceptual/CertKeyTrustProgGuide/iPhone_Tasks/iPhone_Tasks.html#//apple_ref/doc/uid/TP40001358-CH208-SW13

* 次にサンプルコードの "CryptoExercise" を参考にして、手動で SecItemAdd => SecItemCopyMatching を実行したが、常に NULL が返り、正しい情報を取得することができなかった
   * 以下のURLの他、多くのフォーラムでも同様の問題が投稿されている
   * http://stackoverflow.com/questions/11301158/ios-keychain-issue-seckeyref-always-is-null-as-result-of-secitemcopymatching
   * 解決方法: 以下に書かれているような方法で、鍵のバイナリからヘッダ情報を取り除かなければならない模様 (stripPublicKeyHeader)
      * http://blog.flirble.org/2011/01/05/rsa-public-key-openssl-ios/

* なお、Android版と同じ鍵を使いたい場合、"-----BEGIN PUBLIC KEY-----" や "-----END PUBLIC KEY-----", "\n" を自分で取り除く必要がある

### RSAESCryptorライブラリ
* GitHub: https://github.com/bigsan/RSAESCryptor
* AES暗号を施すもので、今回の使い方にそぐわなかったが、最も参考になり、上記リファレンスとこちらのソースを参考にして、今回のクラスを実装した。
* iOS4.3では、SecPKCS12Importが正しく動作しない

