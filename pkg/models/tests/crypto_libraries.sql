CREATE TABLE crypto_libraries (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    url TEXT NOT NULL,
    category TEXT NOT NULL,
    purl TEXT NOT NULL
);
INSERT INTO crypto_libraries VALUES('library/boringssl','BoringSSL','BoringSSL is a cryptographic library forked from OpenSSL, designed by Google to meet their specific needs for speed, security, and maintainability.','https://boringssl.googlesource.com/boringssl/','library','pkg:googlesource/boringssl');
INSERT INTO crypto_libraries VALUES('library/paramiko','paramiko','Paramiko is a pure-Python 1 (3.6+) implementation of the SSHv2 protocol 2, providing both client and server functionality.','https://www.paramiko.org/','library','pkg:github/paramiko/paramiko');
INSERT INTO crypto_libraries VALUES('library/crypto++','Crypto++','Crypto++: free C++ Class Library of Cryptographic Schemes.','https://cryptopp.com/','library','pkg:github/weidai11/cryptopp');
INSERT INTO crypto_libraries VALUES('library/keyzcar','Keyzcar ','this_is_the_description','www.example.com','this_is_the_category','TBD');
INSERT INTO crypto_libraries VALUES('library/themis','Themis ','this_is_the_description','www.example.com','this_is_the_category','TBD');
INSERT INTO crypto_libraries VALUES('library/spongy-castle','pongy Castle (Android)','this_is_the_description','www.example.com','this_is_the_category','TBD');
INSERT INTO crypto_libraries VALUES('library/chilkat','Chilkat','this_is_the_description','www.example.com','this_is_the_category','TBD');
INSERT INTO crypto_libraries VALUES('protocol/ssl','Secure Sockets Layer','TBD','TBD','protocol','TBD');
INSERT INTO crypto_libraries VALUES('protocol/tls','TLS','','TBD','protocol','TBD');
INSERT INTO crypto_libraries VALUES('protocol/https','HTTPS','TBD','tbd','library','');
INSERT INTO crypto_libraries VALUES('protocol/dtls','DTLS','','TBD','protocol','');
INSERT INTO crypto_libraries VALUES('protocol/quic',' ','',' ','protocol','TBD');
INSERT INTO crypto_libraries VALUES('protocol/zrtp','ZRTP','',' ','protocol','TBD');
INSERT INTO crypto_libraries VALUES('protocol/bitmessage','Bitmessage','this_is_the_description','www.example.com','this_is_the_category','TBD');
INSERT INTO crypto_libraries VALUES('protocol/ssh','SSH','Secure shell','www.example.com','this_is_the_category','TBD');
INSERT INTO crypto_libraries VALUES('protocol/scp','Secure Copy Protocol','this_is_the_description','www.example.com','this_is_the_category','TBD');
INSERT INTO crypto_libraries VALUES('protocol/sftp','SFTP','this_is_the_description','www.example.com','this_is_the_category','TBD');
