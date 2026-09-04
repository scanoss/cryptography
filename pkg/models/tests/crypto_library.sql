-- Test data only. The schema comes from testSchemaDDL in pkg/models/test_schema.go; do not add DDL here.
-- Serving `crypto_library`, the renamed crypto_libraries.
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('library/boringssl', 'BoringSSL', 'https://boringssl.googlesource.com/boringssl/', 'pkg:googlesource/boringssl', 'library', 'BoringSSL is a cryptographic library forked from OpenSSL, designed by Google to meet their specific needs for speed, security, and maintainability.');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('library/paramiko', 'paramiko', 'https://www.paramiko.org/', 'pkg:github/paramiko/paramiko', 'library', 'Paramiko is a pure-Python 1 (3.6+) implementation of the SSHv2 protocol 2, providing both client and server functionality.');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('library/crypto++', 'Crypto++', 'https://cryptopp.com/', 'pkg:github/weidai11/cryptopp', 'library', 'Crypto++: free C++ Class Library of Cryptographic Schemes.');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('library/keyzcar', 'Keyzcar ', 'www.example.com', 'TBD', 'this_is_the_category', 'this_is_the_description');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('library/themis', 'Themis ', 'www.example.com', 'TBD', 'this_is_the_category', 'this_is_the_description');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('library/spongy-castle', 'pongy Castle (Android)', 'www.example.com', 'TBD', 'this_is_the_category', 'this_is_the_description');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('library/chilkat', 'Chilkat', 'www.example.com', 'TBD', 'this_is_the_category', 'this_is_the_description');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('protocol/ssl', 'Secure Sockets Layer', 'TBD', 'TBD', 'protocol', 'TBD');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('protocol/tls', 'TLS', 'TBD', 'TBD', 'protocol', '');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('protocol/https', 'HTTPS', 'tbd', '', 'library', 'TBD');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('protocol/dtls', 'DTLS', 'TBD', '', 'protocol', '');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('protocol/quic', ' ', ' ', 'TBD', 'protocol', '');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('protocol/zrtp', 'ZRTP', ' ', 'TBD', 'protocol', '');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('protocol/bitmessage', 'Bitmessage', 'www.example.com', 'TBD', 'this_is_the_category', 'this_is_the_description');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('protocol/ssh', 'SSH', 'www.example.com', 'TBD', 'this_is_the_category', 'Secure shell');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('protocol/scp', 'Secure Copy Protocol', 'www.example.com', 'TBD', 'this_is_the_category', 'this_is_the_description');
INSERT INTO crypto_library (id, name, url, purl, category, description) VALUES ('protocol/sftp', 'SFTP', 'www.example.com', 'TBD', 'this_is_the_category', 'this_is_the_description');
