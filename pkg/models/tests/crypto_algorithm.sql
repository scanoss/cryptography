-- Test data only. The schema comes from testSchemaDDL in pkg/models/test_schema.go; do not add DDL here.
-- Serving `crypto_algorithm`: the algorithm catalogue component_version_crypto
-- references. `id` is the short name the API emits ("aes"); `name` is the long
-- description, which the API does not emit. `strength` is stored, not derived.
--
-- These rows are copied from production, so a test asserting on "aes" asserts on
-- the same spelling and strength the service returns in the field.
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('3des', 'Triple Data Encryption Standard', 'Symmetric Encryption', '128', '3des');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('aes', 'Advanced Encryption Standard', 'Symmetric Encryption', '128-256', 'aes');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('blowfish', 'Blowfish Cipher', 'Symmetric Encryption', '320', 'blowfish');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('chacha20', 'ChaCha', 'Symmetric Encryption', '256', 'chacha');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('crc32', 'Cyclic Redundancy Check 32-bit', 'Polynomial Functions', '32', 'crc32');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('des', 'Data Encryption Standard', 'Symmetric Encryption', '168', 'des');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('elgamal', 'ElGamal', 'Asymmetric Encryption', '128', 'elgamal');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('fortuna', 'Fortuna', 'Random Number Generation', '64', 'fortuna');
-- hmac carries no strength in production: the column is empty, not absent.
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('hmac', 'Hash-based Message Authentication Codes', 'Symmetric Encryption', '', 'hmac');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('ice', 'Indispensable Cryptographic Engine', 'Symmetric Encryption', '128', 'ice');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('md5', 'MD5 Message-Digest Algorithm', 'Hash Functions', '128', 'md5');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('mdc2', 'MDC-2', 'Hash Functions', '128', 'mdc2');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('pbe', 'Password-Based Encryption', 'Key Derivation Functions', '128', 'pbe');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('rc4', 'RC4 Stream Cipher', 'Symmetric Encryption', '2048', 'rc4');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('rsa', 'Rivest, Shamir y Adleman encryption', 'Asymmetric Encryption', '128', 'rsa');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('sha1', 'Secure Hash Algorithm 1', 'Hash Functions', '160', 'sha1');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('sha2', 'Secure Hash Algorithm 2', 'Hash Functions', '224-512', 'sha2');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('sha3', 'Secure Hash Algorithm 3', 'Hash Functions', '224-512', 'sha3');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('srp', 'Secure Remote Password', 'Secure Protocols', '128', 'srp');
INSERT INTO crypto_algorithm (id, name, category, strength, spdx_id) VALUES ('ssha', 'Salted SHA', 'Hash Functions', '128', 'ssha');
