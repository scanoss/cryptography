-- Test data only. The schema comes from testSchemaDDL in pkg/models/test_schema.go; do not add DDL here.
-- Serving `SPDX_crypto_algorithm`: the key sizes strength is derived from.
-- A single-value strength is stored as commonkeySize alone; a range as the
-- commonkeySize/specifiedkeySize_max pair.
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (1, 'CRC32', '32', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (2, 'CRC64', '64', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (3, 'MD5', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (4, 'MDC2', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (5, 'RSA', '32', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (6, 'SHA1', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (7, 'SHA256', '32', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (8, 'SHAx', '512', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (9, 'SRP', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (10, 'SSHA', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (11, 'blowfish', '320', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (12, 'chacha(salsa)', '256', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (13, 'crc32', '32', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (14, 'des', '168', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (15, 'elgamal', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (16, 'fortuna', '64', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (17, 'ice', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (18, 'md5', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (19, 'mdc2', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (20, 'pbe', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (21, 'rc4', '2048', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (22, 'rsa', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (23, 'rsa-oaep', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (24, 'sha1', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (25, 'shax', '512', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (26, 'srp', '128', NULL);
INSERT INTO SPDX_crypto_algorithm (id, name, commonkeySize, specifiedkeySize_max) VALUES (27, 'ssha', '128', NULL);
