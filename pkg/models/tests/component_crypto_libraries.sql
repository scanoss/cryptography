CREATE TABLE component_crypto_library (
    url_hash TEXT  NOT NULL,
    det_id TEXT NOT NULL);
CREATE INDEX idx_component_crypto_library ON component_crypto_library(url_hash);
INSERT INTO component_crypto_library VALUES('c8b5644375cfb4acd72dfc8ff458f7e3','protocol/https');
INSERT INTO component_crypto_library VALUES('c8b5644375cfb4acd72dfc8ff458f7e3','protocol/ssh');
INSERT INTO component_crypto_library VALUES('c8b5644375cfb4acd72dfc8ff458f7e3','protocol/tls');
INSERT INTO component_crypto_library VALUES('c8b5644375cfb4acd72dfc8ff458f7e3','sdk/awskms');
--pkg:github/pineappleea/pineapple-src
INSERT INTO component_crypto_library VALUES('c8b5647654826091fb65a97bec820eb9','library/boringssl');
INSERT INTO component_crypto_library VALUES('c8b5647654826091fb65a97bec820eb9','library/openssl');
INSERT INTO component_crypto_library VALUES('c8b5647654826091fb65a97bec820eb9','library/wolfssl');
INSERT INTO component_crypto_library VALUES('c8b5647654826091fb65a97bec820eb9','protocol/dtls');
INSERT INTO component_crypto_library VALUES('c8b5647654826091fb65a97bec820eb9','protocol/https');
INSERT INTO component_crypto_library VALUES('c8b5647654826091fb65a97bec820eb9','protocol/ssl');
INSERT INTO component_crypto_library VALUES('c8b5647654826091fb65a97bec820eb9','protocol/tls');
--pkg:gitee/stonedb/stonedb
INSERT INTO component_crypto_library VALUES('c8b5647654826091fb65a97bec820eb9','sdk/microsoftcng');
INSERT INTO component_crypto_library VALUES('c8b56973c8b178b85f1768c5928a8a49','library/openssl');
INSERT INTO component_crypto_library VALUES('c8b56973c8b178b85f1768c5928a8a49','protocol/dtls');
INSERT INTO component_crypto_library VALUES('c8b56973c8b178b85f1768c5928a8a49','protocol/ssl');
INSERT INTO component_crypto_library VALUES('c8b56973c8b178b85f1768c5928a8a49','protocol/tls');
--pkg:github/code-dot-org/code-dot-org
INSERT INTO component_crypto_library VALUES('c8b569083fe8d7b94ad429c445800253','protocol/https');
INSERT INTO component_crypto_library VALUES('c8b569083fe8d7b94ad429c445800253','protocol/ssl');
INSERT INTO component_crypto_library VALUES('c8b569083fe8d7b94ad429c445800253','sdk/awskms');

