-- Test data only. The schema comes from testSchemaDDL in pkg/models/test_schema.go; do not add DDL here.
-- Serving `component_version_crypto_library`, keyed by (purl_id, version).
INSERT INTO component_version_crypto_library (library_id, purl_id, version) VALUES ('library/boringssl', '018327fd-8993-5c93-a7eb-3320b845a4d5', 'v5.4.7');
INSERT INTO component_version_crypto_library (library_id, purl_id, version) VALUES ('library/openssl', '018327fd-8993-5c93-a7eb-3320b845a4d5', 'v5.4.7');
INSERT INTO component_version_crypto_library (library_id, purl_id, version) VALUES ('library/wolfssl', '018327fd-8993-5c93-a7eb-3320b845a4d5', 'v5.4.7');
INSERT INTO component_version_crypto_library (library_id, purl_id, version) VALUES ('protocol/dtls', '018327fd-8993-5c93-a7eb-3320b845a4d5', 'v5.4.7');
INSERT INTO component_version_crypto_library (library_id, purl_id, version) VALUES ('protocol/https', '018327fd-8993-5c93-a7eb-3320b845a4d5', 'v5.4.7');
INSERT INTO component_version_crypto_library (library_id, purl_id, version) VALUES ('protocol/ssl', '018327fd-8993-5c93-a7eb-3320b845a4d5', 'v5.4.7');
INSERT INTO component_version_crypto_library (library_id, purl_id, version) VALUES ('protocol/tls', '018327fd-8993-5c93-a7eb-3320b845a4d5', 'v5.4.7');
INSERT INTO component_version_crypto_library (library_id, purl_id, version) VALUES ('sdk/microsoftcng', '018327fd-8993-5c93-a7eb-3320b845a4d5', 'v5.4.7');
