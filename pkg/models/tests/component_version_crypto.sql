-- Test data only. The schema comes from testSchemaDDL in pkg/models/test_schema.go; do not add DDL here.
-- Serving `component_version_crypto`: the algorithms detected in one version of
-- one component, keyed by (purl_id, version) where mining keyed by url_hash.
-- algorithm_id holds the algorithm's short name, which is crypto_algorithm.id.
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', 'v5.4.7', 'crc32');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', 'v5.4.7', 'des');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', 'v5.4.7', 'md5');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', 'v5.4.7', 'rsa');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', 'v5.4.6', 'crc32');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', 'v5.4.6', 'des');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', 'v5.4.6', 'md5');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', 'v5.4.6', 'rsa');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', 'v5.4.5', 'crc32');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', 'v5.4.5', 'des');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', 'v5.4.5', 'md5');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', 'v5.4.5', 'rsa');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', '5.2.4', 'md5');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', '5.2.4', 'sha2');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', '5.2.4', 'crc32');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('bb7b1725-5229-54b2-949f-66143ae3e340', '0.0.10', 'sha2');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('bb7b1725-5229-54b2-949f-66143ae3e340', '0.0.12', 'sha2');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('bb7b1725-5229-54b2-949f-66143ae3e340', '0.0.7', 'sha2');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('bb7b1725-5229-54b2-949f-66143ae3e340', '0.0.4', 'sha2');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('bb7b1725-5229-54b2-949f-66143ae3e340', '0.0.10', 'rsa');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('bb7b1725-5229-54b2-949f-66143ae3e340', '0.0.12', 'rsa');
INSERT INTO component_version_crypto (purl_id, version, algorithm_id) VALUES ('bb7b1725-5229-54b2-949f-66143ae3e340', '0.0.7', 'rsa');
