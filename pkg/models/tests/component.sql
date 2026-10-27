-- Test data only. The schema comes from testSchemaDDL in pkg/models/test_schema.go; do not add DDL here.
-- Serving `component`: the resolver's entry point, replacing the mining
-- all_urls/mines/versions lookup. source_purl_id links a package to the repository
-- it was built from, which is the link the source-purl fallback follows.
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:gem/tablestyle', NULL, NULL, 'bb7b1725-5229-54b2-949f-66143ae3e340', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/pineappleea/pineapple-src', NULL, NULL, '018327fd-8993-5c93-a7eb-3320b845a4d5', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/scanoss/dependencies', NULL, NULL, '8cdab3da-376b-58d3-9a95-6f62ae2564da', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/scanoss/engine', NULL, NULL, 'b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:maven/org.bouncycastle/bcutil-lts8on', NULL, NULL, '125dcee9-be49-581c-b21a-a1eab867707c', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/abort-controller', NULL, NULL, '054c2529-778c-5e3a-bc9a-6eae003f417d', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/chart.js', NULL, NULL, '38b06139-f0ec-50cf-b3c3-c17185b92c8a', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/electron-debug', NULL, NULL, '67f29a3b-d899-5d68-a154-2d634b2ce791', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/electron-log', NULL, NULL, 'eeb3d635-3ea9-5102-a0ff-6a3ce0aa0b9f', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/electron-updater', NULL, NULL, 'ffb62692-da93-59c5-93c9-a0a56dc1768a', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/form-data', NULL, NULL, 'c6527752-fb08-5482-b1c6-11969cbebde6', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/history', NULL, NULL, 'f8729c3b-d95c-58a9-928e-18832c8e393c', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/isbinaryfile', NULL, NULL, '288541b4-61cb-5ef3-94b6-4a0dc9e0ad1d', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/node-blob', NULL, NULL, '6620f01a-cde0-5943-b151-3cffd66a9e15', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/node-fetch', NULL, NULL, '0732215f-a6f9-5478-a9e6-dacd5e76e3dd', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/p-queue', NULL, NULL, '3e0374eb-7ce7-5fc3-84bf-6320541903f0', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/react', NULL, NULL, '9d07eb3b-ee90-57a8-ad82-cfc882cd751a', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/react-checkbox-tree', NULL, NULL, 'd2972898-c0db-52ad-b9aa-ebb64ce31c34', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/react-dom', NULL, NULL, '7bffd266-035e-5371-9324-68def4caf86d', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/react-router-dom', NULL, NULL, '8336afea-5a57-5781-b45d-e3dbbb8118b4', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/react-split-pane', NULL, NULL, '5eaa2428-a310-526d-9752-d4330a91475b', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/react-syntax-highlighter', NULL, NULL, 'a08fdc76-17d0-5e48-9944-b33a0b8243e2', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/regenerator-runtime', NULL, NULL, '047936bf-872b-5cea-af3c-16294f832fc5', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/sort-paths', NULL, NULL, 'ad2f480a-6b0b-59c3-aa4d-24e5b10d5a73', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/source-map-support', NULL, NULL, 'aad1b172-b655-5115-8ddd-3ba14e80f55e', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/uuid', NULL, NULL, '590b46af-0aa0-51ac-93c2-09e224d28d3c', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:pypi/binaryornot', NULL, NULL, 'dbe40650-dbfb-5859-a975-2697e373025e', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:pypi/crc32c', NULL, NULL, '40ab20c6-aece-5364-b388-5d83d4185945', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:pypi/grpcio', NULL, NULL, '83707358-ce45-54e9-8be6-cd5a9c319759', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:pypi/progress', NULL, NULL, 'ad959a36-6c10-5528-ad43-d59bd4007430', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:pypi/protobuf', NULL, NULL, '895a17a0-80a1-5f34-ac4e-9a3ae1a215f8', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:pypi/requests', NULL, NULL, 'b2612508-69f0-5763-aca7-6c87ba8563a9', NULL);
