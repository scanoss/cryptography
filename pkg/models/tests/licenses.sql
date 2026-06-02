DROP TABLE IF EXISTS licenses;
CREATE TABLE licenses
(
    id           integer primary key,
    license_name text,
    spdx_id      text,
    is_spdx      integer
);

INSERT INTO licenses (id, license_name, spdx_id, is_spdx) values (83, 'GPL-2.0-only', 'GPL-2.0-only', 1);
INSERT INTO licenses (id, license_name, spdx_id, is_spdx) values (2815, 'GPL-2.0-only', 'GPL-2.0-only', 1);
INSERT INTO licenses (id, license_name, spdx_id, is_spdx) values (10684, 'Apache-2.0', 'Apache-2.0', 1);
