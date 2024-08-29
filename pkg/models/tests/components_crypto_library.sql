DROP TABLE IF EXISTS component_crypto_library;
CREATE TABLE component_crypto_library (
    url_hash TEXT  NOT NULL,
    detId TEXT NOT NULL);
    INSERT INTO component_crypto_library (url_hash,detId) VALUES 
    ('2c2ae45c192df28dcfd1caab7e2b12db','protocol/openssl')
,('2c2ae45c192df28dcfd1caab7e2b12db','library/cryptography')
,('2c2ae45c192df28dcfd1caab7e2b12db','library/cryptography')
,('2c2ae45c192df28dcfd1caab7e2b12db','sdk/microsoftcng')
,('541bae26cbf8e2d2f33d20cd22d435dd','framework/javajca-jce')
,('541bae26cbf8e2d2f33d20cd22d435dd','library/cryptography')
,('541bae26cbf8e2d2f33d20cd22d435dd','protocol/gnutls')
,('541bae26cbf8e2d2f33d20cd22d435dd','framework/javajca-jce')
,('57031cd9434a17cfc3a5b93af112592a','protocol/wolfssl')
,('57031cd9434a17cfc3a5b93af112592a','sdk/microsoftcng')
,('57031cd9434a17cfc3a5b93af112592a','sdk/microsoftcng')
,('57031cd9434a17cfc3a5b93af112592a','library/cryptography')
,('7774ed78584b719f076bb92aa42fbc7f', 'protocol/gnutls')
,('7774ed78584b719f076bb92aa42fbc7f', 'library/cryptography')
,('7774ed78584b719f076bb92aa42fbc7f', 'library/cryptography')
,('4d66775f503b1e76582e7e5b2ea54d92', 'protocol/libressl')
,('bfada11fd2b2b8fa23943b8b6fe5cb3f', 'protocol/libressl')