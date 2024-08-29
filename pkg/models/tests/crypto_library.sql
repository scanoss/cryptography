DROP TABLE IF EXISTS EC_Component;
CREATE TABLE EC_Component (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    url TEXT NOT NULL,
    category TEXT NOT NULL,
    purl TEXT NOT NULL
);
INSERT INTO EC_Component (id, name, description, url, category, purl) VALUES
('library/openssl', 'OpenSSL', 'A robust, full-featured open-source toolkit implementing the Secure Sockets Layer (SSL) and Transport Layer Security (TLS) protocols.', 'https://www.openssl.org/docs/', 'library', 'pkg:github/openssl/openssl'),
('library/bouncycastle', 'BouncyCastle', 'A collection of APIs used in cryptography, including lightweight cryptography for Java and C#.', 'https://www.bouncycastle.org/documentation.html', 'library', 'pkg:github/bouncycastle/bc-java'),
('library/libsodium', 'libsodium', 'A modern, easy-to-use software library for encryption, decryption, signatures, password hashing, and more.', 'https://libsodium.gitbook.io/doc/', 'library', 'pkg:github/jedisct1/libsodium'),
('package/pycryptodome', 'PyCryptodome', 'A self-contained Python package of low-level cryptographic primitives.', 'https://pycryptodome.readthedocs.io/en/latest/', 'package', 'pkg:github/Legrandin/pycryptodome'),
('library/cryptography', 'Cryptography (Python package)', 'A Python library providing cryptographic recipes and primitives to developers.', 'https://cryptography.io/en/latest/', 'library', 'pkg:pypi/cryptography'),
('library/nacl', 'NaCl (Networking and Cryptography Library)', 'A high-speed software library for network communication, encryption, decryption, signatures, etc.', 'https://nacl.cr.yp.to/', 'library', 'pkg:github/dedis/nacl'),
('sdk/awskms', 'AWS Key Management Service (KMS)', 'A managed service that makes it easy to create and control the encryption keys used to encrypt your data.', 'https://docs.aws.amazon.com/kms/latest/developerguide/overview.html', 'sdk', 'pkg:aws/kms'),
('library/googletink', 'Google Tink', 'A multi-language, cross-platform library that provides cryptographic APIs that are secure, easy to use correctly, and hard(er) to misuse.', 'https://developers.google.com/tink', 'library', 'pkg:github/google/tink'),
('sdk/microsoftcng', 'Microsoft Cryptography Next Generation (CNG)', 'A suite of cryptographic APIs that are part of the Windows operating system, used to perform cryptographic operations.', 'https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal', 'sdk', 'pkg:github/microsoft/CNG'),
('framework/javajca-jce', 'Java Cryptography Architecture/Java Cryptography Extension (JCA/JCE)', 'A framework for accessing and developing cryptographic functionality for the Java platform.', 'https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html', 'framework', 'pkg:github/oracle/jdk8u'),
('protocol/openssl', 'OpenSSL', 'OpenSSL is a robust, full-featured implementation of the SSL (Secure Sockets Layer) and TLS (Transport Layer Security) protocols used to secure network communications.', 'https://www.openssl.org/docs/', 'protocol', 'pkg:github/openssl/openssl'),
('protocol/libressl', 'LibreSSL', 'LibreSSL is a fork of OpenSSL developed by the OpenBSD project, aimed at modernizing and simplifying the codebase to improve security.', 'https://www.libressl.org/', 'protocol', 'pkg:github/libressl-portable/portable'),
('protocol/gnutls', 'GnuTLS', 'GnuTLS is an implementation of the SSL, TLS, and DTLS protocols that is compatible with various operating systems. It is part of the GNU project.', 'https://www.gnutls.org/documentation.html', 'protocol', 'pkg:github/gnutls/gnutls'),
('protocol/boringssl', 'BoringSSL', 'BoringSSL is a fork of OpenSSL maintained by Google, designed for internal use in Google products and as a resource for developers looking for a simplified TLS implementation.', 'https://boringssl.googlesource.com/boringssl/', 'protocol', 'pkg:github/google/boringssl'),
('protocol/wolfssl', 'WolfSSL', 'WolfSSL is a lightweight, open-source SSL/TLS library designed for resource-constrained environments such as embedded devices.', 'https://www.wolfssl.com/docs/', 'protocol', 'pkg:github/wolfSSL/wolfssl'),
('package/paramiko', 'Paramiko', 'Paramiko is a pure-Python (3.6+) implementation of the SSHv2 protocol, providing both client and server functionality.', 'paramiko.org', 'package', 'pkg:github/paramiko/paramiko');
