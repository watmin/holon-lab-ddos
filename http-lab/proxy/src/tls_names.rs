//! Human-readable names for TLS numeric identifiers from IANA registries.
//!
//! Covers cipher suites, extensions, named groups, signature algorithms,
//! TLS versions, EC point formats, PSK modes, and certificate compression.
//! Lookup functions return the IANA name or fall back to hex notation.

pub fn cipher_suite_name(id: u16) -> &'static str {
    match id {
        // TLS 1.3
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",

        // ECDHE+AESGCM
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",

        // ECDHE+CBC
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xc027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",

        // ChaCha20-Poly1305
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xccaa => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",

        // RSA
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",

        // DHE
        0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0067 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        0x006b => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",

        // Legacy / weak (interesting as anomaly signals)
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        0xc011 => "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        0x00ff => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        0x5600 => "TLS_FALLBACK_SCSV",

        // GREASE values
        0x0a0a | 0x1a1a | 0x2a2a | 0x3a3a | 0x4a4a |
        0x5a5a | 0x6a6a | 0x7a7a | 0x8a8a | 0x9a9a |
        0xaaaa | 0xbaba | 0xcaca | 0xdada | 0xeaea | 0xfafa => "GREASE",

        _ => return_hex_leak(id),
    }
}

pub fn extension_name(id: u16) -> &'static str {
    match id {
        0x0000 => "server_name",
        0x0001 => "max_fragment_length",
        0x0002 => "client_certificate_url",
        0x0003 => "trusted_ca_keys",
        0x0004 => "truncated_hmac",
        0x0005 => "status_request",
        0x0006 => "user_mapping",
        0x0007 => "client_authz",
        0x0008 => "server_authz",
        0x0009 => "cert_type",
        0x000a => "supported_groups",
        0x000b => "ec_point_formats",
        0x000c => "srp",
        0x000d => "signature_algorithms",
        0x000e => "use_srtp",
        0x000f => "heartbeat",
        0x0010 => "application_layer_protocol_negotiation",
        0x0011 => "status_request_v2",
        0x0012 => "signed_certificate_timestamp",
        0x0013 => "client_certificate_type",
        0x0014 => "server_certificate_type",
        0x0015 => "padding",
        0x0016 => "encrypt_then_mac",
        0x0017 => "extended_main_secret",
        0x001b => "compress_certificate",
        0x001c => "record_size_limit",
        0x0022 => "delegated_credential",
        0x0023 => "session_ticket",
        0x0029 => "pre_shared_key",
        0x002a => "early_data",
        0x002b => "supported_versions",
        0x002c => "cookie",
        0x002d => "psk_key_exchange_modes",
        0x002f => "certificate_authorities",
        0x0030 => "oid_filters",
        0x0031 => "post_handshake_auth",
        0x0032 => "signature_algorithms_cert",
        0x0033 => "key_share",
        0x0039 => "quic_transport_parameters",
        0x4469 => "application_settings",
        0xff01 => "renegotiation_info",

        // GREASE
        0x0a0a | 0x1a1a | 0x2a2a | 0x3a3a | 0x4a4a |
        0x5a5a | 0x6a6a | 0x7a7a | 0x8a8a | 0x9a9a |
        0xaaaa | 0xbaba | 0xcaca | 0xdada | 0xeaea | 0xfafa => "GREASE",

        _ => return_hex_leak(id),
    }
}

pub fn named_group_name(id: u16) -> &'static str {
    match id {
        // Elliptic curves
        0x0017 => "secp256r1",
        0x0018 => "secp384r1",
        0x0019 => "secp521r1",
        0x001d => "x25519",
        0x001e => "x448",

        // Finite field groups
        0x0100 => "ffdhe2048",
        0x0101 => "ffdhe3072",
        0x0102 => "ffdhe4096",
        0x0103 => "ffdhe6144",
        0x0104 => "ffdhe8192",

        // ML-KEM (post-quantum)
        0x0200 => "MLKEM512",
        0x0201 => "MLKEM768",
        0x0202 => "MLKEM1024",

        // Hybrid ECDH + ML-KEM
        0x11eb => "SecP256r1MLKEM768",
        0x11ec => "X25519MLKEM768",
        0x11ed => "SecP384r1MLKEM1024",

        // Obsolete Kyber drafts (still seen in the wild)
        0x6399 => "X25519Kyber768Draft00",
        0x639a => "SecP256r1Kyber768Draft00",

        // GREASE
        0x0a0a | 0x1a1a | 0x2a2a | 0x3a3a | 0x4a4a |
        0x5a5a | 0x6a6a | 0x7a7a | 0x8a8a | 0x9a9a |
        0xaaaa | 0xbaba | 0xcaca | 0xdada | 0xeaea | 0xfafa => "GREASE",

        _ => return_hex_leak(id),
    }
}

pub fn sig_alg_name(id: u16) -> &'static str {
    match id {
        // RSASSA-PKCS1-v1_5
        0x0201 => "rsa_pkcs1_sha1",
        0x0401 => "rsa_pkcs1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0601 => "rsa_pkcs1_sha512",

        // ECDSA
        0x0203 => "ecdsa_sha1",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0603 => "ecdsa_secp521r1_sha512",

        // RSASSA-PSS (rsae)
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",

        // Ed25519 / Ed448
        0x0807 => "ed25519",
        0x0808 => "ed448",

        // RSASSA-PSS (pss)
        0x0809 => "rsa_pss_pss_sha256",
        0x080a => "rsa_pss_pss_sha384",
        0x080b => "rsa_pss_pss_sha512",

        _ => return_hex_leak(id),
    }
}

pub fn tls_version_name(id: u16) -> &'static str {
    match id {
        0x0300 => "SSL3.0",
        0x0301 => "TLS1.0",
        0x0302 => "TLS1.1",
        0x0303 => "TLS1.2",
        0x0304 => "TLS1.3",

        // GREASE
        0x0a0a | 0x1a1a | 0x2a2a | 0x3a3a | 0x4a4a |
        0x5a5a | 0x6a6a | 0x7a7a | 0x8a8a | 0x9a9a |
        0xaaaa | 0xbaba | 0xcaca | 0xdada | 0xeaea | 0xfafa => "GREASE",

        _ => return_hex_leak(id),
    }
}

pub fn ec_point_format_name(id: u8) -> &'static str {
    match id {
        0x00 => "uncompressed",
        0x01 => "ansiX962_compressed_prime",
        0x02 => "ansiX962_compressed_char2",
        _ => "unknown",
    }
}

pub fn psk_mode_name(id: u8) -> &'static str {
    match id {
        0x00 => "psk_ke",
        0x01 => "psk_dhe_ke",
        _ => "unknown",
    }
}

pub fn compress_cert_name(id: u16) -> &'static str {
    match id {
        0x0001 => "zlib",
        0x0002 => "brotli",
        0x0003 => "zstd",
        _ => return_hex_leak(id),
    }
}

pub fn compression_method_name(id: u8) -> &'static str {
    match id {
        0x00 => "null",
        0x01 => "DEFLATE",
        0x40 => "LZS",
        _ => "unknown",
    }
}

/// For unknown codes, leak a formatted hex string so we can return &'static str.
/// This is fine — unknown TLS identifiers are rare and bounded.
fn return_hex_leak(id: u16) -> &'static str {
    Box::leak(format!("0x{:04x}", id).into_boxed_str())
}
