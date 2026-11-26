//! Test vectors: RFC 9605 Appendix C.2 and C.3, and RFC 10079 Appendix A.2 for the three
//! AES-256-CTR suites. (RFC 10079 Appendix A.1 announces vectors of the AEAD on its own; the RFC
//! and the JSON file it cites give none.)

use crate::CipherSuite;

/// One case of RFC 9605 Appendix C.2: the AES-CTR with HMAC construction on its own.
pub(crate) struct AeadVector {
    pub(crate) suite: CipherSuite,
    pub(crate) key: &'static str,
    pub(crate) nonce: &'static str,
    pub(crate) aad: &'static str,
    pub(crate) pt: &'static str,
    pub(crate) ct: &'static str,
}

const C2_KEY: &str = "000102030405060708090a0b0c0d0e0f
                      101112131415161718191a1b1c1d1e1f
                      202122232425262728292a2b2c2d2e2f";
const C2_NONCE: &str = "101112131415161718191a1b";
/// "IETF SFrame WG"
const AAD: &str = "4945544620534672616d65205747";
/// "draft-ietf-sframe-enc"
const PT: &str = "64726166742d696574662d736672616d652d656e63";

pub(crate) const RFC9605_C2: &[AeadVector] = &[
    AeadVector {
        suite: CipherSuite::Aes128CtrHmacSha256_80,
        key: C2_KEY,
        nonce: C2_NONCE,
        aad: AAD,
        pt: PT,
        ct: "6339af04ada1d064688a442b8dc69d5b
             6bfa40f4bef0583e8081069cc60705",
    },
    AeadVector {
        suite: CipherSuite::Aes128CtrHmacSha256_64,
        key: C2_KEY,
        nonce: C2_NONCE,
        aad: AAD,
        pt: PT,
        ct: "6339af04ada1d064688a442b8dc69d5b
             6bfa40f4be6e93b7da076927bb",
    },
    AeadVector {
        suite: CipherSuite::Aes128CtrHmacSha256_32,
        key: C2_KEY,
        nonce: C2_NONCE,
        aad: AAD,
        pt: PT,
        ct: "6339af04ada1d064688a442b8dc69d5b
             6bfa40f4be09480509",
    },
];

/// One case of RFC 9605 Appendix C.3: key derivation and a whole SFrame ciphertext.
pub(crate) struct SFrameVector {
    pub(crate) suite: CipherSuite,
    pub(crate) sframe_secret: &'static str,
    pub(crate) sframe_key: &'static str,
    pub(crate) sframe_salt: &'static str,
    pub(crate) ct: &'static str,
}

/// Common to every C.3 case.
pub(crate) const KID: u64 = 0x123;
pub(crate) const CTR: u64 = 0x4567;
pub(crate) const BASE_KEY: &str = "000102030405060708090a0b0c0d0e0f";
pub(crate) const METADATA: &str = AAD;
pub(crate) const PLAINTEXT: &str = PT;

const SECRET_SHA256: &str = "d926952ca8b7ec4a95941d1ada3a5203
                             ceff8cceee34f574d23909eb314c40c0";
const SECRET_SHA512: &str = "0fc3ea6de6aac97a35f194cf9bed94d4
                             b5230f1cb45a785c9fe5dce9c188938a
                             b6ba005bc4c0a19181599e9d1bcf7b74
                             aca48b60bf5e254e546d809313e083a3";

/// RFC 9605 Appendix C.3, in the RFC's order.
pub(crate) const RFC9605_C3: &[SFrameVector] = &[
    SFrameVector {
        suite: CipherSuite::Aes128CtrHmacSha256_80,
        sframe_secret: SECRET_SHA256,
        sframe_key: "3f7d9a7c83ae8e1c8a11ae695ab59314
                     b367e359fadac7b9c46b2bc6f81f46e1
                     6b96f0811868d59402b7e870102720b3",
        sframe_salt: "50b29329a04dc0f184ac3168",
        ct: "9901234567449408b6f490086165b9d6
             f62b24ae1a59a56486b4ae8ed036b889
             12e24f11",
    },
    SFrameVector {
        suite: CipherSuite::Aes128CtrHmacSha256_64,
        sframe_secret: SECRET_SHA256,
        sframe_key: "e2ec5c797540310483b16bf6e7a570d2
                     a27d192fe869c7ccd8584a8d9dab9154
                     9fbe553f5113461ec6aa83bf3865553e",
        sframe_salt: "e68ac8dd3d02fbcd368c5577",
        ct: "99012345673f31438db4d09434e43afa
             0f8a2f00867a2be085046a9f5cb4f101
             d607",
    },
    SFrameVector {
        suite: CipherSuite::Aes128CtrHmacSha256_32,
        sframe_secret: SECRET_SHA256,
        sframe_key: "2c5703089cbb8c583475e4fc461d97d1
                     8809df79b6d550f78eb6d50ffa80d892
                     11d57909934f46f5405e38cd583c69fe",
        sframe_salt: "38c16e4f5159700c00c7f350",
        ct: "990123456717fc8af28a5a695afcfc6c
             8df6358a17e26b2fcb3bae32e443",
    },
    SFrameVector {
        suite: CipherSuite::Aes128GcmSha256_128,
        sframe_secret: SECRET_SHA256,
        sframe_key: "d34f547f4ca4f9a7447006fe7fcbf768",
        sframe_salt: "75234edefe07819026751816",
        ct: "9901234567b7412c2513a1b66dbb4884
             1bbaf17f598751176ad847681a69c6d0
             b091c07018ce4adb34eb",
    },
    SFrameVector {
        suite: CipherSuite::Aes256GcmSha512_128,
        sframe_secret: SECRET_SHA512,
        sframe_key: "d3e27b0d4a5ae9e55df01a70e6d4d28d
                     969b246e2936f4b7a5d9b494da6b9633",
        sframe_salt: "84991c167b8cd23c93708ec7",
        ct: "990123456794f509d36e9beacb0e261d
             99c7d1e972f1fed787d4049f17ca2135
             3c1cc24d56ceabced279",
    },
];

/// RFC 10079 Appendix A.2: the same inputs under the AES-256-CTR suites (byte for byte the
/// vectors of draft-barnes-sframe-iana-256 that were here before the RFC).
pub(crate) const AES_256_CTR: &[SFrameVector] = &[
    SFrameVector {
        suite: CipherSuite::Aes256CtrHmacSha512_80,
        sframe_secret: SECRET_SHA512,
        sframe_key: "3c343886ec1c79278836863e00fe934c
                     8894460cfa367ebdc4856b0a9268a4f4
                     fb99437876819394ef90b10ee12602d0
                     23f7128ee50f2314c2cc3cff4c56616d
                     2fe03ad2a254cc2ed29b2a4d3f2534c0
                     dda9e7c391ad1917ea07aa221dd4b224",
        sframe_salt: "e082f7ce012ad30c87c49e3f",
        ct: "9901234567b369e03ec6467ad505ddc8
             4914115069280c5c797555be6e32cde6
             ac25bc9e",
    },
    SFrameVector {
        suite: CipherSuite::Aes256CtrHmacSha512_64,
        sframe_secret: SECRET_SHA512,
        sframe_key: "7271d6c6cbccd2e2343d480ebea65718
                     a7bb379eefcf3f8d107c1e2a76e75529
                     3a497fd9e4e8291b965161987ef4ef24
                     983eabb06cb0a392defaab18654780a3
                     9c106ffa4a47d4183a6e593cd0c1bcab
                     2b9c6dcf049215845bfb7580c4dea80e",
        sframe_salt: "46b4367993a314910d4d9f3d",
        ct: "990123456797cb5644d8831ff8bdc080
             249990b24b569144cab2a87be22c20d9
             7976",
    },
    SFrameVector {
        suite: CipherSuite::Aes256CtrHmacSha512_32,
        sframe_secret: SECRET_SHA512,
        sframe_key: "afe92c81e0df8c00fab619e0559fe5ae
                     efce1ef77789d4c728af1b1c1f2e3552
                     c405d274415a5291ec075c2d9954c450
                     fbd36682a4e978494808b703ce78b409
                     f9fec29b91e6e703a75c4131377c80c9
                     d51b8906088092452e2593eb142eea2d",
        sframe_salt: "f6de647bac1263524cfb6533",
        ct: "9901234567112a94a288b85b49ffef1d
             279f2830165c39d76cac8884011c",
    },
];
