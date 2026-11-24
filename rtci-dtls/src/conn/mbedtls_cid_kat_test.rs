//! A known answer from Mbed TLS 3.6.2 for the DTLS 1.2 `tls12_cid` record (RFC 9146): a
//! handshake between `examples/dtls_interop.rs` as the server (asking for a 4-byte connection
//! id) and Mbed TLS `ssl_client2 dtls=1 cid=1 nss_keylog=1` on loopback, recorded in the test
//! container. Mbed TLS printed the master secret (its NSS key log line); the datagrams are as
//! they went over the wire. The production record protection, keyed from that secret and the
//! hellos' randoms, opens the records Mbed TLS protected with the connection id in their
//! additional data (RFC 9146 section 5), and only with it.

use super::*;
use crate::cipher_suite::{CipherSuiteId, cipher_suite_for_id};
use crate::record_layer::split_datagram;

/// The ClientHello that answered the HelloVerifyRequest (Mbed TLS).
const CLIENT_HELLO: &[&str] = &[
    "16fefd0000000000000001016d010001610001000000000161fefd6b0381efadc4b8dd5b91d43889711453bac5a985ed",
    "2651e7cec2c631cd0c58f60014e5da86924f635ee19f8180818cd90cac3e3c90d900d0cca8cca9ccaac02cc030009fc0",
    "adc09fc024c028006bc00ac0140039c0afc0a3c087c08bc07dc073c07700c40088c05dc061c053c049c04dc045c02bc0",
    "2f009ec0acc09ec023c0270067c009c0130033c0aec0a2c086c08ac07cc072c07600be0045c05cc060c052c048c04cc0",
    "44009dc09d003d0035c032c02ac00fc02ec026c005c0a1c07b00c00084c08dc079c089c075c05fc063c051c04bc04fc0",
    "3d009cc09c003c002fc031c029c00ec02dc025c004c0a0c07a00ba0041c08cc078c088c074c05ec062c050c04ac04ec0",
    "3c00ff010000530000000e000c0000096c6f63616c686f7374000a00120010001d00170018001e0019001a001b001c00",
    "0d000e000c060306010503050104030401000b000201000036000302beef001600000017000000230000",
];
/// This side's flight: ServerHello and the rest.
const SERVER_HELLO: &[&str] = &[
    "16fefd0000000000000001004c020000400001000000000040fefd6b0381eff85e0f4dceacb4e5ac63cbe04a7abe5f3f",
    "0b5bf7c1b8660f63baeddc00c02b0000180036000504497fd626ff0100010000170000000b0002010016fefd00000000",
    "0000000201730b00016700020000000001670001640001613082015d30820104a0030201020214703ea9bfd728f5c16b",
    "ae209d2ff80c4ffc7e3032300a06082a8648ce3d0403023021311f301d06035504030c16726367656e2073656c662073",
    "69676e656420636572743020170d3735303130313030303030305a180f34303936303130313030303030305a3021311f",
    "301d06035504030c16726367656e2073656c66207369676e656420636572743059301306072a8648ce3d020106082a86",
    "48ce3d0301070342000427e7dbbac4638776a714205c6589c17adfbf3f38bd72e60db3b77b8fd111c9e49d2c0ebc6b55",
    "bdad7a8ed3d21a1500cce9262313374121ccf6c507e0bbfb86a3a318301630140603551d11040d300b82096c6f63616c",
    "686f7374300a06082a8648ce3d0403020347003044022029e45d8190e377088222c9f56fa5c912f6d4cc4bfabc3a34d4",
    "f9f45f787a43bd022065c3506129285dbd096758a97c54632dbb0bde56a3e66bf9ad3bd24a2a7d619d16fefd00000000",
    "00000003007b0c00006f000300000000006f03001d20eb4268788f2d7027de696c45c80afd6c8c2a097a6101d513f434",
    "d7d91367556f04030047304502210092776d9ec6102cd5aa78d9896961f9bf7a377d379b39932905805310fc32f2b902",
    "2058f10638ec39eb47347e33448d9b64079dfcab7bbc95560d106712a2d8b9f7c116fefd0000000000000004000c0e00",
    "00000004000000000000",
];
/// Mbed TLS: ClientKeyExchange, ChangeCipherSpec, and its Finished as a `tls12_cid` record.
const CLIENT_FINISHED: &[&str] = &[
    "16fefd0000000000000002002d100000210002000000000021207dcc181e4ccf7338fb1d0d514a4b9383200fdfaefc61",
    "6e10723111e3cfa9cc0914fefd000000000000000300010119fefd0001000000000000497fd626003800010000000000",
    "001f1a631f5999730c7c39c0976cb0821e9cf7367287babce40e2b6052923045036adc5aeaff12da43b2f3784a764f59",
    "48",
];
/// Mbed TLS: its HTTP request, application data in a `tls12_cid` record.
const CLIENT_REQUEST: &[&str] = &[
    "19fefd0001000000000001497fd6260048000100000000000108e536b69967fd06f4e4abce5f7cecf5d762d39e599302",
    "05053864e60dff2f1ab79794b4da5de66679d6a28ae7abbd0de500a963559e80c67f55652b69feda1c",
];
/// From the NSS key log line Mbed TLS printed (`CLIENT_RANDOM <client random> <master secret>`).
const MASTER_SECRET: &str = "1c7a34010ec0e120c218eef620ed22fd5e2cf35f69f3d9e598d94bd4b59cb430cef068a5fc53916299134d63c63c6341";
const CLIENT_RANDOM: &str = "6b0381efadc4b8dd5b91d43889711453bac5a985ed2651e7cec2c631cd0c58f6";
/// The connection id this side asked for, which Mbed TLS puts in the records it sends.
const CONNECTION_ID: &str = "497fd626";

fn bytes(parts: &[&str]) -> Vec<u8> {
    let hex: String = parts.concat();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// The random of the first hello in `datagram`: after the record header, the handshake
/// header and the version.
fn random_of(datagram: &[u8]) -> Vec<u8> {
    datagram[RECORD_LAYER_HEADER_SIZE + 12 + 2..RECORD_LAYER_HEADER_SIZE + 12 + 34].to_vec()
}

/// The `tls12_cid` records of `datagram` (connection id of 4 bytes).
fn cid_records(datagram: &[u8]) -> Vec<Vec<u8>> {
    let (records, well_formed) = split_datagram(datagram, 4);
    assert!(well_formed);
    records
        .into_iter()
        .filter(|record| record[0] == ContentType::Tls12Cid as u8)
        .collect()
}

/// Opens a `tls12_cid` record as the connection does: the connection id taken out of the
/// header and handed to the cipher for the additional data.
fn open(
    cipher: &mut Box<dyn crate::cipher_suite::CipherSuite>,
    record: &[u8],
    connection_id: &[u8],
) -> Result<(ContentType, Vec<u8>)> {
    let at = RECORD_LAYER_HEADER_SIZE - 2;
    let mut canonical = record.to_vec();
    canonical.drain(at..at + 4);
    let opened = cipher.decrypt_with_connection_id(&canonical, connection_id)?;
    let inner = &opened[RECORD_LAYER_HEADER_SIZE..];
    let (content_type, length) = inner_content_type(inner).ok_or(Error::ErrInvalidContentType)?;
    Ok((content_type, inner[..length].to_vec()))
}

#[test]
fn the_tls12_cid_records_of_mbed_tls_open_with_the_connection_id() {
    let client_hello = bytes(CLIENT_HELLO);
    assert_eq!(
        random_of(&client_hello),
        bytes(&[CLIENT_RANDOM]),
        "the key log's random"
    );
    let server_hello = bytes(SERVER_HELLO);
    let mut server =
        cipher_suite_for_id(CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256).unwrap();
    server
        .init(
            crypto::default_provider().unwrap(),
            &bytes(&[MASTER_SECRET]),
            &random_of(&client_hello),
            &random_of(&server_hello),
            false,
        )
        .unwrap();
    let connection_id = bytes(&[CONNECTION_ID]);

    // Its Finished: the first record of epoch 1, a handshake message inside.
    let finished = cid_records(&bytes(CLIENT_FINISHED));
    assert_eq!(finished.len(), 1);
    assert_eq!(
        &finished[0][11..15],
        connection_id.as_slice(),
        "the id after the sequence number"
    );
    let (content_type, message) = open(&mut server, &finished[0], &connection_id).unwrap();
    assert_eq!(content_type, ContentType::Handshake);
    assert_eq!(message[0], 20, "Finished");
    assert_eq!(message.len(), 12 + 12);

    // Its request.
    let request = cid_records(&bytes(CLIENT_REQUEST));
    let (content_type, data) = open(&mut server, &request[0], &connection_id).unwrap();
    assert_eq!(content_type, ContentType::ApplicationData);
    assert!(
        data.starts_with(b"GET / HTTP/1.0"),
        "{:?}",
        String::from_utf8_lossy(&data)
    );

    // The connection id is in the additional data: another one, or none (the record opened as
    // an ordinary one), does not open it.
    assert!(open(&mut server, &request[0], &[0x49, 0x7f, 0xd6, 0x27]).is_err());
    let mut ordinary = request[0].clone();
    ordinary.drain(11..15);
    ordinary[0] = ContentType::ApplicationData as u8;
    assert!(server.decrypt(&ordinary).is_err());
}
