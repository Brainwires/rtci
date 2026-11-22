//! A peer's certificate is verified with any hash function RFC 8122 defines for fingerprints,
//! except MD5 and MD2 (RFC 8122 section 5, RFC 8842 section 5.1).
//!
//! > An endpoint MUST select the set of fingerprints that use its most preferred hash function
//! > (out of those offered by the peer) and verify that each certificate used matches one
//! > fingerprint out of that set. If a certificate does not match any such fingerprint, the
//! > endpoint MUST NOT establish the TLS connection.
//!
//! Only sha-256 fingerprints were compared before: a peer whose description carried the
//! certificate's fingerprint with another hash function could never connect.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World, keep, replace_lines};
use rtc::crypto::HashAlgorithm;
use rtc::peer_connection::certificate::{CertificateParams, RTCCertificate};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::RTCDtlsTransportState;
use std::time::{Duration, Instant};

fn certificate() -> Result<RTCCertificate> {
    let provider = rtc::crypto::default_provider()?;
    Ok(RTCCertificate::generate(
        provider.crypto(),
        rtc::crypto::SignatureScheme::EcdsaP256Sha256,
        CertificateParams::new(vec!["fingerprint-hashes".to_owned()])?,
    )?)
}

/// `a=fingerprint:<hash> <value>` for the certificate, upper-case as RFC 8122 writes it.
fn fingerprint_line(certificate: &RTCCertificate, algorithm: HashAlgorithm) -> Result<String> {
    let provider = rtc::crypto::default_provider()?;
    let fingerprint = certificate.fingerprint(provider.crypto(), algorithm)?;
    Ok(format!(
        "a=fingerprint:{} {}",
        fingerprint.algorithm,
        fingerprint.value.to_uppercase()
    ))
}

/// The same line with its first byte changed: a well-formed fingerprint of another certificate.
fn wrong(line: &str) -> String {
    let (head, value) = line.rsplit_once(' ').expect("hash-func SP fingerprint");
    let first = if value.starts_with("00") { "01" } else { "00" };
    format!("{head} {first}{}", &value[2..])
}

/// A world whose offerer (peer 0) has `certificate`, and whose offer reaches the answerer with
/// its `a=fingerprint` line replaced by `fingerprints`.
fn connect_with_fingerprints(
    certificate: &RTCCertificate,
    fingerprints: &[String],
) -> Result<World> {
    let mut world = World::new(
        Peer::with_configuration(
            "10.0.0.1:5000",
            RTCConfigurationBuilder::new()
                .with_certificates(vec![certificate.clone()])
                .build(),
            SettingEngineBuilder::new().build(),
        )?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    world.peers[0].pc.create_data_channel("data", None)?;
    let lines = fingerprints.join("\r\n");
    world.exchange_with(
        0,
        |sdp| replace_lines(sdp, "a=fingerprint:", Some(&lines)),
        keep,
    )?;
    world.trickle()?;
    Ok(world)
}

fn connects(what: &str, certificate: &RTCCertificate, fingerprints: &[String]) -> Result<()> {
    let mut world = connect_with_fingerprints(certificate, fingerprints)?;
    world.run(what, |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    world.ping_pong(what)?;
    assert_eq!(
        world.peers[1].remote_certificate().as_deref(),
        Some(certificate.dtls_certificate.certificate[0].as_ref()),
        "{what}"
    );
    Ok(())
}

fn fails(what: &str, certificate: &RTCCertificate, fingerprints: &[String]) -> Result<()> {
    let mut world = connect_with_fingerprints(certificate, fingerprints)?;
    let failed = world.run_for(Duration::from_secs(30), |peers| peers[1].failed());
    assert!(failed, "{what}: the answerer's connection did not fail");
    let now = world.now;
    assert_eq!(
        world.peers[1].dtls_state(now),
        RTCDtlsTransportState::Failed,
        "{what}"
    );
    assert!(
        !world.peers[1]
            .states
            .contains(&rtc::peer_connection::state::RTCPeerConnectionState::Connected),
        "{what}: the answerer connected"
    );
    assert!(world.peers[1].channel.is_none(), "{what}");
    Ok(())
}

/// A peer that gives its certificate's fingerprint with one hash function only, whichever of
/// RFC 8122's it is, is verified with it: the association is established with the right
/// certificate and refused with another one.
#[test]
fn a_certificate_is_verified_with_each_fingerprint_hash_function() -> Result<()> {
    let certificate = certificate()?;
    for algorithm in [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha512,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha224,
        HashAlgorithm::Sha1,
    ] {
        let line = fingerprint_line(&certificate, algorithm)?;
        connects(
            &format!("{algorithm:?} only"),
            &certificate,
            std::slice::from_ref(&line),
        )?;
        fails(
            &format!("{algorithm:?} only, of another certificate"),
            &certificate,
            &[wrong(&line)],
        )?;
    }
    Ok(())
}

/// Several `a=fingerprint` lines: the set of the most preferred hash function offered is the
/// one checked (sha-256 before the others), and the certificate must match one of that set.
#[test]
fn the_most_preferred_hash_function_offered_decides() -> Result<()> {
    let certificate = certificate()?;
    let sha256 = fingerprint_line(&certificate, HashAlgorithm::Sha256)?;
    let sha512 = fingerprint_line(&certificate, HashAlgorithm::Sha512)?;
    let sha1 = fingerprint_line(&certificate, HashAlgorithm::Sha1)?;

    // Two certificates' sha-256 fingerprints: the one presented matches one of them.
    connects(
        "two sha-256 fingerprints",
        &certificate,
        &[wrong(&sha256), sha256.clone()],
    )?;
    // A right sha-256 fingerprint and a wrong one of a less preferred function: sha-256 decides.
    connects(
        "sha-512 (wrong) and sha-256",
        &certificate,
        &[wrong(&sha512), sha256.clone()],
    )?;
    // A wrong sha-256 fingerprint is not rescued by a right one of a less preferred function:
    // "matches one fingerprint out of that set".
    fails(
        "sha-256 (wrong) and sha-512",
        &certificate,
        &[wrong(&sha256), sha512.clone()],
    )?;
    // Among the others the stronger one is preferred: sha-512 before sha-1.
    connects(
        "sha-1 (wrong) and sha-512",
        &certificate,
        &[wrong(&sha1), sha512.clone()],
    )?;
    fails(
        "sha-512 (wrong) and sha-1",
        &certificate,
        &[wrong(&sha512), sha1],
    )?;
    Ok(())
}

/// RFC 8122 section 5: "Implementations compliant with this specification MUST NOT use the MD2
/// and MD5 hash functions to calculate fingerprints or to verify received fingerprints that
/// have been calculated using them." A description whose only fingerprints are MD5 or MD2 (the
/// certificate's real MD5 included), or of a function nobody knows, cannot be verified and is
/// refused; next to a usable fingerprint such a line is ignored.
#[test]
fn md5_and_md2_fingerprints_are_never_used() -> Result<()> {
    let certificate = certificate()?;
    let provider = rtc::crypto::default_provider()?;
    let md5: Vec<String> = provider
        .crypto()
        .hash(
            HashAlgorithm::Md5,
            certificate.dtls_certificate.certificate[0].as_ref(),
        )?
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    let md5 = md5.join(":");

    let mut offerer = Peer::with_configuration(
        "10.0.0.1:5000",
        RTCConfigurationBuilder::new()
            .with_certificates(vec![certificate.clone()])
            .build(),
        SettingEngineBuilder::new().build(),
    )?;
    offerer.pc.create_data_channel("data", None)?;
    let offer = offerer.pc.create_offer(None)?.sdp;
    for only in [
        format!("a=fingerprint:md5 {md5}"),
        format!("a=fingerprint:md2 {md5}"),
        format!("a=fingerprint:sha3-256 {md5}"),
        format!("a=fingerprint:md5 {md5}\r\na=fingerprint:md2 {md5}"),
    ] {
        let sdp = replace_lines(&offer, "a=fingerprint:", Some(&only));
        let mut answerer = Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?;
        let applied = answerer
            .pc
            .set_remote_description(Instant::now(), RTCSessionDescription::offer(sdp)?);
        assert!(applied.is_err(), "{only:?} was accepted");
        assert!(answerer.pc.remote_description().is_none(), "{only:?}");
    }

    let sha256 = fingerprint_line(&certificate, HashAlgorithm::Sha256)?;
    connects(
        "md5 next to sha-256",
        &certificate,
        &[format!("a=fingerprint:md5 {md5}"), sha256.clone()],
    )?;
    // The MD5 value is right and the sha-256 one is not: MD5 does not verify the certificate.
    fails(
        "md5 next to a wrong sha-256",
        &certificate,
        &[format!("a=fingerprint:md5 {md5}"), wrong(&sha256)],
    )?;
    Ok(())
}
