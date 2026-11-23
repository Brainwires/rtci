//! Behaviour profiles: one switch for every default where the engine and an RFC, or the engine
//! and libwebrtc (Chrome), choose differently.
//!
//! The engine's defaults follow the RFCs, except where a named browser or deployed peer cannot
//! interoperate with the RFC form (the audit's `setting` verdict, `docs/conformance/audit/RULES.md`).
//! Each such choice is an individual setting of [`SettingEngineBuilder`], [`MediaEngine`] or
//! [`DefaultInterceptorOptions`]. A [`BehaviourProfile`] sets all of them at once:
//!
//! - [`BehaviourProfile::Rfc`]: the engine's defaults, unchanged. Nothing is different from a
//!   configuration that never names a profile.
//! - [`BehaviourProfile::Chrome`]: libwebrtc's (Chrome's) choice wherever the engine and
//!   libwebrtc both do a thing and choose differently: a timer value, an ordering, a form on
//!   the wire, a lenient or a strict acceptance rule. It never turns off a capability the engine
//!   has and Chrome lacks (SCTP message interleaving, RFC 8888 feedback, FlexFEC per RFC 8627,
//!   ...): those negotiate down with a Chrome peer by themselves, so a `Chrome` profile's
//!   offers are a superset of Chrome's. Each Chrome value is observed in the recorded Chromium
//!   descriptions or read in libwebrtc's source at a pinned revision (the table names the file,
//!   the symbol and the commit).
//! - [`BehaviourProfile::StrictRfc`]: the RFC form even where the engine's default is the
//!   interoperable one (the audit's `setting` rows and a few RFC SHOULDs). For conformance
//!   testing: it does **not** interoperate with browsers (Chromium, Firefox and WebKit refuse a
//!   bundled section without `a=rtcp-mux`, and ignore a new `a=tls-id`).
//! - [`BehaviourProfile::Performance`]: the engine's defaults, with each behaviour where an
//!   RFC offers a form that does the same thing at lower cost (a parameter such as
//!   `T_rr_interval`, a MAY) set to it: fewer regular RTCP reports, congestion control
//!   feedback and reports together inside RFC 3550's 5%. It never turns a capability off and
//!   never leaves what the RFCs permit; a cheaper libwebrtc value outside an RFC belongs to
//!   `Chrome`. The table gives each value's measured saving and cost.
//!
//! # One entry point
//!
//! ```
//! use rtc::interceptor::Registry;
//! use rtc::peer_connection::configuration::BehaviourProfile;
//! use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
//! use rtc::peer_connection::configuration::media_engine::MediaEngine;
//! use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let profile = BehaviourProfile::Chrome;
//! let setting_engine = SettingEngineBuilder::new()
//!     .with_behaviour_profile(profile)
//!     // Individual settings still override the profile, when set after it.
//!     .with_sctp_message_size_limit_without_interleaving(true)
//!     .build();
//! let mut media_engine = MediaEngine::for_profile(profile);
//! media_engine.register_default_codecs()?;
//! // Reads the media engine's profile.
//! let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
//! # let _ = (setting_engine, registry);
//! # Ok(())
//! # }
//! ```
//!
//! # The `chrome-defaults` cargo feature
//!
//! With the feature on, [`BehaviourProfile::default()`] is [`BehaviourProfile::Chrome`], and so
//! is every `Default` / `new()` of the three objects above. Cargo unifies features across a
//! dependency graph: **one crate in a build that turns the feature on changes the defaults of
//! every user of `rtc` in that build**, including libraries that never asked for it. Prefer the
//! explicit [`SettingEngineBuilder::with_behaviour_profile`] call; read
//! [`BehaviourProfile::compiled_default`] to see which default a build has.
//!
//! # The `performance-defaults` cargo feature
//!
//! The same for [`BehaviourProfile::Performance`]. With both features on, `chrome-defaults`
//! wins and the build prints a deprecation warning naming both, so the choice is never
//! silent ([`BehaviourProfile::compiled_default`]).
//!
//! The table of every governed behaviour, with its clause, its value in each profile and the
//! source of each Chrome value, is `docs/behaviour-profiles.md`, rendered from the tables of
//! this module by `scripts/behaviour-profiles.py` (a gate of CI) and checked against the code by
//! this module's tests.

use std::fmt;
use std::time::Duration;

use crate::peer_connection::configuration::interceptor_registry::DefaultInterceptorOptions;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::configuration::setting_engine::{
    DtlsFlightInterval, SctpMaxMessageSize, SettingEngine, SettingEngineBuilder,
};
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;

#[cfg(test)]
#[path = "behaviour_profile_test.rs"]
mod behaviour_profile_test;

/// Which family of defaults a peer connection takes; see the [module](self) documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BehaviourProfile {
    /// The engine's defaults: the RFCs' behaviour, and the interoperable form where a named
    /// browser or deployed peer cannot take the RFC's (the audit's `setting` rows).
    Rfc,
    /// libwebrtc's (Chrome's) choice wherever both do the thing and choose differently.
    Chrome,
    /// The RFC form everywhere, including where browsers cannot interoperate with it. For
    /// conformance testing; it does not interoperate with browsers.
    StrictRfc,
    /// The engine's defaults, with each governed behaviour where the RFCs offer a form that
    /// does the same thing at lower cost (a parameter, a MAY) set to it. It never turns a
    /// capability off and never leaves what the RFCs permit; libwebrtc's cheaper values that
    /// lie outside an RFC stay in [`BehaviourProfile::Chrome`]. Each value carries its
    /// measured saving and cost (`docs/behaviour-profiles.md`).
    Performance,
}

impl BehaviourProfile {
    /// Every profile, in the order of the table.
    pub const ALL: [BehaviourProfile; 4] =
        [Self::Rfc, Self::Chrome, Self::StrictRfc, Self::Performance];

    /// The profile `Default` gives in this build: [`BehaviourProfile::Chrome`] when the
    /// `chrome-defaults` cargo feature of `rtc` is on anywhere in the build's dependency graph,
    /// [`BehaviourProfile::Performance`] when `performance-defaults` is (and `chrome-defaults`
    /// is not), [`BehaviourProfile::Rfc`] otherwise.
    ///
    /// With both features on, `chrome-defaults` wins: it is the one that changes what goes on
    /// the wire to match a peer, while `performance-defaults` only trims cost within the RFCs,
    /// and the build says so with a compile-time warning (a deprecated item used under that
    /// feature combination), not silently.
    pub const fn compiled_default() -> Self {
        if cfg!(feature = "chrome-defaults") {
            Self::Chrome
        } else if cfg!(feature = "performance-defaults") {
            Self::Performance
        } else {
            Self::Rfc
        }
    }

    /// The profile's name as the table and the interop peer write it: `rfc`, `chrome`,
    /// `strict-rfc`, `performance`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rfc => "rfc",
            Self::Chrome => "chrome",
            Self::StrictRfc => "strict-rfc",
            Self::Performance => "performance",
        }
    }

    /// The profile named `name` (as [`Self::name`] writes it; case and `_` / `-` aside).
    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.trim().to_ascii_lowercase().replace('_', "-");
        Self::ALL.into_iter().find(|profile| profile.name() == name)
    }
}

/// Both `chrome-defaults` and `performance-defaults` are on: the build's default profile is
/// `Chrome` ([`BehaviourProfile::compiled_default`]). Using this item is what makes the
/// compiler say so.
#[cfg(all(feature = "chrome-defaults", feature = "performance-defaults"))]
#[deprecated(
    note = "both the `chrome-defaults` and the `performance-defaults` features of `rtc` are on: \
            the default behaviour profile is `Chrome`, `performance-defaults` has no effect"
)]
const BOTH_DEFAULT_PROFILE_FEATURES: () = ();

#[cfg(all(feature = "chrome-defaults", feature = "performance-defaults"))]
#[allow(clippy::let_unit_value)]
const _: () = BOTH_DEFAULT_PROFILE_FEATURES;

impl Default for BehaviourProfile {
    fn default() -> Self {
        Self::compiled_default()
    }
}

impl fmt::Display for BehaviourProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Where a Chrome value of the table comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Evidence {
    /// Seen: in the recorded Chromium descriptions (`tests/fixtures/browser-sdp/chromium--*`)
    /// or in a cell of the browser matrix.
    Observed,
    /// Read in libwebrtc's source at a pinned revision: the row names the file, the symbol and
    /// the revision (`docs/behaviour-profiles.md` the full commit).
    Source,
    /// Neither observed nor established from the source: marked "unverified" in the table,
    /// with the reason. No row is at present.
    #[allow(dead_code)]
    Unverified,
}

/// How a governed behaviour is set and read on the object that holds it.
#[derive(Clone, Copy)]
pub(crate) enum Hook {
    Setting {
        apply: fn(SettingEngineBuilder, BehaviourProfile) -> SettingEngineBuilder,
        read: fn(&SettingEngine) -> String,
    },
    Media {
        apply: fn(&mut MediaEngine, BehaviourProfile),
        read: fn(&MediaEngine) -> String,
    },
    Interceptors {
        apply: fn(&mut DefaultInterceptorOptions, BehaviourProfile),
        read: fn(&DefaultInterceptorOptions) -> String,
    },
}

/// One row of the table: a default that differs between the profiles.
#[derive(Clone, Copy)]
pub(crate) struct GovernedBehaviour {
    /// A stable name of the behaviour.
    pub(crate) id: &'static str,
    /// The setting that selects it (the path of the method or field).
    pub(crate) setting: &'static str,
    /// The RFC / specification clause.
    pub(crate) clause: &'static str,
    /// The value under [`BehaviourProfile::Rfc`], as `{:?}` of the setting writes it.
    pub(crate) rfc: &'static str,
    /// The value under [`BehaviourProfile::Chrome`].
    pub(crate) chrome: &'static str,
    /// The value under [`BehaviourProfile::StrictRfc`].
    pub(crate) strict_rfc: &'static str,
    /// The value under [`BehaviourProfile::Performance`] (the `Rfc` value unless the row
    /// names one).
    pub(crate) performance: &'static str,
    /// Where the Chrome value comes from.
    pub(crate) chrome_source: &'static str,
    pub(crate) evidence: Evidence,
    pub(crate) hook: Hook,
}

impl GovernedBehaviour {
    /// The table's value of this behaviour under `profile`.
    pub(crate) fn value(&self, profile: BehaviourProfile) -> &'static str {
        match profile {
            BehaviourProfile::Rfc => self.rfc,
            BehaviourProfile::Chrome => self.chrome,
            BehaviourProfile::StrictRfc => self.strict_rfc,
            BehaviourProfile::Performance => self.performance,
        }
    }
}

/// Writes a value as it is, without the quotes `{:?}` puts on a string.
struct Shown(String);

impl fmt::Debug for Shown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn sctp_rto_shown(rto: Option<sctp::RtoConfig>) -> Shown {
    Shown(match rto {
        None => "None (1s / 1s / 60s)".to_owned(),
        Some(rto) => format!("{:?} / {:?} / {:?}", rto.initial, rto.min, rto.max),
    })
}

fn sctp_max_retransmissions_shown(limit: Option<usize>) -> Shown {
    Shown(match limit {
        None => "None (10)".to_owned(),
        Some(usize::MAX) => "unlimited".to_owned(),
        Some(limit) => limit.to_string(),
    })
}

/// libwebrtc's DTLS-SRTP profiles in its order (`CryptoOptions::GetSupportedDtlsSrtpCryptoSuites`
/// with GCM on and not preferred).
const LIBWEBRTC_SRTP_PROFILES: [SrtpProtectionProfile; 3] = [
    SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
    SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm,
    SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
];

/// The profiles a connection offers: the configured ones, or the engine's default list.
fn srtp_profiles_shown(profiles: &[SrtpProtectionProfile]) -> Shown {
    Shown(if profiles.is_empty() {
        format!(
            "{:?}",
            crate::peer_connection::transport::dtls::default_srtp_protection_profiles()
        )
    } else {
        format!("{profiles:?}")
    })
}

/// The SOFTWARE text of the ICE agent's and the TURN clients' STUN messages.
fn ice_software_shown(software: &Option<Option<String>>) -> Shown {
    Shown(match software {
        None => "rtc-ice / rtc-turn and version".to_owned(),
        Some(None) => "none".to_owned(),
        Some(Some(text)) if text.is_empty() => "none".to_owned(),
        Some(Some(text)) => format!("{text:?}"),
    })
}

fn sctp_rto(initial_ms: u64, min_ms: u64, max_ms: u64) -> Option<sctp::RtoConfig> {
    Some(sctp::RtoConfig {
        initial: Duration::from_millis(initial_ms),
        min: Duration::from_millis(min_ms),
        max: Duration::from_millis(max_ms),
    })
}

/// The table. Each row names the value of each profile twice: as the expression the profile
/// applies, and as the text the table shows (`{:?}` of what `read` returns), which the tests
/// compare. `scripts/behaviour-profiles.py` renders `docs/behaviour-profiles.md` from the
/// literals: keep one `key: value` per line.
macro_rules! governed_behaviours {
    ($( {
        id: $id:literal,
        setting: $setting:literal,
        clause: $clause:literal,
        rfc: $rfc:expr => $rfc_text:literal,
        chrome: $chrome:expr => $chrome_text:literal,
        strict_rfc: $strict:expr => $strict_text:literal,
        $(performance: $perf:expr => $perf_text:literal,
        performance_note: $perf_note:literal,)?
        chrome_source: $source:literal,
        evidence: $evidence:ident,
        $target:ident: $apply:expr,
        read: $read:expr $(,)?
    } ),* $(,)?) => {
        pub(crate) static GOVERNED: &[GovernedBehaviour] = &[ $(
            GovernedBehaviour {
                id: $id,
                setting: $setting,
                clause: $clause,
                rfc: $rfc_text,
                chrome: $chrome_text,
                strict_rfc: $strict_text,
                performance: governed_behaviours!(@or [$($perf_text)?] $rfc_text),
                chrome_source: $source,
                evidence: Evidence::$evidence,
                hook: governed_behaviours!(
                    @hook $target, $apply, $read, $rfc, $chrome, $strict, [$($perf)?]
                ),
            }
        ),* ];
    };
    (@or [$value:expr] $fallback:expr) => { $value };
    (@or [] $fallback:expr) => { $fallback };
    (@hook apply_setting, $apply:expr, $read:expr, $rfc:expr, $chrome:expr, $strict:expr, [$($perf:expr)?]) => {
        Hook::Setting {
            apply: |builder, profile| {
                let value = match profile {
                    BehaviourProfile::Rfc => $rfc,
                    BehaviourProfile::Chrome => $chrome,
                    BehaviourProfile::StrictRfc => $strict,
                    BehaviourProfile::Performance => governed_behaviours!(@or [$($perf)?] $rfc),
                };
                ($apply)(builder, value)
            },
            read: |engine| format!("{:?}", ($read)(engine)),
        }
    };
    (@hook apply_media, $apply:expr, $read:expr, $rfc:expr, $chrome:expr, $strict:expr, [$($perf:expr)?]) => {
        Hook::Media {
            apply: |media_engine, profile| {
                let value = match profile {
                    BehaviourProfile::Rfc => $rfc,
                    BehaviourProfile::Chrome => $chrome,
                    BehaviourProfile::StrictRfc => $strict,
                    BehaviourProfile::Performance => governed_behaviours!(@or [$($perf)?] $rfc),
                };
                ($apply)(media_engine, value)
            },
            read: |media_engine| format!("{:?}", ($read)(media_engine)),
        }
    };
    (@hook apply_interceptors, $apply:expr, $read:expr, $rfc:expr, $chrome:expr, $strict:expr, [$($perf:expr)?]) => {
        Hook::Interceptors {
            apply: |options, profile| {
                let value = match profile {
                    BehaviourProfile::Rfc => $rfc,
                    BehaviourProfile::Chrome => $chrome,
                    BehaviourProfile::StrictRfc => $strict,
                    BehaviourProfile::Performance => governed_behaviours!(@or [$($perf)?] $rfc),
                };
                ($apply)(options, value)
            },
            read: |options| format!("{:?}", ($read)(options)),
        }
    };
}

use ice::{FailedNomination, NominationAcceptance};
use interceptor::{EcnInitiation, EcnMarking, ThresholdTimeBase};

governed_behaviours! {
    // ---- ICE ----
    {
        id: "ice.nomination-acceptance",
        setting: "SettingEngineBuilder::with_ice_nomination_acceptance",
        clause: "RFC 8445 8.1.1",
        rfc: NominationAcceptance::HighestPriority => "HighestPriority",
        chrome: NominationAcceptance::Latest => "Latest",
        strict_rfc: NominationAcceptance::HighestPriority => "HighestPriority",
        chrome_source: "libwebrtc p2p/base/basic_ice_controller.cc::BasicIceController::CompareConnections @ a222406d: on the controlled side a writable, receiving pair is ranked by its remote nomination value (the NOMINATION attribute with renomination, 1 for USE-CANDIDATE), then by the time data last arrived on it, and only then by priority; p2p_transport_channel.cc::P2PTransportChannel::OnNominated switches at once. Without renomination (Chromium writes no a=ice-options:renomination) a nominated pair takes over when the peer moves its data to it: `Latest` is the closest form, not HighestPriority",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_ice_nomination_acceptance(v),
        read: |s: &SettingEngine| s.ice.nomination_acceptance,
    },
    {
        id: "ice.failed-nomination",
        setting: "SettingEngineBuilder::with_ice_failed_nomination",
        clause: "RFC 8445 7.2.5.3.4",
        rfc: FailedNomination::FailChecklist => "FailChecklist",
        chrome: FailedNomination::Retry => "Retry",
        strict_rfc: FailedNomination::FailChecklist => "FailChecklist",
        chrome_source: "libwebrtc p2p/base/connection.cc::Connection::UpdateState @ a222406d: an unanswered check makes a pair unreliable (kConnectionWriteConnectFailures 5 and kConnectionWriteConnectTimeout 5 s, p2p_constants.h) and timed out only after kConnectionWriteTimeout 15 s without a response; it is pinged (and, selected, nominated) again meanwhile, and basic_ice_controller.cc::ReadyToSend keeps sending on an unreliable pair",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_ice_failed_nomination(v),
        read: |s: &SettingEngine| s.ice.failed_nomination,
    },
    {
        id: "ice.nomination-on-consent-checks",
        setting: "SettingEngineBuilder::with_ice_nomination_on_consent_checks",
        clause: "RFC 8445 7.1.2, RFC 7675 5.1",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "libwebrtc p2p/base/basic_ice_controller.cc::BasicIceController::GetUseCandidateAttr @ a222406d: the default NominationMode::SEMI_AGGRESSIVE (p2p/base/ice_transport_internal.h, IceConfig::default_nomination_mode) puts USE-CANDIDATE on every ping of the selected connection (connection.cc::Connection::BuildPingRequest)",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_ice_nomination_on_consent_checks(v),
        read: |s: &SettingEngine| s.ice.nominate_on_consent_checks,
    },
    {
        id: "ice.data-before-nomination",
        setting: "SettingEngineBuilder::with_ice_data_before_nomination",
        clause: "RFC 8445 12.1 (MAY)",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "libwebrtc p2p/base/basic_ice_controller.cc::BasicIceController::ShouldSwitchConnection and ::ReadyToSend @ a222406d: the selected connection is the best one that is writable (or unreliable), nominated or not; p2p_transport_channel.cc::SwitchSelectedConnectionInternal then sends on it and nominates it",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_ice_data_before_nomination(v),
        read: |s: &SettingEngine| s.ice.send_data_before_nomination,
    },
    {
        id: "ice.pairing-before-conveyed",
        setting: "SettingEngineBuilder::with_ice_pairing_before_candidates_are_conveyed",
        clause: "RFC 8838 10",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "libwebrtc p2p/base/p2p_transport_channel.cc::P2PTransportChannel::OnPortReady @ a222406d: a new local port is paired with every remote candidate known (CreateConnection) when it is ready; OnCandidatesReady only tells the application (NotifyCandidateGathered)",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_ice_pairing_before_candidates_are_conveyed(v),
        read: |s: &SettingEngine| s.ice.pair_before_conveyed,
    },
    {
        id: "ice.software-attribute",
        setting: "SettingEngineBuilder::with_ice_software",
        clause: "RFC 8489 6.1, 6.3.1.1, 16.1.2",
        rfc: None => "rtc-ice / rtc-turn and version",
        chrome: Some(None) => "none",
        strict_rfc: None => "rtc-ice / rtc-turn and version",
        chrome_source: "libwebrtc @ a222406d: no SOFTWARE attribute in any STUN message: p2p/base/connection.cc Connection::BuildPingRequest (1122-1199: USERNAME, GOOG-NETWORK-INFO, ICE-CONTROLLING / -CONTROLLED, USE-CANDIDATE or NOMINATION, PRIORITY, MESSAGE-INTEGRITY, FINGERPRINT) and Connection::SendStunBindingResponse (771-847); p2p/base/turn_port.cc TurnAllocateRequest (1513-1532), TurnRefreshRequest (1709-1725), TurnCreatePermissionRequest (1793-1816), TurnChannelBindRequest (1864-1889) and TurnPort::AddRequestAuthInfo (1237-1261); grep for SOFTWARE in p2p/ finds none. Covers the ICE checks and responses and the TURN requests; the engine's server-reflexive Binding requests carry none in every profile (p2p/base/stun_port.cc StunBindingRequest, 63-75, none either)",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.ice_software_choice(v),
        read: |s: &SettingEngine| ice_software_shown(&s.ice.software),
    },
    {
        id: "ice.options-in-media-sections",
        setting: "SettingEngineBuilder::with_ice_options_in_media_sections",
        clause: "RFC 8839 5.6",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "a=ice-options:trickle in every section of every Chromium fixture, after a=ice-pwd (chromium--balanced-rust-s-offer-has-a-transport-per-media-type-answered-without-bundle--1-answer.sdp); source: libwebrtc api/webrtc_sdp.cc::BuildMediaDescription @ a222406d calls BuildIceOptions per section",
        evidence: Observed,
        apply_setting: |b: SettingEngineBuilder, v| b.with_ice_options_in_media_sections(v),
        read: |s: &SettingEngine| s.ice_options_in_media_sections,
    },
    {
        id: "ice.default-pacing-stated",
        setting: "SettingEngineBuilder::with_default_ice_pacing_stated",
        clause: "RFC 8839 4.3.1 (SHOULD), RFC 8445 14.2",
        rfc: true => "true",
        chrome: false => "false",
        strict_rfc: true => "true",
        chrome_source: "no Chromium fixture has a=ice-pacing; source: libwebrtc api/webrtc_sdp.cc @ a222406d writes and reads none; its checks are paced by p2p/base/p2p_constants.h kWeakPingInterval 48 ms. A Ta other than the default is stated under every profile (RFC 8445 14.2 MUST)",
        evidence: Observed,
        apply_setting: |b: SettingEngineBuilder, v| b.with_default_ice_pacing_stated(v),
        read: |s: &SettingEngine| !s.default_ice_pacing_omitted,
    },
    // ---- DTLS / SDP fingerprints ----
    {
        id: "dtls.lowercase-fingerprints",
        setting: "SettingEngineBuilder::with_lowercase_fingerprints_accepted",
        clause: "RFC 8122 5",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "libwebrtc rtc_base/ssl_fingerprint.cc::SSLFingerprint::CreateFromRfc4572 @ a222406d decodes with rtc_base/string_encode.cc::HexDecode, which takes A-F and a-f",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_lowercase_fingerprints_accepted(v),
        read: |s: &SettingEngine| s.accept_lowercase_fingerprints,
    },
    {
        id: "dtls.use-srtp-on-every-association",
        setting: "SettingEngineBuilder::with_dtls_use_srtp_on_every_association",
        clause: "RFC 5764 4.1",
        rfc: true => "true",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "browser matrix (train round 8): Chromium offers use_srtp on a data-only association and keeps its first association when a media section is added (the \"Rust offers media\", \"rollback\" and \"glare\" cells)",
        evidence: Observed,
        apply_setting: |b: SettingEngineBuilder, v| b.with_dtls_use_srtp_on_every_association(v),
        read: |s: &SettingEngine| !s.dtls_use_srtp_only_with_media,
    },
    {
        id: "dtls.flight-interval",
        setting: "SettingEngineBuilder::with_dtls_flight_interval",
        clause: "RFC 9147 5.8.2, RFC 6347 4.2.4.1",
        rfc: DtlsFlightInterval::Rfc9147 => "Rfc9147",
        chrome: DtlsFlightInterval::Libwebrtc => "Libwebrtc",
        strict_rfc: DtlsFlightInterval::Rfc9147 => "Rfc9147",
        chrome_source: "libwebrtc p2p/dtls/dtls_transport.cc::ComputeRetransmissionTimeout @ a222406d: max(kMinDtlsHandshakeTimeoutMs 50, min(kMaxDtlsHandshakeTimeoutMs 3000, 2 * ICE RTT)), set by DtlsTransportInternalImpl::ConfigureHandshakeTimeout; without an RTT the 50 ms of rtc_base/openssl_stream_adapter.h dtls_handshake_timeout_ms_ (BoringSSL then doubles it up to 60 s, ssl/d1_lib.cc @ 289645a4)",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_dtls_flight_interval(v),
        read: |s: &SettingEngine| s.dtls_flight_interval,
    },
    {
        id: "dtls.srtp-profile-order",
        setting: "SettingEngineBuilder::with_srtp_protection_profiles",
        clause: "RFC 5764 4.1.1, 4.1.2, RFC 7714 14.2",
        rfc: Vec::new() => "[Srtp_Aead_Aes_256_Gcm, Srtp_Aead_Aes_128_Gcm, Srtp_Aes128_Cm_Hmac_Sha1_80]",
        chrome: LIBWEBRTC_SRTP_PROFILES.to_vec() => "[Srtp_Aes128_Cm_Hmac_Sha1_80, Srtp_Aead_Aes_256_Gcm, Srtp_Aead_Aes_128_Gcm]",
        strict_rfc: Vec::new() => "[Srtp_Aead_Aes_256_Gcm, Srtp_Aead_Aes_128_Gcm, Srtp_Aes128_Cm_Hmac_Sha1_80]",
        chrome_source: "libwebrtc api/crypto/crypto_options.cc::CryptoOptions::GetSupportedDtlsSrtpCryptoSuites @ a222406d: with prefer_gcm_crypto_suites false (api/crypto/crypto_options.h; Chromium sets enable_gcm_crypto_suites and leaves it, third_party/blink/renderer/modules/peerconnection/rtc_peer_connection_handler.cc @ Chromium 8dafa8bc) AES_CM_128_HMAC_SHA1_80 comes first, GCM 256 and 128 after it; a DTLS server takes its own most preferred profile (BoringSSL ssl/extensions.cc::ext_srtp_parse_clienthello @ 289645a4). The 32-bit tag is off in both",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_srtp_protection_profiles(v),
        read: |s: &SettingEngine| srtp_profiles_shown(&s.srtp_protection_profiles),
    },
    // ---- JSEP / SDP ----
    {
        id: "sdp.bundle-attributes-repeated",
        setting: "SettingEngineBuilder::with_bundle_attributes_repeated",
        clause: "RFC 9143 7.1.3, RFC 9429 5.2.2 / 5.3.1",
        rfc: true => "true",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "Chromium answers and subsequent offers repeat a=ice-ufrag, a=ice-pwd, a=fingerprint, a=setup, a=rtcp-mux in every bundled section (fixture chromium--rust-offers-media-the-browser-answers-and-decodes-it--2-answer.sdp)",
        evidence: Observed,
        apply_setting: |b: SettingEngineBuilder, v| b.with_bundle_attributes_repeated(v),
        read: |s: &SettingEngine| !s.bundle_attributes_tagged_only,
    },
    {
        id: "sdp.unique-transport-credentials",
        setting: "SettingEngineBuilder::with_unique_transport_credentials",
        clause: "RFC 9429 5.2.1",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: true => "true",
        chrome_source: "a Chromium answer without BUNDLE gives each transport an ice-ufrag / ice-pwd of its own (fixture chromium--balanced-rust-s-offer-has-a-transport-per-media-type-answered-without-bundle--1-answer.sdp); bundled sections share the tagged one's",
        evidence: Observed,
        apply_setting: |b: SettingEngineBuilder, v| b.with_unique_transport_credentials(v),
        read: |s: &SettingEngine| s.unique_transport_credentials,
    },
    {
        id: "sdp.msid-appdata",
        setting: "SettingEngineBuilder::with_msid_appdata",
        clause: "RFC 9429 5.2.1, RFC 8830 2",
        rfc: true => "true",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "Chromium writes a=msid with the stream id and the track id (fixture chromium--reflect-video-vp8--1-offer.sdp)",
        evidence: Observed,
        apply_setting: |b: SettingEngineBuilder, v| b.with_msid_appdata(v),
        read: |s: &SettingEngine| !s.msid_appdata_omitted,
    },
    {
        id: "jsep.max-bundle-as-must-bundle",
        setting: "SettingEngineBuilder::with_max_bundle_as_must_bundle",
        clause: "RFC 9429 4.1.1 (SHOULD ignore max-bundle)",
        rfc: true => "true",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "libwebrtc pc/jsep_transport_controller.cc::JsepTransportController::ValidateAndMaybeUpdateBundleGroups @ a222406d: under kBundlePolicyMaxBundle a description of more than one section without BUNDLE is refused (\"max-bundle is used but no bundle group found\"); libwebrtc writes no a=bundle-only itself (api/webrtc_sdp.cc writes it only for content marked bundle_only)",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_max_bundle_as_must_bundle(v),
        read: |s: &SettingEngine| !s.max_bundle_ignored,
    },
    {
        id: "jsep.stopping-transceiver-rejected-in-answer",
        setting: "SettingEngineBuilder::with_stopping_transceiver_rejected_in_answer",
        clause: "RFC 9429 5.3.1",
        rfc: false => "false",
        chrome: false => "false",
        strict_rfc: true => "true",
        chrome_source: "libwebrtc pc/sdp_offer_answer.cc::GetMediaDescriptionOptionsForTransceiver @ a222406d: a section is stopped in createOffer when its transceiver is stopping, in createAnswer only when it is stopped",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_stopping_transceiver_rejected_in_answer(v),
        read: |s: &SettingEngine| s.stopping_transceiver_rejected_in_answer,
    },
    {
        id: "jsep.strict-attribute-grammar",
        setting: "SettingEngineBuilder::with_strict_sdp_attribute_grammar",
        clause: "RFC 9429 5.8",
        rfc: false => "false",
        chrome: false => "false",
        strict_rfc: true => "true",
        chrome_source: "libwebrtc api/webrtc_sdp.cc::ParseRtcpFbAttribute @ a222406d: the fields are split on spaces and the parameter is the concatenation of the rest, so a trailing space adds an empty field and is accepted",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_strict_sdp_attribute_grammar(v),
        read: |s: &SettingEngine| s.strict_sdp_attribute_grammar,
    },
    {
        id: "jsep.rollback-content-ignored",
        setting: "SettingEngineBuilder::with_rollback_content_ignored",
        clause: "RFC 9429 4.1.10 (W3C: sdp unused)",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "libwebrtc api/jsep.cc::CreateSessionDescription @ a222406d: for SdpType::kRollback it returns CreateRollbackSessionDescription() without parsing the sdp",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_rollback_content_ignored(v),
        read: |s: &SettingEngine| s.rollback_content_ignored,
    },
    {
        id: "jsep.w3c-simulcast-answer",
        setting: "SettingEngineBuilder::with_w3c_simulcast_answer",
        clause: "RFC 8853 5.2, RFC 8851 6.3 (W3C webrtc-pc 4.4.2)",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "libwebrtc pc/sdp_offer_answer.cc::GetSendEncodingsFromRemoteDescription @ a222406d: \"We will always use the first alternative\" of each a=simulcast stream; GetMediaDescriptionOptionsForTransceiver writes the answer's send rids (RidDescription) with payload types only, no restrictions",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_w3c_simulcast_answer(v),
        read: |s: &SettingEngine| s.w3c_simulcast_answer,
    },
    {
        id: "sdp.rid-pause-marks",
        setting: "SettingEngineBuilder::with_rid_pause_marks",
        clause: "RFC 8853 5.2, 5.3.2",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "libwebrtc pc/sdp_offer_answer.cc::GetMediaDescriptionOptionsForTransceiver @ a222406d: an inactive encoding becomes SimulcastLayer(rid, /*is_paused=*/true), written ~rid by pc/simulcast_sdp_serializer.cc; libwebrtc has no RFC 7728 pause",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_rid_pause_marks(v),
        read: |s: &SettingEngine| s.rid_pause_marks,
    },
    // ---- SCTP / data channels ----
    {
        id: "sctp.max-message-size",
        setting: "SettingEngineBuilder::with_sctp_max_message_size",
        clause: "RFC 8841 6.1",
        rfc: SctpMaxMessageSize::Bounded(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE) => "Bounded(65536)",
        chrome: SctpMaxMessageSize::Bounded(262_144) => "Bounded(262144)",
        strict_rfc: SctpMaxMessageSize::Bounded(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE) => "Bounded(65536)",
        chrome_source: "every Chromium description with a data section has a=max-message-size:262144 (fixture chromium--data-channel-ordered--1-offer.sdp)",
        evidence: Observed,
        apply_setting: |b: SettingEngineBuilder, v| b.with_sctp_max_message_size(v),
        read: |s: &SettingEngine| s.sctp_max_message_size,
    },
    {
        id: "sctp.message-size-limit-without-interleaving",
        setting: "SettingEngineBuilder::with_sctp_message_size_limit_without_interleaving",
        clause: "RFC 8831 6.6 (SHOULD)",
        rfc: true => "true",
        chrome: false => "false",
        strict_rfc: true => "true",
        chrome_source: "Chromium announces no interleaving and sends messages up to the peer's max-message-size (browser matrix: \"data channel 256 KiB message within both sides' max-message-size\" passes)",
        evidence: Observed,
        apply_setting: |b: SettingEngineBuilder, v| b.with_sctp_message_size_limit_without_interleaving(v),
        read: |s: &SettingEngine| s.sctp_message_size_limit_without_interleaving.unwrap_or(true),
    },
    {
        id: "sctp.rto",
        setting: "SettingEngineBuilder::with_sctp_rto",
        clause: "RFC 9260 6.3.1, 16",
        rfc: None => "None (1s / 1s / 60s)",
        chrome: sctp_rto(500, 400, 3_000) => "500ms / 400ms / 3s",
        strict_rfc: None => "None (1s / 1s / 60s)",
        chrome_source: "libwebrtc net/dcsctp/public/dcsctp_options.h::DcSctpOptions @ a222406d: rto_initial 500 ms, rto_min 400 ms, rto_max 60 s (min_rtt_variance is the 220 ms); media/sctp/dcsctp_transport.cc::DcSctpTransport::CreateDcSctpOptions caps the timer backoff at kMaxTimerBackoffDuration 3 s, which the engine's RTO.Max (it bounds the doubling too, RFC 9260 6.3.3 rule E2) expresses as 3 s. A computed RTO over 3 s, which dcsctp keeps up to 60 s, is the difference",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v: Option<sctp::RtoConfig>| match v {
            Some(rto) => b.with_sctp_rto(rto.initial, rto.min, rto.max),
            None => b.without_sctp_rto(),
        },
        read: |s: &SettingEngine| sctp_rto_shown(s.sctp_rto),
    },
    {
        id: "sctp.max-retransmissions",
        setting: "SettingEngineBuilder::with_sctp_max_retransmissions",
        clause: "RFC 9260 8.1, 8.2, 16 (SHOULD)",
        rfc: None => "None (10)",
        chrome: Some(usize::MAX) => "unlimited",
        strict_rfc: None => "None (10)",
        chrome_source: "libwebrtc media/sctp/dcsctp_transport.cc::DcSctpTransport::CreateDcSctpOptions @ a222406d: \"Don't close the connection automatically on too many retransmissions\": max_retransmissions and max_init_retransmits none (dcsctp's own default is 10, net/dcsctp/public/dcsctp_options.h); an unreachable peer is left to ICE",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v: Option<usize>| match v {
            Some(limit) => b.with_sctp_max_retransmissions(limit),
            None => b.without_sctp_max_retransmissions(),
        },
        read: |s: &SettingEngine| sctp_max_retransmissions_shown(s.sctp_max_retransmissions),
    },
    {
        id: "datachannel.send-before-ack",
        setting: "SettingEngineBuilder::with_data_channel_send_before_ack",
        clause: "RFC 8832 6 (MAY), W3C webrtc-pc 6.2 send()",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "libwebrtc pc/sctp_data_channel.cc::SctpDataChannel::UpdateState @ a222406d: an in-band channel turns kOpen in kHandshakeWaitingForAck, once its DATA_CHANNEL_OPEN is sent; until the ACK its messages go ordered (SctpDataChannel::SendDataMessage)",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_data_channel_send_before_ack(v),
        read: |s: &SettingEngine| s.data_channel_send_before_ack,
    },
    // ---- RTP / RTCP ----
    {
        id: "track.msid-appdata-change-renews-track",
        setting: "SettingEngineBuilder::with_msid_appdata_change_renews_track",
        clause: "RFC 8830 3 (W3C webrtc-pc 5.3)",
        rfc: false => "false",
        chrome: false => "false",
        strict_rfc: true => "true",
        chrome_source: "libwebrtc pc/sdp_offer_answer.cc::SdpOfferAnswerHandler::ApplyRemoteDescriptionUpdateTransceiverState @ a222406d (lines 2815-2838): a remote section's msid gives the receiver its stream ids only (media_desc->streams()[0].stream_ids()), and a track event is fired when the receiver gains a stream or starts receiving, never for a new msid-appdata",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_msid_appdata_change_renews_track(v),
        read: |s: &SettingEngine| s.msid_appdata_change_renews_track,
    },
    {
        id: "track.source-departure-ends-track",
        setting: "SettingEngineBuilder::with_source_departure_ends_track",
        clause: "RFC 8830 3 (W3C webrtc-pc 9.3)",
        rfc: false => "false",
        chrome: false => "false",
        strict_rfc: true => "true",
        chrome_source: "libwebrtc modules/rtp_rtcp/source/rtcp_receiver.cc::RTCPReceiver::HandleBye @ a222406d (lines 643-661): an RTCP BYE clears the round-trip times, the sender's report blocks, the last FIR and its receiver reference times; nothing there ends the track",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_source_departure_ends_track(v),
        read: |s: &SettingEngine| s.source_departure_ends_track,
    },
    {
        id: "rtp.ssrc-per-clock-rate",
        setting: "SettingEngineBuilder::with_ssrc_per_clock_rate",
        clause: "RFC 7160 4.1",
        rfc: false => "false",
        chrome: false => "false",
        strict_rfc: true => "true",
        chrome_source: "libwebrtc audio/audio_send_stream.cc::AudioSendStream::ConfigureStream @ a222406d: \"Configuration parameters which cannot be changed\", RTC_DCHECK(old_config.rtp.ssrc == new_config.rtp.ssrc) when the send codec changes",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_ssrc_per_clock_rate(v),
        read: |s: &SettingEngine| s.ssrc_per_clock_rate,
    },
    {
        id: "rtcp.strict-validity",
        setting: "SettingEngineBuilder::with_strict_rtcp_validity",
        clause: "RFC 3550 A.2, 6.4.1",
        rfc: false => "false",
        chrome: false => "false",
        strict_rfc: true => "true",
        chrome_source: "libwebrtc modules/rtp_rtcp/source/rtcp_receiver.cc::RTCPReceiver::ParseCompoundPacket @ a222406d: each packet whose CommonHeader parses (version 2, length, its own padding: rtcp_packet/common_header.cc::CommonHeader::Parse) is handled, the first one need not be an SR or RR and padding is taken on any",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_strict_rtcp_validity(v),
        read: |s: &SettingEngine| s.strict_rtcp_validity,
    },
    {
        id: "ecn.initiation",
        setting: "SettingEngineBuilder::with_ecn_initiation",
        clause: "RFC 6679 7.2.1, RFC 8888 7",
        rfc: EcnInitiation::RtpAndRtcp => "RtpAndRtcp",
        chrome: EcnInitiation::LeapOfFaith => "LeapOfFaith",
        strict_rfc: EcnInitiation::RtpAndRtcp => "RtpAndRtcp",
        chrome_source: "libwebrtc modules/congestion_controller/ect1_policy.cc::Ect1Policy::ShouldSendEct1 @ a222406d: every packet goes ECT(1) from the first once RFC 8888 feedback is negotiated and the controller adapts to ECN, until no feedback came for 500 ms (kEct1FeedbackTimeoutBeforeAck) or feedback shows it bleached; RFC 8888 is behind the WebRTC-RFC8888CongestionControlFeedback field trial (pc/media_session.cc::OfferRfc8888), off by default",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_ecn_initiation(v),
        read: |s: &SettingEngine| s.ecn_initiation,
    },
    {
        id: "ecn.marking",
        setting: "SettingEngineBuilder::with_ecn_marking",
        clause: "RFC 6679 7.3.1, RFC 9331",
        rfc: EcnMarking::Rfc6679 => "Rfc6679",
        chrome: EcnMarking::L4s => "L4s",
        strict_rfc: EcnMarking::Rfc6679 => "Rfc6679",
        chrome_source: "libwebrtc modules/congestion_controller/ect1_policy.cc::Ect1Policy @ a222406d and media/base/media_channel_impl.cc (rtc_options.ect_1 = options.send_as_ect1): the codepoint is ECT(1) (L4S); behind the WebRTC-RFC8888CongestionControlFeedback field trial",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_ecn_marking(v),
        read: |s: &SettingEngine| s.ecn_marking,
    },
    {
        id: "ecn.without-signalling",
        setting: "SettingEngineBuilder::with_ecn_without_signalling",
        clause: "RFC 6679 6.1.1, RFC 8888 7",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "libwebrtc call/rtp_transport_controller_send.cc @ a222406d: Ect1Policy::SetFeedbackSupportsEcn(rfc_8888_feedback_negotiated) is the only negotiation; api/webrtc_sdp.cc has no a=ecn-capable-rtp, and no Chromium fixture carries it",
        evidence: Source,
        apply_setting: |b: SettingEngineBuilder, v| b.with_ecn_without_signalling(v),
        read: |s: &SettingEngine| s.ecn_without_signalling,
    },
    // ---- media engine ----
    {
        id: "vp9.receiver-limits",
        setting: "MediaEngine::set_vp9_receiver_limits",
        clause: "RFC 9628 6",
        rfc: false => "false",
        chrome: false => "false",
        strict_rfc: true => "true",
        chrome_source: "Chromium's VP9 formats carry profile-id only, no max-fr / max-fs (fixture chromium--reflect-video-vp9--1-offer.sdp)",
        evidence: Observed,
        apply_media: |m: &mut MediaEngine, v| m.set_vp9_receiver_limits(v),
        read: |m: &MediaEngine| m.vp9_receiver_limits,
    },
    // ---- interceptors ----
    {
        id: "rtcp.t-rr-interval",
        setting: "DefaultInterceptorOptions::rtcp_t_rr_interval",
        clause: "RFC 4585 3.4, 4.2",
        rfc: Duration::ZERO => "0ns",
        chrome: Duration::from_secs(1) => "1s",
        strict_rfc: Duration::ZERO => "0ns",
        performance: Duration::from_secs(1) => "1s",
        performance_note: "RFC 4585 3.4 (m): T_rr_interval is \"an OPTIONAL minimal interval\" between Regular RTCP packets, set by the application; 3.5.3 suppresses regular packets inside it and holds no feedback; RFC 5506 3.3 names trr-int as the remedy for regular reports \"of higher density\" than needed. Kept local, not announced as a=rtcp-fb:* trr-int: it states only this endpoint's own minimum (RFC 4585 4.2), and no browser fixture carries the line. Measured (tests/rtcp_rate_trace_rtc2rtc.rs, 30 s, a=rtcp-rsize): 1 Mbit/s one way, sender 13.2 -> 1.4 regular packets/s, 27.3 -> 3.8 SR/s, RTCP 4.20% -> 1.45% of the media; both ways 19.4 -> 1.5 regular/s, 4.91% -> 1.44%; without rsize both ways 5.03% -> 2.25%. Cost: report blocks to the sender (RTT from LSR/DLSR, RR loss, the RTP circuit breaker's input) 12.2/s -> 1.2/s, longest gap 214 ms -> 1.36 s; the breaker counts its windows in reports (MEDIA_TIMEOUT 5, CB_INTERVAL at least 3), so it reacts in seconds instead of under one. Unchanged: the NACK (120 ms -> 114-120 ms from loss to request), the congestion control feedback (20/s, 50 ms apart), and Gcc's loss and RTT, which come from that feedback whenever transport-cc or RFC 8888 is negotiated",
        chrome_source: "libwebrtc modules/rtp_rtcp/source/rtp_rtcp_impl2.cc (RTCPSender configuration) @ a222406d: rtcp_report_interval 5 s for audio, 1 s for video (media/base/media_config.h rtcp_report_interval_ms), drawn from [0.5, 1.5] of it, and for video sent above 72 kbit/s min(360 s / kbit/s, 1 s) (rtcp_sender.cc::RTCPSender::ComputeTimeUntilNextReport); 1 s is the video value, see \"not expressible\" for audio",
        evidence: Source,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.rtcp_t_rr_interval = v,
        read: |o: &DefaultInterceptorOptions| o.rtcp_t_rr_interval,
    },
    {
        id: "rtcp.immediate-congestion-feedback",
        setting: "DefaultInterceptorOptions::rtcp_immediate_congestion_feedback",
        clause: "RFC 4585 3.5.2",
        rfc: true => "true",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "libwebrtc modules/remote_bitrate_estimator/transport_sequence_number_feedback_generator.cc::TransportSequenceNumberFeedbackGenenerator::Process @ a222406d: transport-wide feedback goes on its own timer, every 100 ms (kDefaultInterval) adjusted between 50 and 250 ms to the bitrate, outside the RTCP report schedule",
        evidence: Source,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.rtcp_immediate_congestion_feedback = v,
        read: |o: &DefaultInterceptorOptions| o.rtcp_immediate_congestion_feedback,
    },
    {
        id: "rtcp.congestion-feedback-in-budget",
        setting: "DefaultInterceptorOptions::rtcp_congestion_feedback_in_budget",
        clause: "RFC 3550 6.2, RFC 4585 3.5.3",
        rfc: false => "false",
        chrome: false => "false",
        strict_rfc: false => "false",
        performance: true => "true",
        performance_note: "RFC 3550 6.2: RTCP, feedback included, is 5% of the session bandwidth; the regular interval computed with what the congestion control feedback (sent and received, last 2 s) leaves is applied as a T_rr_interval (RFC 4585 3.5.3: suppression only), at most 5 s (RFC 4585 5). Measured with the next three rows, 30 s, a=rtcp-rsize: 24 kbit/s audio (38.5 kbit/s on the wire) RTCP 12.15% -> 4.49% of the media, without rsize 14.34% -> 6.06% (the minimal compound around each feedback packet is larger than the cadence counts); 100 kbit/s audio and video (203 kbit/s on the wire) 5.96% -> 2.75%. Cost: at 24 kbit/s one regular report every 5 s (report blocks 1.9/s -> 0.2/s, longest gap 657 ms -> 5.2 s); the circuit breaker's RTCP timeout (3 Td, Td at most 5 s) still holds. With RED on audio by default (RFC 2198, train 11) the 24 kbit/s call is 64.5 kbit/s on the wire: 7.46% -> 3.57%",
        chrome_source: "libwebrtc modules/remote_bitrate_estimator/transport_sequence_number_feedback_generator.cc::OnSendBandwidthEstimateChanged @ a222406d: transport feedback is sized to 5% of the send estimate on its own, and rtcp_sender.cc::RTCPSender::ComputeTimeUntilNextReport spaces the reports by their fixed interval whatever the feedback takes",
        evidence: Source,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.rtcp_congestion_feedback_in_budget = v,
        read: |o: &DefaultInterceptorOptions| o.rtcp_congestion_feedback_in_budget,
    },
    {
        id: "rtcp.minimum-session-bandwidth",
        setting: "DefaultInterceptorOptions::rtcp_minimum_session_bandwidth",
        clause: "RFC 3550 6.2",
        rfc: 64_000 => "64000",
        chrome: 64_000 => "64000",
        strict_rfc: 64_000 => "64000",
        performance: 16_000 => "16000",
        performance_note: "RFC 3550 6.2 takes the session bandwidth as what the session expects; the media measured both ways is used down to 16 kbit/s instead of 64 kbit/s, so a 24 kbit/s call's RTCP is 5% of 24 kbit/s, not of 64. Alone (rtc-interceptor tests/rtcp_session_timing.rs::the_minimum_session_bandwidth_lets_rtcp_follow_low_media): a 27 kbit/s sender sends 0.3 to 0.6 times the default's regular reports. In the profile it sizes the budget of rtcp.congestion-feedback-in-budget",
        chrome_source: "libwebrtc modules/rtp_rtcp/source/rtcp_sender.cc::RTCPSender::ComputeTimeUntilNextReport @ a222406d: the report interval is fixed (1 s video, 5 s audio, min(360 s / kbit/s, 1 s) above 72 kbit/s), no RTCP bandwidth is computed, so there is no floor to differ: the engine's value stands",
        evidence: Source,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.rtcp_minimum_session_bandwidth = v,
        read: |o: &DefaultInterceptorOptions| o.rtcp_minimum_session_bandwidth,
    },
    {
        id: "cc.feedback-share",
        setting: "DefaultInterceptorOptions::congestion_feedback_share",
        clause: "RFC 8888 4, RFC 3550 6.2",
        rfc: 0.05 => "0.05",
        chrome: 0.05 => "0.05",
        strict_rfc: 0.05 => "0.05",
        performance: 0.025 => "0.025",
        performance_note: "RFC 8888 4 leaves the interval to \"the acceptable feedback overhead\"; half of the 5% goes to the feedback, the rest to the reports. Measured: 100 kbit/s audio and video 12.2 -> 4.3 feedback packets/s (longest gap 137 -> 399 ms); 24 kbit/s audio 4.0 -> 2.0/s (250 -> 500 ms); 1 Mbit/s unchanged (20/s, the 50 ms floor). Cost (rtc-interceptor tests/gcc_feedback_rate.rs, 500 ms against 250 ms): Gcc settles in 0.5 s either way on a 150 kbit/s path, 6.0 s against 5.5 s on a 500 kbit/s one; a Gcc sender with probing fed by a Performance receiver reaches 2 Mbit/s from 300 kbit/s in 0.62 s (default 0.49 s; tests/congestion_feedback_rate.rs::a_gcc_sender_fed_by_a_performance_receiver_ramps_within_a_second)",
        chrome_source: "libwebrtc modules/remote_bitrate_estimator/transport_sequence_number_feedback_generator.cc::OnSendBandwidthEstimateChanged @ a222406d: \"Let TWCC reports occupy 5% of total bandwidth\", twcc_bitrate = 0.05 * estimate",
        evidence: Source,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.congestion_feedback_share = v,
        read: |o: &DefaultInterceptorOptions| o.congestion_feedback_share,
    },
    {
        id: "cc.feedback-max-interval",
        setting: "DefaultInterceptorOptions::congestion_feedback_max_interval",
        clause: "RFC 8888 4, draft-holmer-rmcat-transport-wide-cc-extensions-01 3",
        rfc: Duration::from_millis(250) => "250ms",
        chrome: Duration::from_millis(250) => "250ms",
        strict_rfc: Duration::from_millis(250) => "250ms",
        performance: Duration::from_millis(500) => "500ms",
        performance_note: "draft-holmer-rmcat-transport-wide-cc-extensions-01 3: \"in cases of low uplink bandwidth it is acceptable to send them less frequently, e.g., for instance once per RTT\"; RFC 8888 4 sets no bound (its 50-200 ms is a measured range of some algorithms, not a requirement). Takes effect only below about 270 kbit/s of media (where 2.5% no longer holds a packet in 250 ms); figures and cost with cc.feedback-share",
        chrome_source: "libwebrtc modules/remote_bitrate_estimator/transport_sequence_number_feedback_generator.cc @ a222406d: kMaxInterval = TimeDelta::Millis(250), the interval kTwccReportSize / twcc_bitrate held between kMinInterval 50 ms and it",
        evidence: Source,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.congestion_feedback_max_interval = v,
        read: |o: &DefaultInterceptorOptions| o.congestion_feedback_max_interval,
    },
    {
        id: "rtcp.report-from-every-ssrc",
        setting: "DefaultInterceptorOptions::rtcp_report_from_every_ssrc",
        clause: "RFC 8108 5.1",
        rfc: false => "false",
        chrome: false => "false",
        strict_rfc: true => "true",
        chrome_source: "libwebrtc audio/channel_receive.cc (ReceiveStatistics per receive channel) and call/rtp_video_sender.cc (send modules with no receive statistics) @ a222406d: rtcp_sender.cc::RTCPSender::CreateReportBlocks reports each remote SSRC from the one receive module, not from every local SSRC",
        evidence: Source,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.rtcp_report_from_every_ssrc = v,
        read: |o: &DefaultInterceptorOptions| o.rtcp_report_from_every_ssrc,
    },
    {
        id: "twcc.rereport-received",
        setting: "DefaultInterceptorOptions::twcc_rereport_received",
        clause: "draft-holmer-rmcat-transport-wide-cc-extensions-01 3.1.1",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "libwebrtc modules/remote_bitrate_estimator/transport_sequence_number_feedback_generator.cc::OnReceivedPacket @ a222406d: a late packet below periodic_window_start_seq_ moves the window back, and MaybeBuildFeedbackPacket reports every packet received from there, those reported already included",
        evidence: Source,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.twcc_rereport_received = v,
        read: |o: &DefaultInterceptorOptions| o.twcc_rereport_received,
    },
    {
        id: "rtp.abs-send-time-on-audio",
        setting: "DefaultInterceptorOptions::abs_send_time_on_audio",
        clause: "RFC 8285 5 (draft-ietf-rmcat-gcc-02 3)",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "Chromium's audio offers carry the abs-send-time extension (fixture chromium--reflect-audio-opus--1-offer.sdp)",
        evidence: Observed,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.abs_send_time_on_audio = v,
        read: |o: &DefaultInterceptorOptions| o.abs_send_time_on_audio,
    },
    {
        id: "rtcp.receiver-reference-time-on-audio",
        setting: "DefaultInterceptorOptions::receiver_reference_time_on_audio",
        clause: "RFC 3611 4.4, 5.1",
        rfc: false => "false",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "Chromium's audio offers carry a=rtcp-xr:rcvr-rtt=all (fixture chromium--reflect-audio-opus--1-offer.sdp)",
        evidence: Observed,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.receiver_reference_time_on_audio = v,
        read: |o: &DefaultInterceptorOptions| o.receiver_reference_time_on_audio,
    },
    {
        id: "gcc.threshold-time-base",
        setting: "DefaultInterceptorOptions::gcc_threshold_time_base",
        clause: "draft-ietf-rmcat-gcc-02 5.4",
        rfc: ThresholdTimeBase::Departure => "Departure",
        chrome: ThresholdTimeBase::ArrivalCapped => "ArrivalCapped",
        strict_rfc: ThresholdTimeBase::Arrival => "Arrival",
        chrome_source: "libwebrtc modules/congestion_controller/goog_cc/trendline_estimator.cc::TrendlineEstimator::UpdateThreshold @ a222406d: the step is now_ms - last_update_ms_ capped at kMaxTimeDeltaMs 100, where now_ms is the packet's receive_time (delay_based_bwe.cc::DelayBasedBwe::IncomingPacketFeedback): the arrival gaps, capped; remote_bitrate_estimator/overuse_detector.cc the same",
        evidence: Source,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.gcc_threshold_time_base = v,
        read: |o: &DefaultInterceptorOptions| o.gcc_threshold_time_base,
    },
    {
        id: "gcc.one-decrease-per-round-trip",
        setting: "DefaultInterceptorOptions::gcc_one_decrease_per_round_trip",
        clause: "draft-ietf-rmcat-gcc-02 5.5",
        rfc: true => "true",
        chrome: true => "true",
        strict_rfc: false => "false",
        chrome_source: "libwebrtc modules/remote_bitrate_estimator/aimd_rate_control.cc::AimdRateControl::TimeToReduceFurther @ a222406d: a decrease waits the round trip time held between 10 and 200 ms since the last change, or for the acknowledged rate to fall under half the estimate (delay_based_bwe.cc calls it on overuse)",
        evidence: Source,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.gcc_one_decrease_per_round_trip = v,
        read: |o: &DefaultInterceptorOptions| o.gcc_one_decrease_per_round_trip,
    },
    {
        id: "pacer.queue-overflow",
        setting: "DefaultInterceptorOptions::pacer_queue_overflow",
        clause: "RFC 8836 2, RFC 8083 4",
        rfc: interceptor::PacerQueueOverflow::Drop => "Drop",
        chrome: interceptor::PacerQueueOverflow::Drain => "Drain",
        strict_rfc: interceptor::PacerQueueOverflow::Drop => "Drop",
        chrome_source: "libwebrtc modules/pacing/pacing_controller.cc::PacingController::MaybeUpdateMediaRateDueToLongQueue @ a222406d (lines 706-728): with drain_large_queues (on by default, pacing_controller.h line 98, unless the WebRTC-Pacer-DrainQueue trial is disabled, pacing_controller.cc lines 62-63) the media rate is raised to queue size / (queue_time_limit - average queue time) when that exceeds the pacing rate, queue_time_limit kMaxExpectedQueueLength 2 s (pacing_controller.h lines 92, 104); nothing is dropped. Performance: same as Rfc",
        evidence: Source,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.pacer_queue_overflow = v,
        read: |o: &DefaultInterceptorOptions| o.pacer_queue_overflow,
    },
    {
        id: "nack.max-requests-per-packet",
        setting: "DefaultInterceptorOptions::nack_max_nacks_per_packet",
        clause: "RFC 4588 6.3, Appendix A",
        rfc: 0 => "0",
        chrome: 100 => "100",
        strict_rfc: 0 => "0",
        chrome_source: "libwebrtc modules/video_coding/nack_requester.cc @ a222406d: kMaxNackRetries = 100 (line 39, \"Number of times a packet can be nacked before giving up. Nack is sent at most every RTT\", lines 37-38); NackRequester::GetNackBatch (lines 235-265) removes a packet from the NACK list once its retries reach it (lines 251-256). 0 is unlimited (NackGeneratorBuilder::with_max_nacks_per_packet). Not 10: the interceptor's SUGGESTED_MAX_NACKS_PER_PACKET says 10 is kMaxNackRetries, which it is not at this revision. libwebrtc's packet-count limits are under \"not expressible\". Performance: same as Rfc",
        evidence: Source,
        apply_interceptors: |o: &mut DefaultInterceptorOptions, v| o.nack_max_nacks_per_packet = v,
        read: |o: &DefaultInterceptorOptions| o.nack_max_nacks_per_packet,
    },
}

/// Why a setting is not governed by the profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotGovernedClass {
    /// A capability the engine has and Chrome lacks: the same in every profile (it negotiates
    /// down with a Chrome peer, or a Chrome peer does not notice it).
    EngineOnly,
    /// Examined: the engine's default is libwebrtc's too, or the RFC form already.
    Same,
    /// Not a default with a libwebrtc counterpart: input the application gives (credentials,
    /// filters, a provider, limits of its own deployment), or a setting with no default to
    /// choose.
    Input,
    /// Deprecated and not read by the engine.
    Deprecated,
}

/// A setting the profiles leave alone, and why.
pub(crate) struct NotGoverned {
    pub(crate) setting: &'static str,
    pub(crate) class: NotGovernedClass,
    pub(crate) note: &'static str,
}

/// Every setting of [`SettingEngineBuilder`], [`MediaEngine`] and
/// [`DefaultInterceptorOptions`] that is not in [`GOVERNED`]. The completeness test fails when
/// a setting is in neither. `scripts/behaviour-profiles.py` renders it: keep each entry's three
/// fields on lines of their own.
pub(crate) static NOT_GOVERNED: &[NotGoverned] = &[
    // ---- engine-only capabilities (class 2) ----
    NotGoverned {
        setting: "SettingEngineBuilder::with_sctp_message_interleaving",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 8260 I-DATA announced; libwebrtc announces it only under the WebRTC-DataChannelMessageInterleaving field trial (media/sctp/dcsctp_transport.cc::CreateDcSctpOptions @ a222406d), off by default, so it negotiates down to DATA chunks",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_sctp_path_mtu_discovery",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 8899 PLPMTUD probes (HEARTBEAT + PAD); a peer without it answers the HEARTBEAT and nothing else changes",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_sctp_zero_checksum",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 9653 zero checksum, used only when the peer announces it too; dcsctp has it but libwebrtc leaves zero_checksum_alternate_error_detection_method at None (net/dcsctp/public/dcsctp_options.h @ a222406d), so it announces none",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_sctp_weighted_fair_queueing",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 8260 3.6 scheduling of the engine's own sends; not visible to the peer",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_disable_sdp_tls_id",
        class: NotGovernedClass::EngineOnly,
        note: "a=tls-id (RFC 8842) is written; libwebrtc writes and reads none (api/webrtc_sdp.cc @ a222406d has no tls-id)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_tcp_candidate_gathering",
        class: NotGovernedClass::EngineOnly,
        note: "engine-run ICE-TCP; the train's Chromium gathered no TCP candidate (matrix: \"ICE-TCP\" cells na-browser)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_tcp_simultaneous_open",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 6544 S-O candidates; libwebrtc gathers none and connects to one as to a passive candidate",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_tcp_close_unused_connections",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 6544 8 housekeeping of the engine's own ICE-TCP connections",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_turn_over_streams",
        class: NotGovernedClass::EngineOnly,
        note: "engine-run TURN over TCP / TLS",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_turn_tcp_relay",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 6062 TCP allocations; libwebrtc makes none",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_server_reflexive_gathering",
        class: NotGovernedClass::EngineOnly,
        note: "who gathers server-reflexive candidates (engine or application); a sans-I/O choice",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_relay_gathering",
        class: NotGovernedClass::EngineOnly,
        note: "who gathers relayed candidates (engine or application); a sans-I/O choice",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_ecn",
        class: NotGovernedClass::EngineOnly,
        note: "ECN needs the application's socket layer; off in every profile (the ECN rows above apply when it is on)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_srtp_automatic_rekeying",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 5764 4.4 re-keying by a new association; libwebrtc has none, and a browser peer ignores the new tls-id",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_video_receive_limits",
        class: NotGovernedClass::EngineOnly,
        note: "a=imageattr (RFC 6236); none by default in every profile, Chromium writes none",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_codec_video_receive_limits",
        class: NotGovernedClass::EngineOnly,
        note: "a=imageattr per codec; none by default",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_candidate_pair_proposals",
        class: NotGovernedClass::EngineOnly,
        note: "webrtc-extensions 7 icecandidatepairnominate; off in every profile (Chrome does not ship the event)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_ice_unauthenticated_requests",
        class: NotGovernedClass::Same,
        note: "RFC 8489 9.1.3 error responses; libwebrtc answers 400 / 401 as well",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_ice_data_from_selected_pair_only",
        class: NotGovernedClass::Same,
        note: "off: data from any valid pair is accepted (RFC 8445 12.2), as libwebrtc accepts it on any connection",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_ice_pacing",
        class: NotGovernedClass::Same,
        note: "Ta 50 ms by default, as RFC 8445 14.2; libwebrtc's checks go every kWeakPingInterval 48 ms while no pair is writable (p2p/base/p2p_constants.h @ a222406d), close enough not to change the proposal. Whether the default is written is the ice.default-pacing-stated row",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_ice_pacing_group",
        class: NotGovernedClass::Input,
        note: "a budget shared between the application's peer connections",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_ice_timeouts",
        class: NotGovernedClass::Same,
        note: "consent every 4 to 6 s and expiry at 30 s (RFC 7675). libwebrtc pings a strong, stable connection every kStrongAndStableWritableConnectionPingInterval 2.5 s (900 ms while stabilising) and declares it dead after kDeadConnectionReceiveTimeout 30 s (p2p/base/p2p_constants.h @ a222406d); a period under 4 s is what RFC 7675 5.1 forbids (\"MUST NOT ... less than 4 seconds\"): not expressible, see below",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_ice_connection_attempts",
        class: NotGovernedClass::Same,
        note: "Rc 7 / RTO doubling (RFC 8489 6.2.1). libwebrtc does not retransmit a connectivity check at all: each is sent once (p2p/base/connection.cc::ConnectionRequest::OnSent, response timeout kConnectionResponseTimeout 60 s) and the pair is pinged again on the channel's schedule (see \"not expressible\")",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_multicast_dns_mode",
        class: NotGovernedClass::Same,
        note: "QueryOnly: remote .local candidates resolved, host addresses written as they are. Chrome hides them behind mDNS names only for a page without media permission; with it (what an application is) it writes them",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_sdp_media_level_fingerprints",
        class: NotGovernedClass::Same,
        note: "media level, as Chromium writes them (fixtures)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_implicit_rollback",
        class: NotGovernedClass::Same,
        note: "on, as browsers (perfect negotiation); RFC 9429 does not forbid it",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_msid_removal_ends_track",
        class: NotGovernedClass::Same,
        note: "off: W3C process remote tracks, what Chrome does; RFC 8830 3 is a \"can\"",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_nominated_candidates_only",
        class: NotGovernedClass::Same,
        note: "off: RFC 9429 5.2.2 (every gathered candidate), as Chromium; RFC 8839 4.4.1.2.2 says the opposite",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_dtls_new_association_without_ice_restart",
        class: NotGovernedClass::Same,
        note: "off (RFC 9429 5.8.3, 5.11); Chromium never asks for a new association",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_unnegotiated_header_extensions",
        class: NotGovernedClass::Same,
        note: "off: only negotiated ids are sent (RFC 8285 4.1.2), as libwebrtc",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_unnegotiated_rtcp_feedback",
        class: NotGovernedClass::Same,
        note: "off: only negotiated feedback (RFC 4585 4.2), as libwebrtc",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_rtcp_session_omitted",
        class: NotGovernedClass::Same,
        note: "off: RTCP is used (RFC 8834 4.1)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_dtls_cipher_suites",
        class: NotGovernedClass::Same,
        note: "DTLS 1.2: ECDSA-AES128-GCM, RSA-AES128-GCM, ECDSA-CHACHA20. libwebrtc offers BoringSSL's \"DEFAULT:!NULL:!aNULL:!SHA256:!SHA384:!aECDH:!AESGCM+AES256:!aPSK:!3DES\" (rtc_base/openssl_stream_adapter.cc @ a222406d), the same AEAD suites in BoringSSL's order and the ECDHE CBC-SHA suites as well, which the engine leaves out (a hardening, kept in every profile); DTLS 1.3 (TLS_AES_128_GCM_SHA256 first) both offer",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_answering_dtls_role",
        class: NotGovernedClass::Same,
        note: "an answer to actpass takes the client role (a=setup:active), as libwebrtc",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_sctp_max_streams",
        class: NotGovernedClass::Same,
        note: "65535, as dcsctp announces (announced_maximum_incoming_streams / outgoing, net/dcsctp/public/dcsctp_options.h @ a222406d)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_data_channel_max_buffer_size",
        class: NotGovernedClass::Same,
        note: "W3C rule with a 16 MiB send buffer, libwebrtc's DataChannelInterface::MaxSendQueueSize (api/data_channel_interface.h @ a222406d)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_dcep_handshake_timeout",
        class: NotGovernedClass::Same,
        note: "none (RFC 8832 has none); libwebrtc has none",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_ignore_rid_pause_for_recv",
        class: NotGovernedClass::Same,
        note: "applies with rid pause marks only",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_write_ssrc_attributes_for_simulcast",
        class: NotGovernedClass::Same,
        note: "off: rid-based simulcast sections carry no a=ssrc lines, as Chromium's (fixture chromium--simulcast-three-rids-reach-rust--1-offer.sdp)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_disable_media_engine_multiple_codecs",
        class: NotGovernedClass::Same,
        note: "off: each section negotiates its own formats (RFC 9429 5.10)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_non_interactive_video",
        class: NotGovernedClass::Same,
        note: "off: DSCP AF4x for video (RFC 8837), as browsers",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_srtp_key_lifetime",
        class: NotGovernedClass::Same,
        note: "the profile's lifetime (RFC 5764 4.1.2, RFC 7714)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_disable_certificate_fingerprint_verification",
        class: NotGovernedClass::Same,
        note: "verification on in every profile (a security check)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_allow_insecure_verification_algorithm",
        class: NotGovernedClass::Same,
        note: "off in every profile (a security check)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_lite",
        class: NotGovernedClass::Same,
        note: "full ICE, as a browser",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_remote_candidate_scopes",
        class: NotGovernedClass::Same,
        note: "loopback / link-local remote candidates paired only within their scope (a hardening, kept in every profile)",
    },
    // ---- application input (no default to choose) ----
    NotGoverned {
        setting: "SettingEngineBuilder::with_crypto_provider",
        class: NotGovernedClass::Input,
        note: "the cryptographic provider",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_turn_allocation_refresh_interval_cap",
        class: NotGovernedClass::Input,
        note: "a NAT keep-alive need of the deployment",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_host_acceptance_min_wait",
        class: NotGovernedClass::Input,
        note: "nomination wait for host pairs",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_srflx_acceptance_min_wait",
        class: NotGovernedClass::Input,
        note: "nomination wait for server-reflexive pairs",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_prflx_acceptance_min_wait",
        class: NotGovernedClass::Input,
        note: "nomination wait for peer-reflexive pairs",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_relay_acceptance_min_wait",
        class: NotGovernedClass::Input,
        note: "nomination wait for relayed pairs",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_network_types",
        class: NotGovernedClass::Input,
        note: "which networks the application gathers on",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_nat_1to1_ips",
        class: NotGovernedClass::Input,
        note: "the deployment's public addresses",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_multicast_dns_timeout",
        class: NotGovernedClass::Input,
        note: "mDNS query timeout",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_multicast_dns_local_name",
        class: NotGovernedClass::Input,
        note: "a fixed mDNS name",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_multicast_dns_local_ip",
        class: NotGovernedClass::Input,
        note: "the mDNS answer address",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_multicast_dns_first_query_delay",
        class: NotGovernedClass::Same,
        note: "RFC 6762 5.2 delay on (mDNS rows are the engine's; Chrome's resolver is the platform's)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_multicast_dns_multi_question_delay",
        class: NotGovernedClass::Same,
        note: "RFC 6762 6.3 delay on",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_multicast_dns_destination_reported",
        class: NotGovernedClass::Input,
        note: "what the application's socket layer reports",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_multicast_dns_unicast_response",
        class: NotGovernedClass::Input,
        note: "depends on the application's socket being the only one on port 5353",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_multicast_dns_rate_limit",
        class: NotGovernedClass::Input,
        note: "a limit shared between the application's peer connections",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_discard_local_candidates_during_ice_restart",
        class: NotGovernedClass::Input,
        note: "whether the application's sockets outlive an ICE restart",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_ice_credentials",
        class: NotGovernedClass::Input,
        note: "fixed credentials for tests",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_ice_tie_breaker",
        class: NotGovernedClass::Input,
        note: "a fixed tiebreaker for tests",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_remote_address_filter",
        class: NotGovernedClass::Input,
        note: "the host's network policy",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_dtls_replay_protection_window",
        class: NotGovernedClass::Input,
        note: "replay window",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_srtp_replay_protection_window",
        class: NotGovernedClass::Input,
        note: "replay window",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_srtcp_replay_protection_window",
        class: NotGovernedClass::Input,
        note: "replay window",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_mid_generator",
        class: NotGovernedClass::Input,
        note: "the application's mid naming",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_sctp_max_receive_buffer_size",
        class: NotGovernedClass::Input,
        note: "memory per connection",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_sctp_mtu",
        class: NotGovernedClass::Input,
        note: "a known path budget (fixing it turns path MTU discovery off)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_stream_limits",
        class: NotGovernedClass::Input,
        note: "limits of the engine's stream transports",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_turn_tls",
        class: NotGovernedClass::Input,
        note: "roots or a verifier for TURN over TLS",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_behaviour_profile",
        class: NotGovernedClass::Input,
        note: "the profile itself",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::without_sctp_rto",
        class: NotGovernedClass::Input,
        note: "back to the RFC 9260 timers (the sctp.rto row's Rfc value)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::without_sctp_max_retransmissions",
        class: NotGovernedClass::Input,
        note: "back to RFC 9260's 10 (the sctp.max-retransmissions row's Rfc value)",
    },
    // ---- deprecated, not read ----
    NotGoverned {
        setting: "SettingEngineBuilder::with_include_loopback_candidate",
        class: NotGovernedClass::Deprecated,
        note: "not read: the engine gathers no host candidates",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_disable_media_engine_copy",
        class: NotGovernedClass::Deprecated,
        note: "not read",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_receive_mtu",
        class: NotGovernedClass::Deprecated,
        note: "not read",
    },
    // ---- media engine ----
    NotGoverned {
        setting: "MediaEngine::set_flexfec_with_retransmission",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 8627 flexfec answering rule; libwebrtc offers flexfec-03 only under the WebRTC-FlexFEC-03 field trial (pc/media_session.cc @ a222406d), off by default: the Chromium fixtures carry no FEC format but red / ulpfec",
    },
    NotGoverned {
        setting: "MediaEngine::set_audio_packet_time",
        class: NotGovernedClass::Same,
        note: "no a=ptime / a=maxptime, as Chromium (fixtures)",
    },
    NotGoverned {
        setting: "MediaEngine::set_header_extension_encryption",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 6904 encrypted header extensions offered beside the clear ones; libwebrtc's CryptoOptions has them on (api/crypto/crypto_options.h @ a222406d) but Chromium turns them on only with the kWebRtcEncryptedRtpHeaderExtensions feature (rtc_peer_connection_handler.cc @ Chromium 8dafa8bc), and takes the clear ones",
    },
    // ---- interceptor options ----
    NotGoverned {
        setting: "DefaultInterceptorOptions::congestion_feedback",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 8888 (ack ccfb) offered beside transport-cc; libwebrtc offers and accepts it only under the WebRTC-RFC8888CongestionControlFeedback field trial (pc/media_session.cc::OfferRfc8888 @ a222406d), so Chromium answers transport-cc",
    },
    NotGoverned {
        setting: "DefaultInterceptorOptions::unnegotiated_tmmbr",
        class: NotGovernedClass::EngineOnly,
        note: "TMMBR (RFC 5104) offered; Chromium answers no ccm tmmbr",
    },
    NotGoverned {
        setting: "DefaultInterceptorOptions::pacer_immediate_release",
        class: NotGovernedClass::Same,
        note: "a packet inside the budget leaves at once; libwebrtc's PacingController sends within its budget and lets a burst build up over send_burst_interval (modules/pacing/pacing_controller.h @ a222406d), which Chromium sets to 40 ms (rtc_peer_connection_handler.cc pacer_burst_interval @ Chromium 8dafa8bc)",
    },
    NotGoverned {
        setting: "DefaultInterceptorOptions::bandwidth_probing",
        class: NotGovernedClass::Same,
        note: "probing on, as libwebrtc's ProbeController (modules/congestion_controller/goog_cc/probe_controller.cc @ a222406d: exponential probes at 3x and 6x the start rate)",
    },
    NotGoverned {
        setting: "DefaultInterceptorOptions::rapid_synchronisation",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 6051 ntp-64 offered; Chromium answers without it",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_bundled_fingerprints_agreeing",
        class: NotGovernedClass::Same,
        note: "off: a bundled section's a=fingerprint is not used, the tagged section's is (RFC 8859 TRANSPORT, RFC 9143 7.1.3); `true` is a hardening beyond the RFCs, in no profile. libwebrtc the same: pc/jsep_transport_controller.cc::JsepTransportController::ApplyDescription_n @ a222406d (lines 868-892) points a bundled non-tagged section at the tagged section's transport and skips its transport description (\"continue;  // Skip code below.\")",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_cryptex_required_on_every_bundled_section",
        class: NotGovernedClass::Same,
        note: "off: a BUNDLE group's Cryptex is read from its tagged section (RFC 8859 TRANSPORT, RFC 9143 7.1.3); `true` is the JSEP stack's earlier strict reading, in no profile. libwebrtc reads it from the group's first RTP section too: pc/jsep_transport_controller.cc::BundleUsesCryptex @ a222406d (lines 80-90), used for jsep_description.transport_desc.cryptex (lines 918-921); Chromium's cryptex_policy is kDisabled by default",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_dtls_alpn",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 8833 ALPN (`webrtc`, `c-webrtc`) in the DTLS handshake, on in every profile; a peer that answers none connects as `webrtc` (RFC 8833 2). libwebrtc's DTLS has none: rtc_base/openssl_stream_adapter.cc @ a222406d sets no ALPN; its only ALPN is TLS, rtc_base/openssl_adapter.cc::OpenSSLAdapter::SetAlpnProtocols (line 228)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_dtls_connection_id",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 9146 / RFC 9147 9 connection ids, asked for only when the application gives a length (`None`, the extension asking for none, in every profile). No connection id code in the fetched libwebrtc sources (rtc_base/openssl_stream_adapter.cc, p2p/dtls/ @ a222406d); not checked further",
    },
    NotGoverned {
        setting: "DefaultInterceptorOptions::circuit_breaker_packet_size",
        class: NotGovernedClass::EngineOnly,
        note: "RFC 8083 circuit breaker's packet size s; libwebrtc has no RTP circuit breaker, so nothing of Chrome's to follow (searched @ a222406d: \"circuit\" appears only in modules/pacing/pacing_controller.cc's loop guard SetCircuitBreakerThreshold, lines 143-145, 477, 556)",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_sctp_inbound_reassembly_limit",
        class: NotGovernedClass::EngineOnly,
        note: "the ceiling on incomplete inbound messages held above SCTP, which exists because the engine's SCTP gives a message it cannot hold out in parts (RFC 9260 6.9 partial delivery) and the data channel layer joins them; 64 MiB in every profile. libwebrtc's dcSCTP has no partial delivery: a message is reassembled inside the receive window (net/dcsctp/public/dcsctp_options.h @ a222406d, max_receiver_window_buffer_size 5 MiB, line 86), and net/dcsctp/socket/dcsctp_socket.cc::DcSctpSocket::HandleDataCommon (lines 1157-1172) drops data while the reassembly queue is full and assembled messages wait, and aborts the association (OutOfResourceErrorCause) when none do; nothing of Chrome's to follow",
    },
    NotGoverned {
        setting: "DefaultInterceptorOptions::nack_retransmission_rate_limit",
        class: NotGovernedClass::Same,
        note: "UpToTarget in every profile on this base: the retransmissions alone held under the congestion controller's target (measured in tests/capacity_cap_video_rtc2rtc.rs, see RetransmissionRateLimit). libwebrtc limits retransmissions by a RateLimiter of their own: modules/rtp_rtcp/source/rtp_sender.cc::RTPSender::ReSendPacket @ a222406d (lines 331-333) drops a retransmission retransmission_rate_limiter_->TryUseRate refuses (rtc_base/rate_limiter.cc lines 37, 59); where its maximum is set to the target was not found in the snapshot (searched call/call.cc, call/rtp_transport_controller_send.{h,cc}, call/rtp_video_sender.cc, video/), so the Chrome value is unverified beyond that. Pending: conf/gcc-2-rfc-retransmission makes Rfc and StrictRfc WithinTarget (RFC 4588 7) and leaves Chrome and Performance UpToTarget, which turns this into a governed row",
    },
    NotGoverned {
        setting: "DefaultInterceptorOptions::rtcp_random",
        class: NotGovernedClass::Input,
        note: "an injected random source for the RTCP sessions (report interval variation, RFC 3550 6.3.1; early feedback dither, RFC 4585 3.5.2; SSRC and CNAME), for runs a seeded provider makes repeatable; `None` (rand) in every profile",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_audio_redundancy",
        class: NotGovernedClass::Same,
        note: "WhenPreferred in every profile: a local audio stream is sent in RED (RFC 2198) only when the remote description lists RED ahead of the primary (RFC 3264 5.1, 6.1). libwebrtc the same: media/engine/webrtc_voice_engine.cc::WebRtcVoiceSendChannel::SetSendCodecs @ a222406d (lines 1507-1641) looks for RED only among the codecs before the send codec (lines 1610-1622: \"RED codec needs to be negotiated before the actual codec they reference\", for (i = 0; i < send_codec_position; ++i))",
    },
    NotGoverned {
        setting: "SettingEngineBuilder::with_own_payload_types_in_answers",
        class: NotGovernedClass::Same,
        note: "off: an answer uses the offer's payload type numbers (RFC 3264 6.1 SHOULD). libwebrtc the same: pc/codec_vendor.cc::NegotiateCodecs @ a222406d (lines 801-...) \"Use their ID, if available\" (lines 846-848: negotiated.id = theirs->id), apt values remapped after (lines 853-)",
    },
];

/// What Chrome does that no setting of the engine can express.
pub(crate) struct NotExpressible {
    pub(crate) behaviour: &'static str,
    pub(crate) chrome: &'static str,
    pub(crate) needed: &'static str,
}

/// `scripts/behaviour-profiles.py` renders it: keep each entry's fields on lines of their own.
pub(crate) static NOT_EXPRESSIBLE: &[NotExpressible] = &[
    NotExpressible {
        behaviour: "NACK request limits counted in packets",
        chrome: "modules/video_coding/nack_requester.cc @ a222406d: a missing packet more than kMaxPacketAge 10,000 sequence numbers behind the newest is no longer asked for (lines 34, 210-211), and a NACK list that would pass kMaxNackPackets 1000 entries is cleared and a key frame requested instead (lines 35, 214-219). kMaxPacketAgeToNack 450 in video/rtp_video_stream_receiver2.cc (line 114) is not a NACK limit: it is the receive statistics' reordering threshold (SetMaxReorderingThreshold, lines 337-340)",
        needed: "limits in sequence numbers in NackGeneratorBuilder: its with_max_packet_age is a time (Duration), not a packet count, and no setting clears the list for a key frame. Both profiles keep no age limit (RFC 4588 6.3 gives none)",
    },
    NotExpressible {
        behaviour: "ICE connectivity check retransmission",
        chrome: "no retransmission: each check is sent once and given kConnectionResponseTimeout 60 s (p2p/base/connection.cc::ConnectionRequest::OnSent / resend_delay @ a222406d); the channel sends a new check every kWeakPingInterval 48 ms while no pair is writable, a pair with no answer being unreliable after 5 checks and 5 s (Connection::UpdateState). Only requests to STUN / TURN servers retransmit: STUN_INITIAL_RTO 250 ms doubling to STUN_MAX_RTO 8 s, 9 sends (p2p/base/stun_request.cc)",
        needed: "a check scheduler in rtc-ice that replaces transactions by new checks; the engine's checks are RFC 8489 transactions with RTO at least 500 ms (RFC 8445 14.3, a MUST: \"RTO = MAX (500ms, ...)\")",
    },
    NotExpressible {
        behaviour: "Consent / keepalive pings on the selected pair",
        chrome: "every kStrongAndStableWritableConnectionPingInterval 2.5 s on a strong, stable connection, 900 ms while it stabilises, 480 ms strong / 48 ms weak at the channel level (p2p/base/p2p_constants.h @ a222406d)",
        needed: "nothing that keeps RFC 7675 5.1: a period under 4 s is forbidden (MUST NOT), the engine raises it to 5 s",
    },
    NotExpressible {
        behaviour: "Candidate type preferences",
        chrome: "host 126, prflx 110, srflx 100, host TCP 90, prflx TCP 80, relayed UDP 3 / TCP 1 / TLS 0 (p2p/base/p2p_constants.h IcePriorityValue @ a222406d)",
        needed: "a candidate-priority policy in rtc-ice; the engine takes RFC 8445 5.1.2.2's (host 126, prflx 110, srflx 100, relayed 0) and for TCP the UDP preference less one (RFC 6544 4.2)",
    },
    NotExpressible {
        behaviour: "Payload type numbering and codec order",
        chrome: "Chromium's numbering (opus 111, red 63, VP8 96, VP9 98 / 100, AV1 45, H264 102...; fixtures)",
        needed: "a Chrome codec table; the application registers its own codecs with MediaEngine::register_codec. Payload types are negotiated, so this changes no behaviour",
    },
    NotExpressible {
        behaviour: "Header extensions the engine does not implement",
        chrome: "toffset, playout-delay, video-content-type, video-timing, color-space (fixtures)",
        needed: "an implementation of each; offering them without one would announce what the engine does not send",
    },
    NotExpressible {
        behaviour: "RTCP report interval per media type",
        chrome: "5 s for audio, 1 s for video, and for video sent above 72 kbit/s min(360 s / kbit/s, 1 s), drawn from [0.5, 1.5] of it (modules/rtp_rtcp/source/rtp_rtcp_impl2.cc, rtcp_sender.cc::RTCPSender::ComputeTimeUntilNextReport @ a222406d)",
        needed: "a per-kind interval in the RTCP session; the Chrome profile sets T_rr to 1 s for every section",
    },
    NotExpressible {
        behaviour: "Transports of an initial offer",
        chrome: "every section in one BUNDLE group whatever the bundle policy, max-compat included (pc/sdp_offer_answer.cc: bundle_enabled = use_rtp_mux; pc/media_session.cc::UpdateTransportInfoForBundle @ a222406d): one ice-ufrag in all sections, candidates for the first transport only",
        needed: "a bundle layout setting; the engine gives each media type a transport of its own under balanced and every section one under max-compat (RFC 9429 4.1.1), each with credentials of its own under Chrome's per-transport rule (sdp.unique-transport-credentials)",
    },
    NotExpressible {
        behaviour: "Candidate generation / network-id / network-cost",
        chrome: "a=candidate lines end with generation <n>, and network-id <n> / network-cost <n> where the network is known (api/candidate.cc::BuildCandidate @ a222406d; fixtures: generation 0 network-cost 999)",
        needed: "nothing cheap and harmless: network-id and network-cost are the application socket layer's knowledge of its interfaces, and a made-up cost would change libwebrtc's choice of pair (basic_ice_controller.cc::CompareCandidatePairNetworks prefers the lower cost); generation is redundant, since libwebrtc reads the ufrag the engine writes before it (p2p_transport_channel.cc::GetRemoteCandidateGeneration)",
    },
    NotExpressible {
        behaviour: "Google STUN attributes in connectivity checks",
        chrome: "GOOG-NETWORK-INFO in every check, GOOG-MISC-INFO / GOOG_PING, GOOG-DELTA and DTLS-in-STUN behind field trials (p2p/base/connection.cc::Connection::BuildPingRequest @ a222406d)",
        needed: "an implementation of libwebrtc's private attributes (comprehension-optional, RFC 8489 14: a peer without them ignores them)",
    },
    NotExpressible {
        behaviour: "Delay-based estimator filter",
        chrome: "a trendline filter: window 20, smoothing 0.9, threshold gain 4, adaptive threshold gains k_up 0.0087 (outside) / k_down 0.039 (inside) (modules/congestion_controller/goog_cc/trendline_estimator.cc / .h @ a222406d)",
        needed: "a trendline estimator in rtc-interceptor; the engine's adaptive threshold takes draft-ietf-rmcat-gcc-02 5.4's gains, K_u 0.01 / K_d 0.00018",
    },
    NotExpressible {
        behaviour: "SCTP INIT retransmissions",
        chrome: "unlimited (max_init_retransmits none, media/sctp/dcsctp_transport.cc::CreateDcSctpOptions @ a222406d)",
        needed: "a Max.Init.Retransmits setting on the setting engine; the engine keeps RFC 9260's 8",
    },
];

/// Sets every governed setting of the setting engine to `profile`'s value.
pub(crate) fn apply_to_setting_engine(
    mut builder: SettingEngineBuilder,
    profile: BehaviourProfile,
) -> SettingEngineBuilder {
    for row in GOVERNED {
        if let Hook::Setting { apply, .. } = row.hook {
            builder = apply(builder, profile);
        }
    }
    builder
}

/// Sets every governed setting of the media engine to `profile`'s value.
pub(crate) fn apply_to_media_engine(media_engine: &mut MediaEngine, profile: BehaviourProfile) {
    for row in GOVERNED {
        if let Hook::Media { apply, .. } = row.hook {
            apply(media_engine, profile);
        }
    }
}

/// Sets every governed interceptor option to `profile`'s value.
pub(crate) fn apply_to_interceptor_options(
    options: &mut DefaultInterceptorOptions,
    profile: BehaviourProfile,
) {
    for row in GOVERNED {
        if let Hook::Interceptors { apply, .. } = row.hook {
            apply(options, profile);
        }
    }
}
