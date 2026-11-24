#![no_main]
//! Parser target: the value of one typed attribute. The first byte picks the attribute, the
//! rest is the text after `a=<name>:`.
//!
//! Beyond "no panic": a value that parses is printed as text that parses again, and printing
//! that changes nothing.

use libfuzzer_sys::fuzz_target;
use rtci_sdp::attribute::*;
use rtci_sdp::description::common::{Address, Bandwidth, ConnectionInformation};
use rtci_sdp::extmap::ExtMap;

fn fixed_point<T: TypedAttribute>(value: &str) {
    let Ok(parsed) = T::parse(value) else {
        return;
    };
    let printed = parsed.to_string();
    let again = T::parse(&printed)
        .unwrap_or_else(|e| panic!("a={}:{printed:?} does not parse again: {e}", T::NAME));
    assert_eq!(again.to_string(), printed, "a={}", T::NAME);
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(value) = std::str::from_utf8(rest) else {
        return;
    };
    match selector % 39 {
        0 => fixed_point::<Group>(value),
        1 => fixed_point::<Mid>(value),
        2 => fixed_point::<Msid>(value),
        3 => fixed_point::<MsidSemantic>(value),
        4 => fixed_point::<Ssrc>(value),
        5 => fixed_point::<SsrcGroup>(value),
        6 => fixed_point::<Rid>(value),
        7 => fixed_point::<Simulcast>(value),
        8 => fixed_point::<ExtMap>(value),
        9 => fixed_point::<Rtcp>(value),
        10 => fixed_point::<RtcpFb>(value),
        11 => fixed_point::<RtcpXr>(value),
        12 => fixed_point::<RtpMap>(value),
        13 => fixed_point::<Fmtp>(value),
        14 => fixed_point::<Ptime>(value),
        15 => fixed_point::<MaxPtime>(value),
        16 => fixed_point::<FrameRate>(value),
        17 => fixed_point::<ImageAttr>(value),
        18 => fixed_point::<Content>(value),
        19 => fixed_point::<Candidate>(value),
        20 => fixed_point::<RemoteCandidates>(value),
        21 => fixed_point::<IceUfrag>(value),
        22 => fixed_point::<IcePwd>(value),
        23 => fixed_point::<IceOptions>(value),
        24 => fixed_point::<IcePacing>(value),
        25 => fixed_point::<Fingerprint>(value),
        26 => fixed_point::<Setup>(value),
        27 => fixed_point::<TlsId>(value),
        28 => fixed_point::<Identity>(value),
        29 => fixed_point::<SctpPort>(value),
        30 => fixed_point::<MaxMessageSize>(value),
        31 => fixed_point::<SctpMap>(value),
        35 => fixed_point::<Tool>(value),
        36 => fixed_point::<ConferenceType>(value),
        37 => fixed_point::<Orient>(value),
        38 => {
            fixed_point::<Quality>(value);
            if let Ok(quality) = Quality::parse(value) {
                let _ = quality.value();
            }
        }
        32 => {
            if let Ok(connection) = ConnectionInformation::parse(value) {
                let printed = connection.to_string();
                let again = ConnectionInformation::parse(&printed).expect("c= parses again");
                assert_eq!(again.to_string(), printed);
            }
        }
        33 => {
            if let Ok(bandwidth) = Bandwidth::parse(value) {
                let _ = bandwidth.kind();
                let _ = bandwidth.bits_per_second();
                let printed = bandwidth.to_string();
                let again = Bandwidth::parse(&printed).expect("b= parses again");
                assert_eq!(again.to_string(), printed);
            }
        }
        _ => {
            for address_type in ["IP4", "IP6", "E164"] {
                let _ = Address::parse(address_type, value);
            }
            let _ = mux::attribute(value);
            let _ = mux::category(value);
        }
    }
});
