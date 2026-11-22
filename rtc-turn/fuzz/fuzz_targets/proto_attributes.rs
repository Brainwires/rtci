#![no_main]
//! Parser target: what a TURN server sends a client (RFC 8656). ChannelData messages
//! (section 12.4), and STUN messages decoded with every TURN attribute getter: CHANNEL-NUMBER,
//! LIFETIME, XOR-PEER-ADDRESS, XOR-RELAYED-ADDRESS, DATA, EVEN-PORT, REQUESTED-TRANSPORT,
//! REQUESTED-ADDRESS-FAMILY, DONT-FRAGMENT and RESERVATION-TOKEN.

use libfuzzer_sys::fuzz_target;
use rtc_stun::message::{Getter, Message};
use rtc_turn::proto::chandata::ChannelData;
use rtc_turn::proto::channum::ChannelNumber;
use rtc_turn::proto::data::Data;
use rtc_turn::proto::dontfrag::DontFragmentAttr;
use rtc_turn::proto::evenport::EvenPort;
use rtc_turn::proto::lifetime::Lifetime;
use rtc_turn::proto::peeraddr::PeerAddress;
use rtc_turn::proto::relayaddr::RelayedAddress;
use rtc_turn::proto::reqfamily::RequestedAddressFamily;
use rtc_turn::proto::reqtrans::RequestedTransport;
use rtc_turn::proto::rsrvtoken::ReservationToken;

fuzz_target!(|data: &[u8]| {
    if ChannelData::is_channel_data(data) {
        let mut channel_data = ChannelData {
            raw: data.to_vec(),
            ..Default::default()
        };
        if channel_data.decode().is_ok() {
            let _ = channel_data.encode();
        }
    }

    let mut m = Message::new();
    if m.unmarshal_binary(data).is_err() {
        return;
    }
    let _ = ChannelNumber::default().get_from(&m);
    let _ = Lifetime::default().get_from(&m);
    let _ = PeerAddress::default().get_from(&m);
    let _ = RelayedAddress::default().get_from(&m);
    let _ = Data::default().get_from(&m);
    let _ = EvenPort::default().get_from(&m);
    let _ = RequestedTransport::default().get_from(&m);
    let _ = RequestedAddressFamily::default().get_from(&m);
    let _ = DontFragmentAttr.get_from(&m);
    let _ = ReservationToken::default().get_from(&m);
});
