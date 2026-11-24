#![no_main]
//! Parser target: what a TURN server sends a client (RFC 8656). ChannelData messages
//! (section 12.4), and STUN messages decoded with every TURN attribute getter: CHANNEL-NUMBER,
//! LIFETIME, XOR-PEER-ADDRESS, XOR-RELAYED-ADDRESS, DATA, EVEN-PORT, REQUESTED-TRANSPORT,
//! REQUESTED-ADDRESS-FAMILY, DONT-FRAGMENT, RESERVATION-TOKEN, ADDITIONAL-ADDRESS-FAMILY,
//! ADDRESS-ERROR-CODE, ICMP and CONNECTION-ID (RFC 6062).

use libfuzzer_sys::fuzz_target;
use rtci_stun::message::{Getter, Message};
use rtci_turn::proto::addfamily::AdditionalAddressFamily;
use rtci_turn::proto::addrerror::AddressErrorCode;
use rtci_turn::proto::chandata::ChannelData;
use rtci_turn::proto::channum::ChannelNumber;
use rtci_turn::proto::connid::ConnectionId;
use rtci_turn::proto::data::Data;
use rtci_turn::proto::dontfrag::DontFragmentAttr;
use rtci_turn::proto::evenport::EvenPort;
use rtci_turn::proto::icmp::Icmp;
use rtci_turn::proto::lifetime::Lifetime;
use rtci_turn::proto::peeraddr::PeerAddress;
use rtci_turn::proto::relayaddr::RelayedAddress;
use rtci_turn::proto::reqfamily::RequestedAddressFamily;
use rtci_turn::proto::reqtrans::RequestedTransport;
use rtci_turn::proto::rsrvtoken::ReservationToken;

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
    let _ = AdditionalAddressFamily::default().get_from(&m);
    let _ = AddressErrorCode::default().get_from(&m);
    let _ = Icmp::default().get_from(&m);
    let _ = ConnectionId::default().get_from(&m);
});
