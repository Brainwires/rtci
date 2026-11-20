//! A TWCC feedback packet describes exactly `packet_status_count` packets.
//!
//! A run-length chunk can claim a run of up to 8191 whatever the count says
//! (draft-holmer-rmcat-transport-wide-cc-extensions-01 3.1.3). Converting a feedback must stop at
//! the count, so a small packet cannot expand into a flood of acknowledgements.

use rtc_interceptor::convert_twcc;
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RunLengthChunk, StatusChunkTypeTcc, StatusVectorChunk, SymbolSizeTypeTcc,
    SymbolTypeTcc, TransportLayerCc,
};

fn lost_run(run_length: u16) -> PacketStatusChunk {
    PacketStatusChunk::RunLengthChunk(RunLengthChunk {
        type_tcc: StatusChunkTypeTcc::RunLengthChunk,
        packet_status_symbol: SymbolTypeTcc::PacketNotReceived,
        run_length,
    })
}

#[test]
fn runs_are_cut_at_the_packet_status_count() {
    let feedback = TransportLayerCc {
        base_sequence_number: 7,
        packet_status_count: 3,
        packet_chunks: vec![
            lost_run(8191),
            lost_run(8191),
            PacketStatusChunk::StatusVectorChunk(StatusVectorChunk {
                type_tcc: StatusChunkTypeTcc::StatusVectorChunk,
                symbol_size: SymbolSizeTypeTcc::OneBit,
                symbol_list: vec![SymbolTypeTcc::PacketNotReceived; 14],
            }),
        ],
        ..Default::default()
    };

    let acknowledgements = convert_twcc(&feedback);
    assert_eq!(
        vec![7, 8, 9],
        acknowledgements
            .iter()
            .map(|ack| ack.sequence_number)
            .collect::<Vec<_>>()
    );
    assert!(acknowledgements.iter().all(|ack| !ack.arrived));
}

#[test]
fn a_zero_count_describes_no_packets() {
    let feedback = TransportLayerCc {
        packet_status_count: 0,
        packet_chunks: vec![lost_run(8191)],
        ..Default::default()
    };
    assert!(convert_twcc(&feedback).is_empty());
}
