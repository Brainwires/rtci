//! The GCC estimator walks a TWCC feedback only as far as its packet status count.

use super::*;
use rtcp::transport_feedbacks::transport_layer_cc::{RunLengthChunk, StatusChunkTypeTcc};

#[test]
fn runs_are_cut_at_the_packet_status_count() {
    let lost = PacketStatusChunk::RunLengthChunk(RunLengthChunk {
        type_tcc: StatusChunkTypeTcc::RunLengthChunk,
        packet_status_symbol: SymbolTypeTcc::PacketNotReceived,
        run_length: 8191,
    });
    let fb = TransportLayerCc {
        packet_status_count: 4,
        packet_chunks: vec![lost.clone(), lost],
        ..Default::default()
    };
    assert_eq!(packet_statuses(&fb).count(), 4);
    assert_eq!(loss_fraction(&fb, |_| true), 1.0);
}

#[test]
fn a_zero_count_has_no_loss() {
    let lost = PacketStatusChunk::RunLengthChunk(RunLengthChunk {
        type_tcc: StatusChunkTypeTcc::RunLengthChunk,
        packet_status_symbol: SymbolTypeTcc::PacketNotReceived,
        run_length: 8191,
    });
    let fb = TransportLayerCc {
        packet_status_count: 0,
        packet_chunks: vec![lost],
        ..Default::default()
    };
    assert_eq!(packet_statuses(&fb).count(), 0);
    assert_eq!(loss_fraction(&fb, |_| true), 0.0);
}
