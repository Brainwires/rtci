//! Based on <https://chromium.googlesource.com/external/webrtc/+/4e513346ec56c829b3a6010664998469fc237b35/modules/rtp_rtcp/source/rtp_packetizer_av1.cc>
//! Reference: <https://aomediacodec.github.io/av1-rtp-spec>

use std::cmp::min;

use crate::codec::av1::leb128::leb128_size;
use crate::codec::av1::obu::{
    OBU_TYPE_FRAME, OBU_TYPE_FRAME_HEADER, OBU_TYPE_SEQUENCE_HEADER, Obu, obu_has_extension,
    obu_type,
};

/// When there are 3 or less OBU (fragments) in a packet, size of the last one
/// can be omitted.
pub const MAX_NUM_OBUS_TO_OMIT_SIZE: usize = 3;
pub const AGGREGATION_HEADER_SIZE: usize = 1;

pub struct PacketMetadata {
    pub first_obu_index: usize,
    pub num_obu_elements: usize,
    pub first_obu_offset: usize,
    pub last_obu_size: usize,
    /// Total size consumed by the packet.
    pub packet_size: usize,
}

impl PacketMetadata {
    fn new(first_obu_index: usize) -> Self {
        Self {
            first_obu_index,
            num_obu_elements: 0,
            first_obu_offset: 0,
            last_obu_size: 0,
            packet_size: 0,
        }
    }
}

/// Returns the scheme for how to aggregate or split the OBUs across RTP packets.
/// Reference: https://aomediacodec.github.io/av1-rtp-spec/#45-payload-structure
///            https://aomediacodec.github.io/av1-rtp-spec/#5-packetization-rules
pub fn packetize(obus: &[Obu], mtu: usize) -> Vec<PacketMetadata> {
    if obus.is_empty() {
        return vec![];
    }
    // Ignore certain edge cases where packets should be very small. They are
    // impractical but adds complexity to handle.
    if mtu < 3 {
        return vec![];
    }

    let mut packets = vec![];

    // Aggregation header will be present in all packets.
    let max_payload_size = mtu - AGGREGATION_HEADER_SIZE;

    // Assemble packets. Push to current packet as much as it can hold before
    // considering next one. That would normally cause uneven distribution across
    // packets, specifically last one would be generally smaller.
    packets.push(PacketMetadata::new(0));
    let mut packet_remaining_bytes = max_payload_size;
    // The layer (temporal_id and spatial_id) of the OBUs with an extension header in the
    // packet being filled.
    let mut packet_layer: Option<u8> = None;

    for obu_index in 0..obus.len() {
        let obu = &obus[obu_index];
        let layer = obu_layer(obu);

        // Putting |obu| into the last packet would make last obu element stored in
        // that packet not last. All not last OBU elements must be prepend with the
        // element length. AdditionalBytesForPreviousObuElement calculates how many
        // bytes are needed to store that length.
        let mut packet = packets.pop().unwrap();
        let mut previous_obu_extra_size = additional_bytes_for_previous_obu_element(&packet);
        let min_required_size = if packet.num_obu_elements >= MAX_NUM_OBUS_TO_OMIT_SIZE {
            2
        } else {
            1
        };
        // AV1 RTP 5: the OBUs with an extension header in one packet MUST all be of one
        // layer; a sequence header SHOULD be the first OBU of its packet; OBUs without an
        // extension header SHOULD be at the beginning of a packet. Greedy aggregation used to
        // cross all three, so a temporal unit with two spatial layers went out with both in
        // one packet.
        let layer_boundary = packet.num_obu_elements > 0
            && (obu_type(obu.header) == OBU_TYPE_SEQUENCE_HEADER
                || (packet_layer.is_some() && layer != packet_layer));
        if layer_boundary || packet_remaining_bytes < previous_obu_extra_size + min_required_size {
            // Start a new packet.
            packets.push(packet);
            packet = PacketMetadata::new(obu_index);
            packet_remaining_bytes = max_payload_size;
            previous_obu_extra_size = 0;
            packet_layer = None;
        }
        if layer.is_some() {
            packet_layer = layer;
        }
        packet.packet_size += previous_obu_extra_size;
        packet_remaining_bytes -= previous_obu_extra_size;
        packet.num_obu_elements += 1;
        let must_write_obu_element_size = packet.num_obu_elements > MAX_NUM_OBUS_TO_OMIT_SIZE;

        // Can fit all of the obu into the packet?
        let mut required_bytes = obu.size;
        if must_write_obu_element_size {
            required_bytes += leb128_size(obu.size as u32);
        }
        // (`<=`: an OBU that exactly fills the packet used to be cut in two.)
        if required_bytes <= packet_remaining_bytes {
            // Insert the obu into the packet unfragmented.
            packet.last_obu_size = obu.size;
            packet.packet_size += required_bytes;
            packet_remaining_bytes -= required_bytes;
            packets.push(packet);
            continue;
        }

        // Fragment the obu.
        let max_first_fragment_size = if must_write_obu_element_size {
            max_fragment_size(packet_remaining_bytes)
        } else {
            packet_remaining_bytes
        };
        // Because available_bytes might be different than
        // packet_remaining_bytes it might happen that max_first_fragment_size >=
        // obu.size. Also, since checks above verified |obu| should not be put
        // completely into the |packet|, leave at least 1 byte for later packet.
        let first_fragment_size = min(obu.size - 1, max_first_fragment_size);
        if first_fragment_size == 0 {
            // Rather than writing 0-size element at the tail of the packet,
            // 'uninsert' the |obu| from the |packet|.
            packet.num_obu_elements -= 1;
            packet.packet_size -= previous_obu_extra_size;
        } else {
            packet.packet_size += first_fragment_size;
            if must_write_obu_element_size {
                packet.packet_size += leb128_size(first_fragment_size as u32);
            }
            packet.last_obu_size = first_fragment_size;
        }
        packets.push(packet);

        // Add middle fragments that occupy all of the packet.
        // These are easy because
        // - one obu per packet imply no need to store the size of the obu.
        // - this packets are nor the first nor the last packets of the frame, so
        // packet capacity is always limits.max_payload_len.
        let mut obu_offset = first_fragment_size;
        while obu_offset + max_payload_size < obu.size {
            let mut packet = PacketMetadata::new(obu_index);
            packet.num_obu_elements = 1;
            packet.first_obu_offset = obu_offset;
            let middle_fragment_size = max_payload_size;
            packet.last_obu_size = middle_fragment_size;
            packet.packet_size = middle_fragment_size;
            packets.push(packet);
            obu_offset += max_payload_size;
        }

        // Add the last fragment of the obu. The loop above leaves at most a packet's worth.
        let last_fragment_size = obu.size - obu_offset;
        let mut last_packet = PacketMetadata::new(obu_index);
        last_packet.num_obu_elements = 1;
        last_packet.first_obu_offset = obu_offset;
        last_packet.last_obu_size = last_fragment_size;
        last_packet.packet_size = last_fragment_size;
        packets.push(last_packet);
        packet_remaining_bytes = max_payload_size - last_fragment_size;
        // The packet being filled now holds the tail of this OBU and nothing else.
        packet_layer = layer;
    }

    packets
}

/// The layer of an OBU with an extension header: `temporal_id` (three bits) and `spatial_id`
/// (two bits), as one value. `None` for an OBU without one, which belongs to every layer.
pub fn obu_layer(obu: &Obu) -> Option<u8> {
    obu_has_extension(obu.header).then_some(obu.extension_header >> 3)
}

/// The layer of the OBUs in a packet (AV1 RTP 6: "the entire packet is considered associated
/// with the layer identified by the temporal_id and spatial_id combination"), or `None` when
/// none of them has an extension header.
pub fn packet_layer(obus: &[Obu], packet: &PacketMetadata) -> Option<u8> {
    obus[packet.first_obu_index..packet.first_obu_index + packet.num_obu_elements]
        .iter()
        .find_map(obu_layer)
}

/// Returns the aggregation header for the packet.
/// Reference: https://aomediacodec.github.io/av1-rtp-spec/#44-av1-aggregation-header
pub fn get_aggregation_header(obus: &[Obu], packets: &[PacketMetadata], packet_index: usize) -> u8 {
    let packet = &packets[packet_index];
    let mut header: u8 = 0;

    // Set Z flag: first obu element is continuation of the previous OBU.
    let first_obu_element_is_fragment = packet.first_obu_offset > 0;
    if first_obu_element_is_fragment {
        header |= 1 << 7;
    }

    // Set Y flag: last obu element will be continuated in the next packet.
    let last_obu_offset = if packet.num_obu_elements == 1 {
        packet.first_obu_offset
    } else {
        0
    };
    let last_obu_is_fragment = last_obu_offset + packet.last_obu_size
        < obus[packet.first_obu_index + packet.num_obu_elements - 1].size;
    if last_obu_is_fragment {
        header |= 1 << 6;
    }

    // Set W field: number of obu elements in the packet (when not too large).
    if packet.num_obu_elements <= MAX_NUM_OBUS_TO_OMIT_SIZE {
        header |= (packet.num_obu_elements as u8) << 4;
    }

    // Set N flag: beginning of a new coded video sequence (AV1 RTP 4.4). The AV1 spec (7.5)
    // defines one to start at a temporal unit where a sequence header OBU comes before the first
    // frame header, and that frame header is a shown key frame (`frame_type == KEY_FRAME`,
    // `show_frame == 1`, `show_existing_frame == 0`) of temporal layer 0. A sequence header alone
    // used to be taken for this, so a sequence header repeated on a delta frame set N.
    if packet_index == 0 && starts_coded_video_sequence(obus) {
        header |= 1 << 3;
    }
    header
}

/// Whether the temporal unit in `obus` starts a new coded video sequence (AV1 spec 7.5).
///
/// Reads only the leading bits of the sequence header (`reduced_still_picture_header`) and of
/// the first frame header (`show_existing_frame`, `frame_type`, `show_frame`), which come before
/// anything that needs the sequence header's other fields to parse.
fn starts_coded_video_sequence(obus: &[Obu]) -> bool {
    let mut reduced_still_picture_header = None;
    for obu in obus {
        match obu_type(obu.header) {
            OBU_TYPE_SEQUENCE_HEADER => {
                // seq_profile f(3), still_picture f(1), reduced_still_picture_header f(1).
                reduced_still_picture_header = obu.payload.first().map(|b| b & 0x08 != 0);
            }
            OBU_TYPE_FRAME_HEADER | OBU_TYPE_FRAME => {
                let Some(reduced) = reduced_still_picture_header else {
                    // No sequence header before the first frame header.
                    return false;
                };
                let temporal_id = if obu_has_extension(obu.header) {
                    obu.extension_header >> 5
                } else {
                    0
                };
                if temporal_id != 0 {
                    return false;
                }
                if reduced {
                    // A reduced still picture header has no such fields: every frame is a
                    // shown key frame.
                    return true;
                }
                let Some(&first) = obu.payload.first() else {
                    return false;
                };
                let show_existing_frame = first & 0x80 != 0;
                let frame_type = (first >> 5) & 0x3;
                let show_frame = first & 0x10 != 0;
                return !show_existing_frame && frame_type == 0 && show_frame;
            }
            _ => {}
        }
    }
    false
}

/// Returns the number of additional bytes needed to store the previous OBU
/// element if an additional OBU element is added to the packet.
fn additional_bytes_for_previous_obu_element(packet: &PacketMetadata) -> usize {
    if packet.packet_size == 0 || packet.num_obu_elements > MAX_NUM_OBUS_TO_OMIT_SIZE {
        // Packet is still empty => no last OBU element, no need to reserve space for it.
        //  OR
        // There are so many obu elements in the packet, all of them must be
        // prepended with the length field. That imply space for the length of the
        // last obu element is already reserved.
        0
    } else {
        leb128_size(packet.last_obu_size as u32)
    }
}

/// Given |remaining_bytes| free bytes left in a packet, returns max size of an
/// OBU fragment that can fit into the packet.
/// i.e. MaxFragmentSize + Leb128Size(MaxFragmentSize) <= remaining_bytes.
fn max_fragment_size(remaining_bytes: usize) -> usize {
    if remaining_bytes <= 1 {
        return 0;
    }
    let mut i = 1;
    loop {
        if remaining_bytes < (1 << (7 * i)) + i {
            return remaining_bytes - i;
        }
        i += 1;
    }
}
