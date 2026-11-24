//! Application layer feedback (AFB, [RFC 4585] §6.4) that is not REMB.
//!
//! [RFC 4585]: https://datatracker.ietf.org/doc/html/rfc4585#section-6.4
use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut, Bytes};
use std::fmt;

/// Application layer feedback (PSFB FMT=15): a message from one application to its peer that
/// RTCP only carries.
///
/// The application identifies its own messages by what it puts in `data`; REMB, which opens
/// its data with `REMB`, is parsed as
/// [`ReceiverEstimatedMaximumBitrate`](crate::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate)
/// instead.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct ApplicationLayerFeedback {
    /// The source that sends the message.
    pub sender_ssrc: u32,
    /// The media source the message is about.
    pub media_ssrc: u32,
    /// The application's message. Its length is a multiple of four octets: the application
    /// pads it, in a way its peer can tell from the data (RFC 4585 §6.4).
    pub data: Bytes,
}

impl fmt::Display for ApplicationLayerFeedback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ApplicationLayerFeedback {:x} {:x} {} octets",
            self.sender_ssrc,
            self.media_ssrc,
            self.data.len()
        )
    }
}

impl Packet for ApplicationLayerFeedback {
    fn header(&self) -> Header {
        Header {
            padding: false,
            count: FORMAT_AFB,
            packet_type: PacketType::PayloadSpecificFeedback,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    fn destination_ssrc(&self) -> Vec<u32> {
        vec![self.media_ssrc]
    }

    fn raw_size(&self) -> usize {
        HEADER_LENGTH + FEEDBACK_SSRCS_LENGTH + self.data.len()
    }

    packet_any!(ApplicationLayerFeedback);
}

impl MarshalSize for ApplicationLayerFeedback {
    fn marshal_size(&self) -> usize {
        let l = self.raw_size();
        l + get_padding_size(l)
    }
}

impl Marshal for ApplicationLayerFeedback {
    fn marshal_to(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.data.len().is_multiple_of(4) {
            return Err(Error::WrongMarshalSize);
        }
        let size = self.raw_size();
        let mut buf = put_feedback_start(
            buf,
            PacketType::PayloadSpecificFeedback,
            FORMAT_AFB,
            size,
            self.sender_ssrc,
            self.media_ssrc,
        )?;
        buf.put_slice(&self.data);
        Ok(size)
    }
}

impl Unmarshal for ApplicationLayerFeedback {
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let (sender_ssrc, media_ssrc, data) =
            read_feedback(raw_packet, PacketType::PayloadSpecificFeedback, FORMAT_AFB)?;
        if !data.len().is_multiple_of(4) {
            return Err(Error::WrongPadding);
        }
        Ok(ApplicationLayerFeedback {
            sender_ssrc,
            media_ssrc,
            data,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn application_layer_feedback_round_trips() {
        let afb = ApplicationLayerFeedback {
            sender_ssrc: 1,
            media_ssrc: 2,
            data: Bytes::from_static(b"ABCD\x01\x02\x03\x04"),
        };
        let raw = afb.marshal().unwrap();
        assert_eq!(
            &[
                0x8f, 0xce, 0x00, 0x04, 0, 0, 0, 1, 0, 0, 0, 2, b'A', b'B', b'C', b'D', 1, 2, 3, 4
            ][..],
            &raw[..]
        );
        assert_eq!(
            afb,
            ApplicationLayerFeedback::unmarshal(&mut raw.freeze()).unwrap()
        );

        let empty = ApplicationLayerFeedback::default();
        let raw = empty.marshal().unwrap();
        assert_eq!(12, raw.len());
        assert_eq!(
            empty,
            ApplicationLayerFeedback::unmarshal(&mut raw.freeze()).unwrap()
        );
    }

    // RFC 4585 6.4: the message is padded to 32 bits, by the application.
    #[test]
    fn data_that_is_not_a_whole_number_of_words_is_refused() {
        let afb = ApplicationLayerFeedback {
            data: Bytes::from_static(b"ABC"),
            ..Default::default()
        };
        assert_eq!(Err(Error::WrongMarshalSize), afb.marshal());

        // RTCP padding of three octets leaves data of five.
        let mut raw = Bytes::from_static(&[
            0xaf, 0xce, 0x00, 0x04, 0, 0, 0, 1, 0, 0, 0, 2, 1, 2, 3, 4, 5, 0, 0, 3,
        ]);
        assert_eq!(
            Err(Error::WrongPadding),
            ApplicationLayerFeedback::unmarshal(&mut raw)
        );
        // Another feedback format is not AFB.
        let mut raw = Bytes::from_static(&[0x81, 0xce, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2]);
        assert_eq!(
            Err(Error::WrongType),
            ApplicationLayerFeedback::unmarshal(&mut raw)
        );
    }
}
