//! The RTP header and its extensions.
//!
//! [`Header`](crate::header::Header) is the fixed 12-byte header plus the optional CSRC list and header-extension
//! block. The `*_SHIFT`/`*_MASK` constants describe how the flag fields pack into the first two
//! octets, and the `*_OFFSET`/`*_LENGTH` constants give the byte positions a caller can patch in
//! place without re-encoding.
//!
//! Header extensions ([RFC 8285]) come in two forms, selected by
//! [`Header::extension_profile`](crate::header::Header::extension_profile): one-byte ids ([`EXTENSION_PROFILE_ONE_BYTE`](crate::header::EXTENSION_PROFILE_ONE_BYTE)) or two-byte ids
//! ([`EXTENSION_PROFILE_TWO_BYTE`](crate::header::EXTENSION_PROFILE_TWO_BYTE)) when an id above 14 is needed. Use
//! [`Header::set_extension`](crate::header::Header::set_extension) and [`Header::get_extension`](crate::header::Header::get_extension) rather than touching
//! [`Header::extensions`](crate::header::Header::extensions) directly — they keep [`Header::extensions_padding`](crate::header::Header::extensions_padding) and the extension
//! flag consistent, which marshalling depends on.
//!
//! [RFC 8285]: https://datatracker.ietf.org/doc/html/rfc8285

use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut, Bytes};

/// The RTP header validity checks of RFC 3550 Appendix A.1, on raw bytes.
pub mod validity;

/// The length of the extension-profile and length fields that precede header extensions.
pub const HEADER_LENGTH: usize = 4;
/// Bit offset of the version field in the first header octet.
pub const VERSION_SHIFT: u8 = 6;
/// Bit mask of the version field once shifted.
pub const VERSION_MASK: u8 = 0x3;
/// Bit offset of the padding flag.
pub const PADDING_SHIFT: u8 = 5;
/// Bit mask of the padding flag once shifted.
pub const PADDING_MASK: u8 = 0x1;
/// Bit offset of the extension flag.
pub const EXTENSION_SHIFT: u8 = 4;
/// Bit mask of the extension flag once shifted.
pub const EXTENSION_MASK: u8 = 0x1;
/// Extension profile `0xBEDE`, which selects one-byte header extension ids ([RFC 8285]).
pub const EXTENSION_PROFILE_ONE_BYTE: u16 = 0xBEDE;
/// Extension profile `0x1000`, which selects two-byte header extension ids, allowing ids
/// above 14.
pub const EXTENSION_PROFILE_TWO_BYTE: u16 = 0x1000;
/// The bits of "defined by profile" that select the two-byte form. The low four bits are
/// `appbits`, which a receiver ignores ([RFC 8285] section 4.3).
///
/// [RFC 8285]: https://datatracker.ietf.org/doc/html/rfc8285
pub const EXTENSION_PROFILE_TWO_BYTE_MASK: u16 = 0xFFF0;
/// Extension id 15, reserved by the RFC and never assigned.
pub const EXTENSION_ID_RESERVED: u8 = 0xF;
/// The RTP version this crate reads and writes (RFC 3550 section 5.1).
pub const RTP_VERSION: u8 = 2;
/// The highest id the one-byte form can carry (RFC 8285 section 4.2).
pub const ONE_BYTE_EXTENSION_MAX_ID: u8 = 14;
/// The longest element the one-byte form can carry, in bytes.
pub const ONE_BYTE_EXTENSION_MAX_LEN: usize = 16;
/// The longest element the two-byte form can carry, in bytes.
pub const TWO_BYTE_EXTENSION_MAX_LEN: usize = 255;

/// The form of a header-extension block, as its "defined by profile" field selects it.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExtensionForm {
    /// RFC 8285 one-byte form (`0xBEDE`): ids 1 to 14, 1 to 16 bytes each.
    OneByte,
    /// RFC 8285 two-byte form (`0x100` and four `appbits`): ids 1 to 255, 0 to 255 bytes each.
    TwoByte,
    /// Any other profile: one opaque RFC 3550 section 5.3.1 extension, kept under id 0.
    Rfc3550,
}

impl ExtensionForm {
    /// The form a "defined by profile" value selects. The two-byte form is recognised whatever
    /// its `appbits` are (RFC 8285 section 4.3: the receiver ignores them).
    pub fn of_profile(extension_profile: u16) -> Self {
        if extension_profile == EXTENSION_PROFILE_ONE_BYTE {
            ExtensionForm::OneByte
        } else if extension_profile & EXTENSION_PROFILE_TWO_BYTE_MASK == EXTENSION_PROFILE_TWO_BYTE
        {
            ExtensionForm::TwoByte
        } else {
            ExtensionForm::Rfc3550
        }
    }

    /// Bytes of element header in this form: the id / length byte or bytes.
    fn element_header_len(self) -> usize {
        match self {
            ExtensionForm::OneByte => 1,
            ExtensionForm::TwoByte => 2,
            ExtensionForm::Rfc3550 => 0,
        }
    }

    /// Whether an element with this id and length can be written in the one-byte form.
    fn one_byte_fits(id: u8, payload_len: usize) -> bool {
        (1..=ONE_BYTE_EXTENSION_MAX_ID).contains(&id)
            && (1..=ONE_BYTE_EXTENSION_MAX_LEN).contains(&payload_len)
    }
}
/// Bit mask of the CSRC count field.
pub const CC_MASK: u8 = 0xF;
/// Bit offset of the marker bit.
pub const MARKER_SHIFT: u8 = 7;
/// Bit mask of the marker bit once shifted.
pub const MARKER_MASK: u8 = 0x1;
/// Bit mask of the payload-type field.
pub const PT_MASK: u8 = 0x7F;
/// Byte offset of the sequence number within the header.
pub const SEQ_NUM_OFFSET: usize = 2;
/// Length of the sequence number in bytes.
pub const SEQ_NUM_LENGTH: usize = 2;
/// Byte offset of the timestamp within the header.
pub const TIMESTAMP_OFFSET: usize = 4;
/// Length of the timestamp in bytes.
pub const TIMESTAMP_LENGTH: usize = 4;
/// Byte offset of the SSRC within the header.
pub const SSRC_OFFSET: usize = 8;
/// Length of the SSRC in bytes.
pub const SSRC_LENGTH: usize = 4;
/// Byte offset of the first CSRC within the header.
pub const CSRC_OFFSET: usize = 12;
/// Length of each CSRC in bytes.
pub const CSRC_LENGTH: usize = 4;

#[derive(Debug, Eq, PartialEq, Default, Clone)]
/// One RTP header extension: an id and its payload bytes.
pub struct Extension {
    /// The extension id, as negotiated by `a=extmap`.
    pub id: u8,
    /// The extension's value.
    pub payload: Bytes,
}

/// Header represents an RTP packet header
/// NOTE: PayloadOffset is populated by Marshal/Unmarshal and should not be modified
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Header {
    /// The RTP version, always 2. [`Header::default`] sets it; marshal and unmarshal refuse any
    /// other value (RFC 3550 section 5.1).
    pub version: u8,
    /// Whether the payload is followed by padding octets, the last giving the padding length.
    pub padding: bool,
    /// Whether a header-extension block follows the fixed header.
    pub extension: bool,
    /// The marker bit: the last packet of a video frame, or the start of a talk spurt for audio.
    pub marker: bool,
    /// The payload type, which identifies the codec as negotiated in SDP.
    pub payload_type: u8,
    /// Increments by one per packet sent; used to detect loss and restore order.
    pub sequence_number: u16,
    /// The sampling instant of the first octet, in the codec's clock rate.
    pub timestamp: u32,
    /// The synchronization source — the identifier of the stream this packet belongs to.
    pub ssrc: u32,
    /// The contributing sources, listed when a mixer combined several streams.
    pub csrc: Vec<u32>,
    /// Which header-extension form is in use: [`EXTENSION_PROFILE_ONE_BYTE`] or
    /// [`EXTENSION_PROFILE_TWO_BYTE`].
    pub extension_profile: u16,
    /// The header extensions present on this packet.
    pub extensions: Vec<Extension>,
    /// Padding bytes appended to the extension block so it ends on a 32-bit boundary.
    pub extensions_padding: usize,
    /// How many padding octets follow the payload when `padding` is set, the count octet
    /// included (RFC 3550 5.1). Filled in by [`Packet`](crate::packet::Packet) unmarshal so a
    /// packet re-marshals with the padding it arrived with; 0 lets marshal pad to the next
    /// 32-bit boundary, as it always did.
    pub padding_size: u8,
}

impl Default for Header {
    /// A header of version 2 with every other field zero or empty.
    fn default() -> Self {
        Header {
            version: RTP_VERSION,
            padding: false,
            extension: false,
            marker: false,
            payload_type: 0,
            sequence_number: 0,
            timestamp: 0,
            ssrc: 0,
            csrc: Vec::new(),
            extension_profile: 0,
            extensions: Vec::new(),
            extensions_padding: 0,
            padding_size: 0,
        }
    }
}

impl Unmarshal for Header {
    /// Unmarshal parses the passed byte slice and stores the result in the Header this method is called upon
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let raw_packet_len = raw_packet.remaining();
        if raw_packet_len < HEADER_LENGTH {
            return Err(Error::ErrHeaderSizeInsufficient);
        }
        /*
         *  0                   1                   2                   3
         *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |V=2|P|X|  CC   |M|     PT      |       sequence number         |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |                           timestamp                           |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |           synchronization source (SSRC) identifier            |
         * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         * |            contributing source (CSRC) identifiers             |
         * |                             ....                              |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        let b0 = raw_packet.get_u8();
        let version = b0 >> VERSION_SHIFT & VERSION_MASK;
        if version != RTP_VERSION {
            // RFC 3550 section 5.1 and Appendix A.1: anything else is not an RTP packet.
            return Err(Error::BadVersion);
        }
        let padding = (b0 >> PADDING_SHIFT & PADDING_MASK) > 0;
        let extension = (b0 >> EXTENSION_SHIFT & EXTENSION_MASK) > 0;
        let cc = (b0 & CC_MASK) as usize;

        let mut curr_offset = CSRC_OFFSET + (cc * CSRC_LENGTH);
        if raw_packet_len < curr_offset {
            return Err(Error::ErrHeaderSizeInsufficient);
        }

        let b1 = raw_packet.get_u8();
        let marker = (b1 >> MARKER_SHIFT & MARKER_MASK) > 0;
        let payload_type = b1 & PT_MASK;

        let sequence_number = raw_packet.get_u16();
        let timestamp = raw_packet.get_u32();
        let ssrc = raw_packet.get_u32();

        let mut csrc = Vec::with_capacity(cc);
        for _ in 0..cc {
            csrc.push(raw_packet.get_u32());
        }
        let mut extensions_padding: usize = 0;
        let (extension_profile, extensions) = if extension {
            let expected = curr_offset + 4;
            if raw_packet_len < expected {
                return Err(Error::ErrHeaderSizeInsufficientForExtension);
            }
            let extension_profile = raw_packet.get_u16();
            curr_offset += 2;
            let extension_length = raw_packet.get_u16() as usize * 4;
            curr_offset += 2;

            let expected = curr_offset + extension_length;
            if raw_packet_len < expected {
                return Err(Error::ErrHeaderSizeInsufficientForExtension);
            }

            // The whole extension block is consumed here, whatever its items say, so the
            // payload starts where the header says it does and `marshal_size()` matches the
            // wire: each item is bounded by the block, not by the rest of the packet.
            let mut block = raw_packet.copy_to_bytes(extension_length);
            let mut extensions = vec![];
            match ExtensionForm::of_profile(extension_profile) {
                // RFC 8285 RTP One Byte Header Extension
                ExtensionForm::OneByte => {
                    while block.has_remaining() {
                        let b = block.get_u8();
                        if b == 0x00 {
                            // padding
                            extensions_padding += 1;
                            continue;
                        }

                        let extid = b >> 4;
                        let len = ((b & (0xFF ^ 0xF0)) + 1) as usize;

                        if extid == EXTENSION_ID_RESERVED || extid == 0 {
                            // RFC 8285 section 4.2: processing stops at ID 15 and the rest of
                            // the block is ignored. Section 4.1.2: the same for ID 0 with a
                            // non-zero length, whose length is ignored. The elements before it
                            // are kept, and the rest is still part of the header.
                            extensions_padding += 1 + block.remaining();
                            break;
                        }

                        if len > block.remaining() {
                            return Err(Error::ErrHeaderSizeInsufficientForExtension);
                        }

                        extensions.push(Extension {
                            id: extid,
                            payload: block.copy_to_bytes(len),
                        });
                    }
                }
                // RFC 8285 RTP Two Byte Header Extension, whatever its appbits (section 4.3)
                ExtensionForm::TwoByte => {
                    while block.has_remaining() {
                        let b = block.get_u8();
                        if b == 0x00 {
                            // padding
                            extensions_padding += 1;
                            continue;
                        }

                        let extid = b;

                        if !block.has_remaining() {
                            return Err(Error::ErrHeaderSizeInsufficientForExtension);
                        }

                        let len = block.get_u8() as usize;

                        if len > block.remaining() {
                            return Err(Error::ErrHeaderSizeInsufficientForExtension);
                        }

                        extensions.push(Extension {
                            id: extid,
                            payload: block.copy_to_bytes(len),
                        });
                    }
                }
                // RFC3550 Extension
                ExtensionForm::Rfc3550 => {
                    extensions.push(Extension {
                        id: 0,
                        payload: block,
                    });
                }
            };

            (extension_profile, extensions)
        } else {
            (0, vec![])
        };

        Ok(Header {
            version,
            padding,
            extension,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc,
            extension_profile,
            extensions,
            extensions_padding,
            padding_size: 0,
        })
    }
}

impl Header {
    /// Marshaled header size given an already-computed extension payload length
    /// (see [`Header::get_extension_payload_len`]). Lets `marshal_to` size the
    /// buffer and write the extension length field from a single scan of the
    /// extensions instead of walking them via `marshal_size` and again directly.
    fn marshal_size_for(&self, extension_payload_len: usize) -> usize {
        let mut head_size = 12 + (self.csrc.len() * CSRC_LENGTH);
        if self.extension {
            let padded = extension_payload_len + self.extensions_padding;
            head_size += 4 + padded.div_ceil(4) * 4;
        }
        head_size
    }
}

impl MarshalSize for Header {
    /// MarshalSize returns the size of the packet once marshaled.
    fn marshal_size(&self) -> usize {
        let extension_payload_len = if self.extension {
            self.get_extension_payload_len()
        } else {
            0
        };
        self.marshal_size_for(extension_payload_len)
    }
}

impl Marshal for Header {
    /// Marshal serializes the header and writes to the buffer.
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        /*
         *  0                   1                   2                   3
         *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |V=2|P|X|  CC   |M|     PT      |       sequence number         |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |                           timestamp                           |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |           synchronization source (SSRC) identifier            |
         * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         * |            contributing source (CSRC) identifiers             |
         * |                             ....                              |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        let remaining_before = buf.remaining_mut();
        // Scan the extensions once here; reused for the bounds check, the
        // extension length field, and the trailing padding below (previously
        // walked three times: marshal_size() here plus twice in the body).
        let extension_payload_len = if self.extension {
            self.get_extension_payload_len()
        } else {
            0
        };
        if remaining_before < self.marshal_size_for(extension_payload_len) {
            return Err(Error::ErrBufferTooSmall);
        }

        // The first byte contains the version, padding bit, extension bit, and csrc size.
        // RFC 3550 §5.1: CC is a 4-bit field, so at most 15 contributing sources are allowed.
        if self.csrc.len() > 15 {
            return Err(Error::TooManyCSRCs(self.csrc.len())); // reject early to avoid truncating CC
        }
        // RFC 3550 section 5.1: the version is 2. Any other value would be read by the peer as
        // STUN or DTLS (RFC 7983), and a value above 3 does not fit the field.
        if self.version != RTP_VERSION {
            return Err(Error::BadVersion);
        }
        // The payload type is a 7-bit field; a larger value would set the marker bit.
        if self.payload_type > PT_MASK {
            return Err(Error::WrongPayloadType);
        }
        let mut b0 = (self.version << VERSION_SHIFT) | self.csrc.len() as u8;
        if self.padding {
            b0 |= 1 << PADDING_SHIFT;
        }

        if self.extension {
            b0 |= 1 << EXTENSION_SHIFT;
        }
        buf.put_u8(b0);

        // The second byte contains the marker bit and payload type.
        let mut b1 = self.payload_type;
        if self.marker {
            b1 |= 1 << MARKER_SHIFT;
        }
        buf.put_u8(b1);

        buf.put_u16(self.sequence_number);
        buf.put_u32(self.timestamp);
        buf.put_u32(self.ssrc);

        for csrc in &self.csrc {
            buf.put_u32(*csrc);
        }

        if self.extension {
            buf.put_u16(self.extension_profile);

            // extension_payload_len computed once at the top of this function. The block is
            // as long as `marshal_size` says: the elements, then `extensions_padding` (what a
            // parsed block had after its elements, an ignored tail after ID 0 or 15 included),
            // rounded up to 32-bit words. A block over 65535 bytes fits no datagram and is
            // refused, as it always was.
            let padded_len = extension_payload_len + self.extensions_padding;
            if padded_len > u16::MAX as usize {
                return Err(Error::ExtensionPayloadTotalOverflow(padded_len));
            }
            let form = ExtensionForm::of_profile(self.extension_profile);
            if form == ExtensionForm::Rfc3550 && !extension_payload_len.is_multiple_of(4) {
                //the payload must be in 32-bit words.
                return Err(Error::HeaderExtensionPayloadNot32BitWords);
            }
            let extension_payload_size = padded_len.div_ceil(4) as u16;
            buf.put_u16(extension_payload_size);

            match form {
                // RFC 8285 RTP One Byte Header Extension
                ExtensionForm::OneByte => {
                    for extension in &self.extensions {
                        // validate each extension before writing
                        // RFC 8285 §4.2: IDs 0 and 15 are reserved.
                        if !(1..=14).contains(&extension.id) {
                            return Err(Error::ErrRfc8285oneByteHeaderIdrange);
                        }
                        // RFC 8285 §4.2: payload must be 1-16 bytes; the 4-bit length field
                        // encodes (len-1), so 0 is invalid and >16 cannot be represented.
                        let ext_payload_len = extension.payload.len();
                        if ext_payload_len == 0 || ext_payload_len > 16 {
                            return Err(Error::OneByteHeaderExtensionPayloadOutOfRange(
                                ext_payload_len,
                            ));
                        }
                        // Upper nibble = extension ID, lower nibble = (length - 1)
                        buf.put_u8((extension.id << 4) | (ext_payload_len as u8 - 1));
                        buf.put(&*extension.payload); // write validated extension payload
                    }
                }
                // RFC 8285 RTP Two Byte Header Extension
                ExtensionForm::TwoByte => {
                    for extension in &self.extensions {
                        // RFC 8285 §4.3: ID 0 is padding in two-byte format;
                        // marshaling it as an extension would confuse receivers.
                        if extension.id == 0 {
                            return Err(Error::ErrRfc8285twoByteHeaderIdrange);
                        }
                        // RFC 8285 §4.3: the length field is a single byte, capping
                        // the maximum extension payload at 255 bytes.
                        let ext_payload_len = extension.payload.len();
                        if ext_payload_len > 255 {
                            return Err(Error::TwoByteHeaderExtensionPayloadTooLarge(
                                ext_payload_len,
                            ));
                        }
                        buf.put_u8(extension.id); // two-byte format: ID occupies a full byte
                        buf.put_u8(ext_payload_len as u8);
                        buf.put(&*extension.payload);
                    }
                }
                // RFC3550 Extension
                ExtensionForm::Rfc3550 => {
                    if self.extensions.len() != 1 {
                        return Err(Error::ErrRfc3550headerIdrange);
                    }

                    if let Some(extension) = self.extensions.first() {
                        let ext_len = extension.payload.len();
                        if ext_len % 4 != 0 {
                            return Err(Error::HeaderExtensionPayloadNot32BitWords);
                        }
                        buf.put(&*extension.payload);
                    }
                }
            };

            // add padding to reach 4 bytes boundaries
            for _ in extension_payload_len..extension_payload_size as usize * 4 {
                buf.put_u8(0);
            }
        }

        let remaining_after = buf.remaining_mut();
        Ok(remaining_before - remaining_after)
    }
}

impl Header {
    /// The total encoded length of the extension payloads, padding excluded.
    pub fn get_extension_payload_len(&self) -> usize {
        let payload_len: usize = self
            .extensions
            .iter()
            .map(|extension| extension.payload.len())
            .sum();

        let profile_len = self.extensions.len()
            * ExtensionForm::of_profile(self.extension_profile).element_header_len();

        payload_len + profile_len
    }

    /// The form of this header's extension block, or `None` when it has none.
    pub fn extension_form(&self) -> Option<ExtensionForm> {
        self.extension
            .then(|| ExtensionForm::of_profile(self.extension_profile))
    }

    /// The padding that brings the extension block to a 32-bit boundary.
    fn canonical_extensions_padding(&self) -> usize {
        match ExtensionForm::of_profile(self.extension_profile) {
            ExtensionForm::Rfc3550 => 0,
            _ => (4 - self.get_extension_payload_len() % 4) % 4,
        }
    }

    /// Sets an RTP header extension, keeping the form the header already has.
    ///
    /// A header that has no extension yet takes the one-byte form when the element fits it
    /// (id 1 to 14, 1 to 16 bytes) and the two-byte form otherwise (RFC 8285 section 4.2: an
    /// id above 14 is never sent in the one-byte form; section 4.1.2: the two-byte form is not
    /// used when everything fits the one-byte form).
    ///
    /// A header that already has extensions keeps its form, because a stream carries one form
    /// only unless `a=extmap-allow-mixed` was negotiated (RFC 8285 sections 4.1.2 and 6). Use
    /// [`Header::set_extension_upgrading`] when mixing is allowed, or
    /// [`Header::upgrade_to_two_byte`] on every packet of a stream that is two-byte throughout.
    ///
    /// # Errors
    ///
    /// Fails when the id or the length does not fit the header's form, or no RFC 8285 form at
    /// all (id 0 on a header without extensions, more than 255 bytes).
    pub fn set_extension(&mut self, id: u8, payload: Bytes) -> Result<()> {
        self.set_extension_in(id, payload, false)
    }

    /// Sets an RTP header extension, converting a one-byte header to the two-byte form when the
    /// element needs it (an id above 14, an empty element or one over 16 bytes).
    ///
    /// The conversion changes the form of this packet only. RFC 8285 section 4.1.2 lets a
    /// stream mix the forms only when `a=extmap-allow-mixed` was negotiated (section 6), so
    /// call this when it was, or when the element is set on every packet of the stream (the
    /// stream is then two-byte throughout).
    ///
    /// # Errors
    ///
    /// Fails when the element fits neither form (id 0, more than 255 bytes), or the header
    /// carries an RFC 3550 extension that is not RFC 8285.
    pub fn set_extension_upgrading(&mut self, id: u8, payload: Bytes) -> Result<()> {
        self.set_extension_in(id, payload, true)
    }

    /// Converts a one-byte extension block to the two-byte form, with `appbits` 0. Every
    /// one-byte element is valid in the two-byte form (RFC 8285 section 4.3: one id space).
    /// A header without extensions, or already two-byte, is left as it is.
    ///
    /// # Errors
    ///
    /// Fails for a header whose extension is not RFC 8285.
    pub fn upgrade_to_two_byte(&mut self) -> Result<()> {
        match self.extension_form() {
            None | Some(ExtensionForm::TwoByte) => Ok(()),
            Some(ExtensionForm::OneByte) => {
                self.extension_profile = EXTENSION_PROFILE_TWO_BYTE;
                self.extensions_padding = self.canonical_extensions_padding();
                Ok(())
            }
            Some(ExtensionForm::Rfc3550) => Err(Error::ErrRfc3550headerIdrange),
        }
    }

    fn set_extension_in(&mut self, id: u8, payload: Bytes, upgrade: bool) -> Result<()> {
        let payload_len = payload.len();
        let form = match self.extension_form() {
            Some(ExtensionForm::OneByte) => {
                if ExtensionForm::one_byte_fits(id, payload_len) {
                    ExtensionForm::OneByte
                } else if upgrade && id != 0 && payload_len <= TWO_BYTE_EXTENSION_MAX_LEN {
                    self.extension_profile = EXTENSION_PROFILE_TWO_BYTE;
                    ExtensionForm::TwoByte
                } else if !(1..=ONE_BYTE_EXTENSION_MAX_ID).contains(&id) {
                    return Err(Error::ErrRfc8285oneByteHeaderIdrange);
                } else {
                    // RFC 8285 section 4.2: the element is 1 to 16 bytes.
                    return Err(Error::ErrRfc8285oneByteHeaderSize);
                }
            }
            Some(ExtensionForm::TwoByte) => {
                if id < 1 {
                    return Err(Error::ErrRfc8285twoByteHeaderIdrange);
                }
                if payload_len > TWO_BYTE_EXTENSION_MAX_LEN {
                    return Err(Error::ErrRfc8285twoByteHeaderSize);
                }
                ExtensionForm::TwoByte
            }
            Some(ExtensionForm::Rfc3550) => {
                if id != 0 {
                    return Err(Error::ErrRfc3550headerIdrange);
                }
                ExtensionForm::Rfc3550
            }
            None => {
                // No extension yet: the smallest form the element fits (RFC 8285 sections
                // 4.1.2 and 4.2).
                if id == 0 {
                    return Err(Error::ErrRfc8285oneByteHeaderIdrange);
                }
                if payload_len > TWO_BYTE_EXTENSION_MAX_LEN {
                    return Err(Error::ErrRfc8285twoByteHeaderSize);
                }
                self.extensions.clear();
                self.extension = true;
                if ExtensionForm::one_byte_fits(id, payload_len) {
                    self.extension_profile = EXTENSION_PROFILE_ONE_BYTE;
                    ExtensionForm::OneByte
                } else {
                    self.extension_profile = EXTENSION_PROFILE_TWO_BYTE;
                    ExtensionForm::TwoByte
                }
            }
        };

        // Update the element if it exists, else add it.
        if let Some(extension) = self
            .extensions
            .iter_mut()
            .find(|extension| extension.id == id)
        {
            extension.payload = payload;
        } else {
            self.extensions.push(Extension { id, payload });
        }
        debug_assert_eq!(form, ExtensionForm::of_profile(self.extension_profile));
        self.extensions_padding = self.canonical_extensions_padding();
        Ok(())
    }

    /// returns an extension id array
    pub fn get_extension_ids(&self) -> Vec<u8> {
        if self.extension {
            self.extensions.iter().map(|e| e.id).collect()
        } else {
            vec![]
        }
    }

    /// returns an RTP header extension
    pub fn get_extension(&self, id: u8) -> Option<Bytes> {
        if self.extension {
            self.extensions
                .iter()
                .find(|extension| extension.id == id)
                .map(|extension| extension.payload.clone())
        } else {
            None
        }
    }

    /// Removes an RTP Header extension.
    ///
    /// Removing the last element removes the extension block too: the X bit is cleared, since
    /// the block is present only when the packet carries at least one element (RFC 8285
    /// section 4.1.1).
    pub fn del_extension(&mut self, id: u8) -> Result<()> {
        if self.extension {
            if let Some(index) = self
                .extensions
                .iter()
                .position(|extension| extension.id == id)
            {
                self.extensions.remove(index);
                if self.extensions.is_empty() {
                    self.extension = false;
                    self.extensions_padding = 0;
                } else {
                    self.extensions_padding = self.canonical_extensions_padding();
                }

                Ok(())
            } else {
                Err(Error::ErrHeaderExtensionNotFound)
            }
        } else {
            Err(Error::ErrHeaderExtensionsNotEnabled)
        }
    }
}

#[cfg(test)]
mod header_test;
#[cfg(test)]
mod rfc8285_test;
