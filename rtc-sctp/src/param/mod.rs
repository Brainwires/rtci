#[cfg(test)]
mod param_test;

pub(crate) mod param_add_streams_request;
pub(crate) mod param_chunk_list;
pub(crate) mod param_forward_tsn_supported;
pub(crate) mod param_header;
pub(crate) mod param_heartbeat_info;
pub(crate) mod param_incoming_reset_request;
pub(crate) mod param_outgoing_reset_request;
pub(crate) mod param_random;
pub(crate) mod param_reconfig_response;
pub(crate) mod param_requested_hmac_algorithm;
pub(crate) mod param_ssn_tsn_reset_request;
pub(crate) mod param_state_cookie;
pub(crate) mod param_supported_extensions;
pub(crate) mod param_type;
pub(crate) mod param_uknown;

use crate::param::{
    param_add_streams_request::ParamAddStreamsRequest, param_chunk_list::ParamChunkList,
    param_forward_tsn_supported::ParamForwardTsnSupported,
    param_heartbeat_info::ParamHeartbeatInfo,
    param_incoming_reset_request::ParamIncomingResetRequest,
    param_outgoing_reset_request::ParamOutgoingResetRequest, param_random::ParamRandom,
    param_reconfig_response::ParamReconfigResponse,
    param_requested_hmac_algorithm::ParamRequestedHmacAlgorithm,
    param_ssn_tsn_reset_request::ParamSsnTsnResetRequest, param_state_cookie::ParamStateCookie,
    param_supported_extensions::ParamSupportedExtensions, param_uknown::ParamUnknown,
};
use param_header::*;
use param_type::*;
use shared::error::{Error, Result};

use bytes::{Buf, Bytes, BytesMut};
use std::{any::Any, fmt};

/// The type of the Unrecognized Parameter parameter (RFC 9260 3.3.3.1): its value is the
/// parameter the receiver of an INIT did not recognize, as it arrived.
pub(crate) const UNRECOGNIZED_PARAMETER: u16 = 8;

pub(crate) trait Param: fmt::Display + fmt::Debug + Send + Sync {
    fn header(&self) -> ParamHeader;
    fn unmarshal(raw: &Bytes) -> Result<Self>
    where
        Self: Sized;
    fn marshal_to(&self, buf: &mut BytesMut) -> Result<usize>;
    fn value_length(&self) -> usize;
    fn clone_to(&self) -> Box<dyn Param>;
    fn as_any(&self) -> &dyn Any;

    fn marshal(&self) -> Result<Bytes> {
        let capacity = PARAM_HEADER_LENGTH + self.value_length();
        let mut buf = BytesMut::with_capacity(capacity);
        self.marshal_to(&mut buf)?;
        Ok(buf.freeze())
    }
}

impl Clone for Box<dyn Param> {
    fn clone(&self) -> Box<dyn Param> {
        self.clone_to()
    }
}

pub(crate) fn build_param(raw_param: &Bytes) -> Result<Box<dyn Param>> {
    if raw_param.len() < PARAM_HEADER_LENGTH {
        return Err(Error::ErrParamHeaderTooShort);
    }
    let reader = &mut raw_param.slice(..2);
    let raw_type = reader.get_u16();
    let t: ParamType = raw_type.into();
    match t {
        ParamType::ForwardTsnSupp => Ok(Box::new(ParamForwardTsnSupported::unmarshal(raw_param)?)),
        ParamType::SupportedExt => Ok(Box::new(ParamSupportedExtensions::unmarshal(raw_param)?)),
        ParamType::Random => Ok(Box::new(ParamRandom::unmarshal(raw_param)?)),
        ParamType::ReqHmacAlgo => Ok(Box::new(ParamRequestedHmacAlgorithm::unmarshal(raw_param)?)),
        ParamType::ChunkList => Ok(Box::new(ParamChunkList::unmarshal(raw_param)?)),
        ParamType::StateCookie => Ok(Box::new(ParamStateCookie::unmarshal(raw_param)?)),
        ParamType::HeartbeatInfo => Ok(Box::new(ParamHeartbeatInfo::unmarshal(raw_param)?)),
        ParamType::OutSsnResetReq => Ok(Box::new(ParamOutgoingResetRequest::unmarshal(raw_param)?)),
        ParamType::ReconfigResp => Ok(Box::new(ParamReconfigResponse::unmarshal(raw_param)?)),
        ParamType::IncSsnResetReq => Ok(Box::new(ParamIncomingResetRequest::unmarshal(raw_param)?)),
        ParamType::SsnTsnResetReq => Ok(Box::new(ParamSsnTsnResetRequest::unmarshal(raw_param)?)),
        ParamType::AddOutStreamsReq | ParamType::AddIncStreamsReq => {
            Ok(Box::new(ParamAddStreamsRequest::unmarshal(raw_param)?))
        }
        // A parameter the engine has no parser for is kept as it arrived. What becomes of it
        // depends on the chunk it is in and on the upper two bits of its type (RFC 9260
        // 3.2.1), which is for the code that handles that chunk to decide: failing the parse
        // here dropped the whole packet for a parameter the peer is entitled to send.
        _ => Ok(Box::new(ParamUnknown::unmarshal(raw_param)?)),
    }
}
