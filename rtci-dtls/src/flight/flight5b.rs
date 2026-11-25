use super::*;
use crate::change_cipher_spec::ChangeCipherSpec;
use crate::content::*;
use crate::handshake::handshake_message_finished::*;
use crate::handshake::*;
use crate::prf::prf_verify_data_client;
use crate::record_layer::record_layer_header::*;
use crate::resumption::{abbreviated_transcript, fatal};
use shared::error::Error;

use crate::config::HandshakeConfig;
use std::fmt;

/// The client's last flight of an abbreviated handshake (RFC 5246 7.3, RFC 6347 4.2.4 figure
/// 2): ChangeCipherSpec and Finished, after the server's Finished. Being the last flight, it
/// is sent again when the server's flight comes again (RFC 6347 4.2.4).
#[derive(Debug, PartialEq)]
pub(crate) struct Flight5b;

impl fmt::Display for Flight5b {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flight 5b")
    }
}

impl Flight for Flight5b {
    fn is_last_send_flight(&self) -> bool {
        true
    }

    fn parse(
        &self,
        _state: &mut State,
        _cache: &HandshakeCache,
        _cfg: &HandshakeConfig,
    ) -> Result<Box<dyn Flight>, (Option<Alert>, Option<Error>)> {
        // The server sent its flight again: this flight was lost, and the association, which
        // has completed, sends it again.
        Ok(Box::new(Flight5b {}))
    }

    fn generate(
        &self,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Vec<Packet>, (Option<Alert>, Option<Error>)> {
        let Some(cipher_suite) = &state.cipher_suite else {
            return Err(fatal(
                AlertDescription::InternalError,
                Error::ErrCipherSuiteUnset,
            ));
        };
        // RFC 5246 7.4.9: over every handshake message before this one, the server's Finished
        // included. (Made once, as the other flights' Finished.)
        if state.local_verify_data.is_empty() {
            state.local_verify_data = prf_verify_data_client(
                cfg.provider().crypto(),
                state.master_secret.as_ref(),
                &abbreviated_transcript(cache, cfg, true),
                cipher_suite.hash_func(),
            )
            .map_err(|err| fatal(AlertDescription::InternalError, err))?;
        }

        Ok(vec![
            Packet {
                record: RecordLayer::new(
                    PROTOCOL_VERSION1_2,
                    0,
                    Content::ChangeCipherSpec(ChangeCipherSpec {}),
                ),
                should_encrypt: false,
                reset_local_sequence_number: false,
            },
            Packet {
                record: RecordLayer::new(
                    PROTOCOL_VERSION1_2,
                    1,
                    Content::Handshake(Handshake::new(HandshakeMessage::Finished(
                        HandshakeMessageFinished {
                            verify_data: state.local_verify_data.clone(),
                        },
                    ))),
                ),
                should_encrypt: true,
                reset_local_sequence_number: true,
            },
        ])
    }
}
