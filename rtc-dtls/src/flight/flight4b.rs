use super::flight4::server_hello_extensions;
use super::*;
use crate::change_cipher_spec::ChangeCipherSpec;
use crate::cipher_suite::CipherSuiteId;
use crate::compression_methods::default_compression_methods;
use crate::content::*;
use crate::handshake::handshake_message_finished::*;
use crate::handshake::handshake_message_server_hello::*;
use crate::handshake::*;
use crate::prf::{prf_verify_data_client, prf_verify_data_server};
use crate::record_layer::record_layer_header::*;
use crate::resumption::{abbreviated_transcript, fatal, marshal_handshake, new_session_ticket};
use shared::error::Error;

use crate::config::HandshakeConfig;
use std::fmt;

/// The server's flight of an abbreviated handshake (RFC 5246 7.3, RFC 6347 4.2.4 figure 2):
/// ServerHello with the session id of the session it resumes, a NewSessionTicket when the
/// client asked for one (RFC 5077 section 3.3), ChangeCipherSpec and Finished. Sent again on
/// its timer until the client's ChangeCipherSpec and Finished, the last flight, arrive.
#[derive(Debug, PartialEq)]
pub(crate) struct Flight4b;

impl fmt::Display for Flight4b {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flight 4b")
    }
}

impl Flight for Flight4b {
    fn is_last_recv_flight(&self) -> bool {
        true
    }

    fn parse(
        &self,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Box<dyn Flight>, (Option<Alert>, Option<Error>)> {
        let Ok((_, msgs)) = cache.full_pull_map(
            state.handshake_recv_sequence,
            &[HandshakeCachePullRule {
                typ: HandshakeType::Finished,
                epoch: cfg.initial_epoch + 1,
                is_client: true,
                optional: false,
            }],
        ) else {
            return Err((None, None));
        };
        let Some(HandshakeMessage::Finished(finished)) = msgs.get(&HandshakeType::Finished) else {
            return Err(fatal(
                AlertDescription::InternalError,
                Error::ErrInvalidContentType,
            ));
        };
        let Some(cipher_suite) = &state.cipher_suite else {
            return Err(fatal(
                AlertDescription::InternalError,
                Error::ErrCipherSuiteUnset,
            ));
        };
        // RFC 5246 7.4.9: the client's Finished covers the server's.
        let expected = prf_verify_data_client(
            cfg.provider().crypto(),
            &state.master_secret,
            &abbreviated_transcript(cache, cfg, true),
            cipher_suite.hash_func(),
        )
        .map_err(|err| fatal(AlertDescription::InternalError, err))?;
        if !crypto::constant_time_eq(&expected, &finished.verify_data) {
            // RFC 5246 7.2.2: decrypt_error, a Finished that does not verify.
            return Err(fatal(
                AlertDescription::DecryptError,
                Error::ErrVerifyDataMismatch,
            ));
        }
        Ok(Box::new(Flight4b {}))
    }

    fn generate(
        &self,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Vec<Packet>, (Option<Alert>, Option<Error>)> {
        let server_hello = HandshakeMessageServerHello {
            version: PROTOCOL_VERSION1_2,
            random: state.local_random.clone(),
            // RFC 5246 7.4.1.3: the session id and cipher suite of the session resumed.
            session_id: state.session_id.clone(),
            cipher_suite: state
                .cipher_suite
                .as_ref()
                .map_or(CipherSuiteId::Unsupported, |cipher_suite| cipher_suite.id()),
            compression_method: default_compression_methods().ids[0],
            extensions: server_hello_extensions(state, cfg),
        };

        // The Finished covers the messages of this flight before it, which are not in the
        // cache until they are sent: they are put in as they will go, with the message
        // sequence numbers `prepare` gives them.
        let mut sequence = state.handshake_send_sequence;
        let mut transcript = cache.pull_and_merge(&[HandshakeCachePullRule {
            typ: HandshakeType::ClientHello,
            epoch: cfg.initial_epoch,
            is_client: true,
            optional: false,
        }]);
        let server_hello = HandshakeMessage::ServerHello(server_hello);
        transcript.extend(marshal_handshake(server_hello.clone(), sequence)?);
        sequence += 1;
        let mut pkts = vec![Packet {
            record: RecordLayer::new(
                PROTOCOL_VERSION1_2,
                0,
                Content::Handshake(Handshake::new(server_hello)),
            ),
            should_encrypt: false,
            reset_local_sequence_number: false,
        }];
        if state.new_session_ticket {
            let ticket = HandshakeMessage::NewSessionTicket(new_session_ticket(state, cfg)?);
            transcript.extend(marshal_handshake(ticket.clone(), sequence)?);
            pkts.push(Packet {
                record: RecordLayer::new(
                    PROTOCOL_VERSION1_2,
                    0,
                    Content::Handshake(Handshake::new(ticket)),
                ),
                should_encrypt: false,
                reset_local_sequence_number: false,
            });
        }

        let Some(cipher_suite) = &state.cipher_suite else {
            return Err(fatal(
                AlertDescription::InternalError,
                Error::ErrCipherSuiteUnset,
            ));
        };
        if state.local_verify_data.is_empty() {
            state.local_verify_data = prf_verify_data_server(
                cfg.provider().crypto(),
                &state.master_secret,
                &transcript,
                cipher_suite.hash_func(),
            )
            .map_err(|err| fatal(AlertDescription::InternalError, err))?;
        }

        pkts.push(Packet {
            record: RecordLayer::new(
                PROTOCOL_VERSION1_2,
                0,
                Content::ChangeCipherSpec(ChangeCipherSpec {}),
            ),
            should_encrypt: false,
            reset_local_sequence_number: false,
        });
        pkts.push(Packet {
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
        });
        Ok(pkts)
    }
}
