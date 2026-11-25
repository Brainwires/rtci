use super::flight4::verify_client_finished;
use super::*;
use crate::change_cipher_spec::*;
use crate::content::*;
use crate::handshake::handshake_message_finished::*;
use crate::handshake::*;
use crate::prf::*;
use crate::record_layer::record_layer_header::*;

use crate::config::HandshakeConfig;
use std::fmt;

#[derive(Debug, PartialEq)]
pub(crate) struct Flight6;

impl fmt::Display for Flight6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flight 6")
    }
}

impl Flight for Flight6 {
    fn is_last_send_flight(&self) -> bool {
        true
    }

    fn parse(
        &self,
        //_tx: &mut mpsc::Sender<mpsc::Sender<()>>,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Box<dyn Flight>, (Option<Alert>, Option<Error>)> {
        let (_, msgs) = match cache.full_pull_map(
            state.handshake_recv_sequence - 1,
            &[HandshakeCachePullRule {
                typ: HandshakeType::Finished,
                epoch: cfg.initial_epoch + 1,
                is_client: true,
                optional: false,
            }],
        ) {
            Ok((seq, msgs)) => (seq, msgs),
            // No valid message received. Keep reading
            Err(_) => return Err((None, None)),
        };

        if let Some(message) = msgs.get(&HandshakeType::Finished) {
            match message {
                // RFC 5246 7.4.9: a Finished is only ever taken with its verify_data checked.
                HandshakeMessage::Finished(finished) => {
                    verify_client_finished(state, cache, cfg, finished)?
                }
                _ => {
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::InternalError,
                        }),
                        None,
                    ));
                }
            };
        }

        // Other party retransmitted the last flight.
        Ok(Box::new(Flight6 {}))
    }

    fn generate(
        &self,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Vec<Packet>, (Option<Alert>, Option<Error>)> {
        // RFC 5077 section 3.3: the NewSessionTicket the ServerHello announced goes ahead of
        // the ChangeCipherSpec, and the Finished covers it. It is not in the cache before it is
        // sent, so it is put in as it will go, with the message sequence `prepare` gives it.
        let mut pkts = vec![];
        let mut ticket_raw = vec![];
        if state.new_session_ticket {
            let ticket = HandshakeMessage::NewSessionTicket(crate::resumption::new_session_ticket(
                state, cfg,
            )?);
            ticket_raw = crate::resumption::marshal_handshake(
                ticket.clone(),
                state.handshake_send_sequence,
            )?;
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
        pkts.push(Packet {
            record: RecordLayer::new(
                PROTOCOL_VERSION1_2,
                0,
                Content::ChangeCipherSpec(ChangeCipherSpec {}),
            ),
            should_encrypt: false,
            reset_local_sequence_number: false,
        });

        if state.local_verify_data.is_empty() {
            let mut plain_text = cache.pull_and_merge(&[
                HandshakeCachePullRule {
                    typ: HandshakeType::ClientHello,
                    epoch: cfg.initial_epoch,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: HandshakeType::ServerHello,
                    epoch: cfg.initial_epoch,
                    is_client: false,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: HandshakeType::Certificate,
                    epoch: cfg.initial_epoch,
                    is_client: false,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: HandshakeType::ServerKeyExchange,
                    epoch: cfg.initial_epoch,
                    is_client: false,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: HandshakeType::CertificateRequest,
                    epoch: cfg.initial_epoch,
                    is_client: false,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: HandshakeType::ServerHelloDone,
                    epoch: cfg.initial_epoch,
                    is_client: false,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: HandshakeType::Certificate,
                    epoch: cfg.initial_epoch,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: HandshakeType::ClientKeyExchange,
                    epoch: cfg.initial_epoch,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: HandshakeType::CertificateVerify,
                    epoch: cfg.initial_epoch,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: HandshakeType::Finished,
                    epoch: cfg.initial_epoch + 1,
                    is_client: true,
                    optional: false,
                },
            ]);
            plain_text.extend_from_slice(&ticket_raw);

            if let Some(cipher_suite) = &state.cipher_suite {
                state.local_verify_data = match prf_verify_data_server(
                    cfg.provider().crypto(),
                    state.master_secret.as_ref(),
                    &plain_text,
                    cipher_suite.hash_func(),
                ) {
                    Ok(data) => data,
                    Err(err) => {
                        return Err((
                            Some(Alert {
                                alert_level: AlertLevel::Fatal,
                                alert_description: AlertDescription::InternalError,
                            }),
                            Some(err),
                        ));
                    }
                };
            }
        }

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
