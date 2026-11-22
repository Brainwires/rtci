use super::*;
use mdns::{MDNS_PORT, MdnsEvent};

impl sansio::Protocol<TaggedBytesMut, (), ()> for Agent {
    type Rout = TaggedBytesMut;
    type Wout = TaggedBytesMut;
    type Eout = TaggedEvent;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<()> {
        // mDNS arrives on the host's mDNS socket, the one bound to MDNS_PORT that this
        // agent's queries leave from. A source port says nothing: anyone can send from 5353 to
        // an ICE socket, and an answer taken from there could point a `.local` candidate at an
        // address of the sender's choosing. Datagrams on ICE sockets are ICE traffic, whatever
        // their source port.
        if msg.transport.local_addr.port() == MDNS_PORT
            && msg.transport.peer_addr.port() == MDNS_PORT
        {
            let remote_candidates = if let Some(mdns_conn) = &mut self.mdns {
                mdns_conn.handle_read(msg)?;

                let mut remote_candidates = vec![];
                // After mdns handle_read, check any query result
                while let Some(event) = mdns_conn.poll_event() {
                    match event {
                        MdnsEvent::QueryAnswered(id, addr) => {
                            if let Some(mut c) = self.mdns_queries.remove(&id)
                                && c.set_ip(&addr).is_ok()
                            {
                                debug!(
                                    "mDNS query id {} answered Candidate {} with resolved_addr {} is added into remote candidates",
                                    id,
                                    c,
                                    c.addr()
                                );
                                remote_candidates.push(c);
                            }
                        }
                        MdnsEvent::QueryTimeout(id) => {
                            if let Some(c) = self.mdns_queries.remove(&id) {
                                error!("mDNS Query {} timed out for {}", id, c.address());
                            }
                        }
                        _ => {}
                    }
                }
                remote_candidates
            } else {
                vec![]
            };

            self.trigger_request_connectivity_check(remote_candidates);

            Ok(())
        } else if self.handle_previous_generation(&msg) {
            // Consent traffic of the generation an ICE restart replaced, on the path that is
            // still in use.
            Ok(())
        } else if let Some(local_index) =
            self.find_local_candidate(msg.transport.local_addr, msg.transport.transport_protocol)
        {
            self.handle_inbound_candidate_msg(local_index, msg)
        } else {
            warn!(
                "[{}]: Discarded message, not a valid local candidate from {:?}:{}",
                self.get_name(),
                msg.transport.transport_protocol,
                msg.transport.local_addr,
            );
            Err(Error::ErrUnhandledStunpacket)
        }
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        None
    }

    fn handle_write(&mut self, _msg: ()) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        if let Some(mdns_conn) = &mut self.mdns {
            while let Some(msg) = mdns_conn.poll_write() {
                self.write_outs.push_back(msg);
            }
        }

        self.write_outs.pop_front()
    }

    fn handle_event(&mut self, _evt: ()) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Self::Time) -> std::result::Result<(), Self::Error> {
        let remote_candidates = if let Some(mdns_conn) = &mut self.mdns {
            let _ = mdns_conn.handle_timeout(now);

            let mut remote_candidates = vec![];
            // After mdns handle_timeout, check any query result
            while let Some(event) = mdns_conn.poll_event() {
                match event {
                    MdnsEvent::QueryAnswered(id, addr) => {
                        if let Some(mut c) = self.mdns_queries.remove(&id)
                            && c.set_ip(&addr).is_ok()
                        {
                            debug!(
                                "mDNS query id {} answered Candidate {} with resolved_addr {} is added into remote candidates",
                                id,
                                c,
                                c.addr()
                            );
                            remote_candidates.push(c);
                        }
                    }
                    MdnsEvent::QueryTimeout(id) => {
                        if let Some(c) = self.mdns_queries.remove(&id) {
                            error!("mDNS Query {} timed out for {}", id, c.address());
                        }
                    }
                    _ => {}
                }
            }
            remote_candidates
        } else {
            vec![]
        };
        self.trigger_request_connectivity_check(remote_candidates);

        // Requests that were answered before the peer's credentials arrived (RFC 8445
        // Section 7.3) are processed now that there are some.
        if !self.early_requests.is_empty() {
            self.process_early_requests(now);
        }

        // The path an ICE restart left in use keeps its consent checks, with or without the
        // peer's new credentials.
        self.maintain_previous_generation(now);

        if self.ice_deadline().is_some_and(|deadline| deadline <= now) {
            self.contact(now);
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        let mdns_timeout = if let Some(mdns_conn) = &mut self.mdns {
            mdns_conn.poll_timeout()
        } else {
            None
        };

        let ice_timeout = self.ice_deadline();

        // This treats the options as a collection and picks the minimum
        [
            mdns_timeout,
            ice_timeout,
            self.previous_generation_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn close(&mut self) -> std::result::Result<(), Self::Error> {
        self.set_selected_pair(None, None);
        self.delete_all_candidates(false);
        self.update_connection_state(None, ConnectionState::Closed);
        if let Some(mdns_conn) = &mut self.mdns {
            mdns_conn.close()?;
        }
        Ok(())
    }
}
