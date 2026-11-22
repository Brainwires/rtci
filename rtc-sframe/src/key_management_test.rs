use crate::test_util::provider;
use crate::{
    CipherSuite, Error, Header, KeyUsage, MLS_EXPORTER_LABEL, MlsContext, MlsKeyId, MlsKeyIdLayout,
    SFrameContext, SenderKeyId, SenderKeyIdLayout, SenderKeyRatchet, SenderKeyReceiver,
    ratchet_base_key,
};

const SUITE: CipherSuite = CipherSuite::Aes128GcmSha256_128;

// ---- MLS (RFC 9605 section 5.2) ----

#[test]
fn mls_key_ids_match_rfc9605_figure_9() {
    // E = 4; S = 6, allowing for 64 group members.
    let layout = MlsKeyIdLayout::new(4, 6).unwrap();
    // (epoch, sender index, context, KID)
    let figure = [
        (14, 3, 0, 0x3e),
        (14, 7, 0, 0x7e),
        (14, 20, 0, 0x14e),
        (15, 3, 0, 0x3f),
        (15, 5, 0, 0x5f),
        (16, 2, 2, 0x820),
        (16, 2, 3, 0xc20),
        (17, 33, 0, 0x211),
        (17, 51, 0, 0x331),
    ];
    for (epoch, sender_index, context, kid) in figure {
        assert_eq!(layout.key_id(epoch, sender_index, context), Ok(kid));
        assert_eq!(
            layout.split(kid),
            MlsKeyId {
                context,
                sender_index,
                // Only the low E bits of the epoch are sent.
                epoch: epoch % 16,
            }
        );
        assert_eq!(layout.epoch_slot(epoch), epoch % 16);
    }
    assert_eq!(layout.context_bits(), 54);
}

#[test]
fn mls_key_id_layout_takes_its_sender_bits_from_the_group_size() {
    // S is the smallest value such that group_size <= (1 << S).
    for (group_size, sender_bits) in [
        (0u64, 0u32),
        (1, 0),
        (2, 1),
        (3, 2),
        (4, 2),
        (5, 3),
        (64, 6),
        (65, 7),
        (1 << 32, 32),
        ((1 << 32) + 1, 33),
    ] {
        let layout = MlsKeyIdLayout::for_group_size(4, group_size).unwrap();
        assert_eq!(layout.sender_bits(), sender_bits, "group of {group_size}");
        assert_eq!(layout.epoch_bits(), 4);
    }
    assert_eq!(
        MlsKeyIdLayout::for_group_size(4, u64::MAX),
        Err(Error::KeyIdLayout)
    );
}

#[test]
fn mls_key_id_layout_refuses_what_does_not_fit_64_bits() {
    assert_eq!(MlsKeyIdLayout::new(33, 32), Err(Error::KeyIdLayout));
    assert_eq!(MlsKeyIdLayout::new(65, 0), Err(Error::KeyIdLayout));
    assert!(MlsKeyIdLayout::new(32, 32).is_ok());
    assert!(MlsKeyIdLayout::new(0, 64).is_ok());

    let layout = MlsKeyIdLayout::new(4, 6).unwrap();
    // A sender index of 7 bits, a context of 55.
    assert_eq!(layout.key_id(1, 64, 0), Err(Error::KeyIdLayout));
    assert_eq!(layout.key_id(1, 0, 1 << 54), Err(Error::KeyIdLayout));
    assert_eq!(
        layout.key_id(u64::MAX, 63, (1 << 54) - 1),
        Ok(u64::MAX),
        "the largest index and context, any epoch"
    );

    // The fields at the edges of the word.
    let all_epoch = MlsKeyIdLayout::new(64, 0).unwrap();
    assert_eq!(
        all_epoch.key_id(0x1234_5678_9abc_def0, 0, 0),
        Ok(0x1234_5678_9abc_def0)
    );
    assert_eq!(all_epoch.key_id(1, 1, 0), Err(Error::KeyIdLayout));
    let no_epoch = MlsKeyIdLayout::new(0, 8).unwrap();
    assert_eq!(no_epoch.key_id(99, 0x12, 0x34), Ok(0x3412));
    assert_eq!(no_epoch.split(0x3412).epoch, 0);
}

fn mls_member(sender_index: u64) -> MlsContext {
    let layout = MlsKeyIdLayout::new(4, 6).unwrap();
    MlsContext::new(SUITE, provider(), layout, sender_index).unwrap()
}

#[test]
fn mls_members_decrypt_each_other_with_keys_derived_from_the_epoch_secret() {
    assert_eq!(MLS_EXPORTER_LABEL, "SFrame 1.0 Base Key");
    for suite in CipherSuite::ALL {
        let layout = MlsKeyIdLayout::new(4, 6).unwrap();
        // What MLS-Exporter("SFrame 1.0 Base Key", "", AEAD.Nk) would give.
        let secret = vec![0x17; suite.key_len()];
        let mut alice = MlsContext::new(suite, provider(), layout, 3).unwrap();
        let mut bob = MlsContext::new(suite, provider(), layout, 20).unwrap();
        alice.add_epoch(14, &secret).unwrap();
        bob.add_epoch(14, &secret).unwrap();
        assert!(alice.has_epoch(14) && !alice.has_epoch(30));

        let from_alice = alice.encrypt(14, 0, b"m", b"hello bob").unwrap();
        assert_eq!(Header::decode(&from_alice).unwrap().0, Header::new(0x3e, 0));
        assert_eq!(alice.key_id(14, 0), Ok(0x3e));
        assert_eq!(
            bob.decrypt(b"m", &from_alice).as_deref(),
            Ok(&b"hello bob"[..])
        );

        let from_bob = bob.encrypt(14, 0, b"m", b"hello alice").unwrap();
        assert_eq!(Header::decode(&from_bob).unwrap().0, Header::new(0x14e, 0));
        assert_eq!(
            alice.decrypt(b"m", &from_bob).as_deref(),
            Ok(&b"hello alice"[..]),
            "{suite}"
        );

        // A second stream of the same sender: another context value, another key and counter.
        let second = alice.encrypt(14, 2, b"m", b"second stream").unwrap();
        assert_eq!(
            Header::decode(&second).unwrap().0,
            Header::new((2 << 10) | 0x3e, 0)
        );
        assert_eq!(
            bob.decrypt(b"m", &second).as_deref(),
            Ok(&b"second stream"[..])
        );

        // Each member's keys have one role.
        assert_eq!(alice.context().key_usage(0x3e), Some(KeyUsage::Encrypt));
        assert_eq!(bob.context().key_usage(0x3e), Some(KeyUsage::Decrypt));
        assert_eq!(bob.context().key_usage(0x14e), Some(KeyUsage::Encrypt));
    }
}

#[test]
fn mls_member_refuses_ciphertexts_under_its_own_key_ids() {
    let mut alice = mls_member(3);
    let mut bob = mls_member(20);
    alice.add_epoch(14, b"secret").unwrap();
    bob.add_epoch(14, b"secret").unwrap();

    // Alice's own frame reflected back to her.
    let own = alice.encrypt(14, 0, b"", b"frame").unwrap();
    assert_eq!(alice.decrypt(b"", &own), Err(Error::KeyRoleConflict(0x3e)));

    // Bob sending as Alice under a KID she has not used yet: the key would be hers to encrypt
    // with, so she never derives it for decryption.
    let mut impostor = mls_member(3);
    impostor.add_epoch(14, b"secret").unwrap();
    let forged = impostor.encrypt(14, 7, b"", b"as alice").unwrap();
    let kid = Header::decode(&forged).unwrap().0.kid;
    assert_eq!(
        alice.decrypt(b"", &forged),
        Err(Error::KeyRoleConflict(kid))
    );
    assert_eq!(alice.context().key_usage(kid), None);
    // Other members cannot tell (SFrame has no per-sender authentication, section 7.2).
    assert_eq!(bob.decrypt(b"", &forged).as_deref(), Ok(&b"as alice"[..]));
}

#[test]
fn mls_new_epoch_with_the_same_low_bits_removes_the_old_one() {
    // E = 4: epochs 2 and 18 share their low-order bits.
    let mut alice = mls_member(3);
    let mut bob = mls_member(20);
    for member in [&mut alice, &mut bob] {
        member.add_epoch(2, b"secret of epoch 2").unwrap();
        member.add_epoch(3, b"secret of epoch 3").unwrap();
    }
    let old = alice.encrypt(2, 0, b"", b"epoch 2").unwrap();
    let late = alice.encrypt(2, 0, b"", b"epoch 2, late").unwrap();
    let other = alice.encrypt(3, 0, b"", b"epoch 3").unwrap();
    assert_eq!(bob.decrypt(b"", &old).as_deref(), Ok(&b"epoch 2"[..]));
    assert_eq!(bob.decrypt(b"", &other).as_deref(), Ok(&b"epoch 3"[..]));
    assert_eq!(bob.context().key_count(), 2);

    bob.add_epoch(18, b"secret of epoch 18").unwrap();
    assert!(!bob.has_epoch(2) && bob.has_epoch(18) && bob.has_epoch(3));
    // The key derived from epoch 2 is gone; epoch 3's stays.
    assert_eq!(bob.context().key_count(), 1);
    assert_eq!(bob.context().key_usage(0x33), Some(KeyUsage::Decrypt));
    assert_eq!(bob.decrypt(b"", &late), Err(Error::AuthenticationFailed));

    // The sender's side: the KID now belongs to epoch 18, with a new key and counter.
    alice.add_epoch(18, b"secret of epoch 18").unwrap();
    assert_eq!(
        alice.encrypt(2, 0, b"", b"too late"),
        Err(Error::UnknownEpoch(2))
    );
    let new = alice.encrypt(18, 0, b"", b"epoch 18").unwrap();
    assert_eq!(Header::decode(&new).unwrap().0, Header::new(0x32, 0));
    assert_ne!(new, old);
    assert_eq!(bob.decrypt(b"", &new).as_deref(), Ok(&b"epoch 18"[..]));
}

#[test]
fn mls_epoch_cannot_go_back_or_return() {
    let mut member = mls_member(3);
    member.add_epoch(18, b"secret of epoch 18").unwrap();
    // The same epoch again, with the same secret, changes nothing.
    member.encrypt(18, 0, b"", b"frame").unwrap();
    member.add_epoch(18, b"secret of epoch 18").unwrap();
    assert_eq!(member.context().next_counter(0x32), Some(1));

    // Another secret for it, or an older epoch with the same low bits, is refused.
    assert_eq!(member.add_epoch(18, b"another"), Err(Error::StaleEpoch(18)));
    assert_eq!(member.add_epoch(2, b"old"), Err(Error::StaleEpoch(2)));
    assert_eq!(member.add_epoch(19, &[]), Err(Error::EmptyBaseKey));

    // A removed epoch takes its keys along, and does not return: its counters would restart.
    assert!(member.remove_epoch(18));
    assert!(!member.remove_epoch(18));
    assert!(!member.has_epoch(18));
    assert_eq!(member.context().key_count(), 0);
    assert_eq!(
        member.encrypt(18, 0, b"", b"frame"),
        Err(Error::UnknownEpoch(18))
    );
    assert_eq!(
        member.add_epoch(18, b"secret of epoch 18"),
        Err(Error::StaleEpoch(18))
    );
    member.add_epoch(34, b"secret of epoch 34").unwrap();
    assert!(member.has_epoch(34));
}

#[test]
fn mls_forged_key_ids_do_not_fill_the_key_store() {
    let mut alice = mls_member(3);
    let mut bob = mls_member(20);
    alice.add_epoch(14, b"secret").unwrap();
    bob.add_epoch(14, b"secret").unwrap();

    let authentic = alice.encrypt(14, 0, b"", b"frame").unwrap();
    // The same body under 200 other KIDs of epoch 14: other senders, other contexts.
    for n in 1..=200u64 {
        let kid = bob.layout().key_id(14, n % 60, n).unwrap();
        let mut forged = Vec::new();
        Header::new(kid, 0).encode_to(&mut forged);
        forged.extend_from_slice(&authentic[2..]);
        let error = bob.decrypt(b"", &forged).unwrap_err();
        assert!(
            matches!(
                error,
                Error::AuthenticationFailed | Error::KeyRoleConflict(_)
            ),
            "{error}"
        );
    }
    assert_eq!(bob.context().key_count(), 0);
    // An epoch that is not held is an unknown key.
    let mut unknown = Vec::new();
    Header::new(0x3d, 0).encode_to(&mut unknown);
    unknown.extend_from_slice(&authentic[2..]);
    assert_eq!(bob.decrypt(b"", &unknown), Err(Error::UnknownKeyId(0x3d)));

    assert_eq!(bob.decrypt(b"", &authentic).as_deref(), Ok(&b"frame"[..]));
    assert_eq!(bob.context().key_count(), 1);

    // The store's limit holds for authentic senders too.
    bob.set_max_keys(2);
    let second = alice.encrypt(14, 1, b"", b"second").unwrap();
    let third = alice.encrypt(14, 2, b"", b"third").unwrap();
    assert_eq!(bob.decrypt(b"", &second).as_deref(), Ok(&b"second"[..]));
    assert_eq!(bob.decrypt(b"", &third), Err(Error::TooManyKeys));
    assert_eq!(bob.encrypt(14, 0, b"", b"mine"), Err(Error::TooManyKeys));
}

#[test]
fn mls_context_refuses_a_sender_index_outside_the_layout() {
    let layout = MlsKeyIdLayout::new(4, 6).unwrap();
    assert!(matches!(
        MlsContext::new(SUITE, provider(), layout, 64),
        Err(Error::KeyIdLayout)
    ));
    let mut member = mls_member(63);
    member.add_epoch(1, b"secret").unwrap();
    // A context value that does not fit its 54 bits.
    assert_eq!(
        member.encrypt(1, 1 << 54, b"", b"frame"),
        Err(Error::KeyIdLayout)
    );
}

// ---- Sender keys (RFC 9605 section 5.1) ----

#[test]
fn sender_key_ids_carry_generation_and_ratchet_step() {
    // KID = (key_generation << R) + (ratchet_step % (1 << R))
    let layout = SenderKeyIdLayout::new(4).unwrap();
    assert_eq!(layout.ratchet_bits(), 4);
    assert_eq!(layout.key_id(0, 0), Ok(0));
    assert_eq!(layout.key_id(0, 5), Ok(5));
    assert_eq!(layout.key_id(3, 5), Ok(0x35));
    // Only the low R bits of the step are sent.
    assert_eq!(layout.key_id(3, 16 + 5), Ok(0x35));
    assert_eq!(
        layout.split(0x35),
        SenderKeyId {
            key_generation: 3,
            ratchet_step: 5
        }
    );
    // The generation has the remaining 60 bits.
    assert_eq!(layout.key_id((1 << 60) - 1, 15), Ok(u64::MAX));
    assert_eq!(layout.key_id(1 << 60, 0), Err(Error::KeyIdLayout));

    assert_eq!(SenderKeyIdLayout::new(65), Err(Error::KeyIdLayout));
    let no_ratchet = SenderKeyIdLayout::new(0).unwrap();
    assert_eq!(no_ratchet.key_id(7, 99), Ok(7));
    let all_ratchet = SenderKeyIdLayout::new(64).unwrap();
    assert_eq!(all_ratchet.key_id(0, 99), Ok(99));
    assert_eq!(all_ratchet.key_id(1, 0), Err(Error::KeyIdLayout));

    // Steps are counted forward, modulo 1 << R.
    assert_eq!(layout.steps_between(5, 7), 2);
    assert_eq!(layout.steps_between(15, 1), 2);
    assert_eq!(layout.steps_between(5, 5), 0);
}

fn ratchet(layout: SenderKeyIdLayout, generation: u64) -> SenderKeyRatchet {
    SenderKeyRatchet::new(SUITE, provider(), layout, generation, b"sender base key").unwrap()
}

#[test]
fn sender_key_ratchet_steps_the_base_key_and_the_key_id() {
    let layout = SenderKeyIdLayout::new(4).unwrap();
    let mut sender = ratchet(layout, 2);
    assert_eq!((sender.key_generation(), sender.ratchet_step()), (2, 0));
    assert_eq!(sender.key_id(), 0x20);
    assert_eq!(sender.base_key(), b"sender base key");

    let provider = provider();
    let mut expected = b"sender base key".to_vec();
    for step in 1..=20u64 {
        expected = ratchet_base_key(provider.crypto(), SUITE, &expected)
            .unwrap()
            .as_ref()
            .to_vec();
        let kid = sender.advance().unwrap();
        assert_eq!(kid, 0x20 | (step % 16));
        assert_eq!(sender.key_id(), kid);
        assert_eq!(sender.ratchet_step(), step);
        assert_eq!(sender.base_key(), expected);
        assert_eq!(sender.base_key().len(), SUITE.hash_len());
    }

    // How far a KID is from here: forward, within the generation.
    assert_eq!(sender.steps_to(sender.key_id()), Some(0));
    assert_eq!(sender.steps_to(0x26), Some(2));
    assert_eq!(sender.steps_to(0x23), Some(15));
    assert_eq!(sender.steps_to(0x36), None);

    assert!(matches!(
        SenderKeyRatchet::new(SUITE, provider.clone(), layout, 1 << 60, b"k"),
        Err(Error::KeyIdLayout)
    ));
    assert!(matches!(
        SenderKeyRatchet::new(SUITE, provider, layout, 0, b""),
        Err(Error::EmptyBaseKey)
    ));
}

/// A sender in the sender-keys scheme: its ratchet and the context holding its current key.
struct Sender {
    ratchet: SenderKeyRatchet,
    context: SFrameContext,
}

impl Sender {
    fn new(layout: SenderKeyIdLayout, generation: u64) -> Self {
        let ratchet = ratchet(layout, generation);
        let mut context = SFrameContext::new(SUITE, provider());
        context
            .add_send_key(ratchet.key_id(), ratchet.base_key())
            .unwrap();
        Self { ratchet, context }
    }

    fn advance(&mut self) {
        let previous = self.ratchet.key_id();
        let next = self.ratchet.advance().unwrap();
        self.context.remove_key(previous);
        self.context
            .add_send_key(next, self.ratchet.base_key())
            .unwrap();
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.context
            .encrypt(self.ratchet.key_id(), b"", plaintext)
            .unwrap()
    }
}

fn receiver_of(sender: &Sender) -> SenderKeyReceiver {
    let mut receiver = SenderKeyReceiver::new(SUITE, provider(), sender.ratchet.layout());
    receiver
        .set_key(sender.ratchet.key_id(), sender.ratchet.base_key())
        .unwrap();
    receiver
}

#[test]
fn sender_key_receiver_follows_the_senders_ratchet() {
    let layout = SenderKeyIdLayout::new(4).unwrap();
    let mut sender = Sender::new(layout, 1);
    let mut receiver = receiver_of(&sender);
    assert_eq!(receiver.current_key_id(), Some(0x10));

    let before = sender.encrypt(b"step 0");
    let held_back = sender.encrypt(b"step 0, late");
    assert_eq!(
        receiver.decrypt(b"", &before).as_deref(),
        Ok(&b"step 0"[..])
    );

    // The sender ratchets; the new KID tells the receiver to do the same.
    sender.advance();
    let after = sender.encrypt(b"step 1");
    assert_eq!(Header::decode(&after).unwrap().0.kid, 0x11);
    assert_eq!(receiver.decrypt(b"", &after).as_deref(), Ok(&b"step 1"[..]));
    assert_eq!(receiver.current_key_id(), Some(0x11));

    // The old key is kept for what was still on the way.
    assert_eq!(
        receiver.decrypt(b"", &held_back).as_deref(),
        Ok(&b"step 0, late"[..])
    );

    // Several steps at once: the keys of the steps passed over are kept too.
    sender.advance();
    let skipped = sender.encrypt(b"step 2");
    sender.advance();
    sender.advance();
    let ahead = sender.encrypt(b"step 4");
    assert_eq!(receiver.decrypt(b"", &ahead).as_deref(), Ok(&b"step 4"[..]));
    assert_eq!(receiver.current_key_id(), Some(0x14));
    assert_eq!(
        receiver.decrypt(b"", &skipped).as_deref(),
        Ok(&b"step 2"[..])
    );

    // Old keys are deleted: a bounded number stay, and none after forget_old_keys.
    assert_eq!(receiver.context().key_count(), 3);
    assert_eq!(
        receiver.decrypt(b"", &before),
        Err(Error::UnknownKeyId(0x10))
    );
    receiver.forget_old_keys();
    assert_eq!(receiver.context().key_count(), 1);
    assert_eq!(receiver.context().key_usage(0x14), Some(KeyUsage::Decrypt));
}

#[test]
fn sender_key_receiver_does_not_move_on_a_forged_key_id() {
    let layout = SenderKeyIdLayout::new(4).unwrap();
    let mut sender = Sender::new(layout, 1);
    let mut receiver = receiver_of(&sender);
    let authentic = sender.encrypt(b"step 0");

    // The authentic body under KIDs that claim later ratchet steps.
    for step in 1..=15u64 {
        let mut forged = Vec::new();
        Header::new(0x10 | step, 0).encode_to(&mut forged);
        forged.extend_from_slice(&authentic[2..]);
        let expected = if step <= 8 {
            // Within reach: derived, tried, refused.
            Error::AuthenticationFailed
        } else {
            Error::UnknownKeyId(0x10 | step)
        };
        assert_eq!(receiver.decrypt(b"", &forged), Err(expected), "step {step}");
    }
    assert_eq!(receiver.current_key_id(), Some(0x10));
    assert_eq!(receiver.context().key_count(), 1);

    // The ratchet did not move, so the sender's real steps are still followed one by one.
    assert_eq!(
        receiver.decrypt(b"", &authentic).as_deref(),
        Ok(&b"step 0"[..])
    );
    sender.advance();
    let next = sender.encrypt(b"step 1");
    assert_eq!(receiver.decrypt(b"", &next).as_deref(), Ok(&b"step 1"[..]));
}

#[test]
fn sender_key_receiver_needs_the_new_key_of_a_new_generation() {
    let layout = SenderKeyIdLayout::new(4).unwrap();
    let mut old = Sender::new(layout, 1);
    let mut receiver = receiver_of(&old);
    let last = old.encrypt(b"generation 1");

    // A new key generation is a fresh base key: it cannot be derived, only received.
    let mut new = Sender {
        ratchet: SenderKeyRatchet::new(SUITE, provider(), layout, 2, b"fresh base key").unwrap(),
        context: SFrameContext::new(SUITE, provider()),
    };
    new.context
        .add_send_key(new.ratchet.key_id(), new.ratchet.base_key())
        .unwrap();
    let first = new.encrypt(b"generation 2");
    assert_eq!(
        receiver.decrypt(b"", &first),
        Err(Error::UnknownKeyId(0x20))
    );

    receiver
        .set_key(new.ratchet.key_id(), new.ratchet.base_key())
        .unwrap();
    assert_eq!(
        receiver.decrypt(b"", &first).as_deref(),
        Ok(&b"generation 2"[..])
    );
    // The previous generation's key serves late frames until it is forgotten.
    assert_eq!(
        receiver.decrypt(b"", &last).as_deref(),
        Ok(&b"generation 1"[..])
    );
    receiver.forget_old_keys();
    assert_eq!(receiver.decrypt(b"", &last), Err(Error::UnknownKeyId(0x10)));
}

#[test]
fn sender_key_receiver_joining_midway_starts_from_the_current_key() {
    let layout = SenderKeyIdLayout::new(4).unwrap();
    let mut sender = Sender::new(layout, 1);
    let early = sender.encrypt(b"before the join");
    for _ in 0..5 {
        sender.advance();
    }
    // The newcomer gets (a) the current sender key and (b) the current KID.
    let mut newcomer = receiver_of(&sender);
    assert_eq!(newcomer.current_key_id(), Some(0x15));

    let now = sender.encrypt(b"after the join");
    assert_eq!(
        newcomer.decrypt(b"", &now).as_deref(),
        Ok(&b"after the join"[..])
    );
    sender.advance();
    let later = sender.encrypt(b"one step on");
    assert_eq!(
        newcomer.decrypt(b"", &later).as_deref(),
        Ok(&b"one step on"[..])
    );
    // What was encrypted before the ratchet steps it was given is out of its reach.
    assert!(newcomer.decrypt(b"", &early).is_err());
}

#[test]
fn sender_key_receiver_follows_key_ids_that_wrap_around() {
    // R = 2: four KIDs per generation, so the fifth step reuses the first KID.
    let layout = SenderKeyIdLayout::new(2).unwrap();
    let mut sender = Sender::new(layout, 1);
    let mut receiver = receiver_of(&sender);
    let mut step = 0u64;
    for round in 0..12u8 {
        let frame = sender.encrypt(&[round; 8]);
        assert_eq!(Header::decode(&frame).unwrap().0.kid, 4 | (step % 4));
        assert_eq!(
            receiver.decrypt(b"", &frame),
            Ok(vec![round; 8]),
            "round {round}, step {step}"
        );
        assert_eq!(receiver.current_key_id(), Some(4 | (step % 4)));
        // Two steps at a time on odd rounds, so a KID comes round while its old key is held.
        for _ in 0..=round % 2 {
            sender.advance();
            step += 1;
        }
    }
    assert_eq!(step, 18);
}

#[test]
fn sender_key_receiver_limits_how_far_it_follows() {
    let layout = SenderKeyIdLayout::new(8).unwrap();
    let mut sender = Sender::new(layout, 0);
    let mut receiver = receiver_of(&sender);
    receiver.set_max_ratchet_steps(3);
    receiver.set_retained_old_keys(0);

    for _ in 0..4 {
        sender.advance();
    }
    let too_far = sender.encrypt(b"four steps on");
    assert_eq!(receiver.decrypt(b"", &too_far), Err(Error::UnknownKeyId(4)));
    assert_eq!(receiver.current_key_id(), Some(0));

    // With no receiver key at all there is nothing to ratchet from.
    let mut empty = SenderKeyReceiver::new(SUITE, provider(), layout);
    assert_eq!(empty.current_key_id(), None);
    assert_eq!(empty.decrypt(b"", &too_far), Err(Error::UnknownKeyId(4)));
    assert_eq!(empty.decrypt(b"", &[]), Err(Error::TruncatedHeader));
    assert_eq!(empty.context().stats().syntax_errors, 1);
}
