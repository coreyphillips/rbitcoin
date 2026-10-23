use rbitcoin_consensus::script::crypto::{
    is_compressed_or_uncompressed_pubkey, is_compressed_pubkey, is_defined_hashtype,
    is_valid_signature_encoding, parse_der_sig, TapSpentHashes,
};

fn valid_der_sig() -> Vec<u8> {
    // Minimal valid-shaped DER + SIGHASH_ALL
    // 30 06 02 01 01 02 01 01 01
    vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]
}

#[test]
fn strictenc_pubkey_and_hashtype_helpers() {
    // Compressed / uncompressed only — hybrid 06/07 rejected.
    assert!(is_compressed_or_uncompressed_pubkey(&[0x02; 33]));
    assert!(is_compressed_or_uncompressed_pubkey(&[0x03; 33]));
    let mut uncomp = vec![0x04];
    uncomp.extend_from_slice(&[0x11; 64]);
    assert!(is_compressed_or_uncompressed_pubkey(&uncomp));
    let mut hybrid = vec![0x06];
    hybrid.extend_from_slice(&[0x11; 64]);
    assert!(!is_compressed_or_uncompressed_pubkey(&hybrid));
    assert!(!is_compressed_or_uncompressed_pubkey(&[]));
    assert!(!is_compressed_or_uncompressed_pubkey(&[0x02; 32]));
    // `0x04` is uncompressed only at 65 bytes. A shorter key is not
    // accepted by dropping the length guard.
    assert!(!is_compressed_or_uncompressed_pubkey(&[0x04; 64]));
    assert!(!is_compressed_or_uncompressed_pubkey(&[0x04; 66]));
    assert!(is_compressed_pubkey(&[0x02; 33]));
    assert!(!is_compressed_pubkey(&[0x02; 32]));
    assert!(!is_compressed_pubkey(&[0x04; 33]));

    assert!(is_defined_hashtype(&[0x30, 0x01])); // 0x01 is SIGHASH_ALL
    assert!(is_defined_hashtype(&[0x30, 0x02])); // 0x02 is SIGHASH_NONE
    assert!(is_defined_hashtype(&[0x30, 0x03])); // 0x03 is SIGHASH_SINGLE
    assert!(is_defined_hashtype(&[0x30, 0x81])); // 0x81 is SIGHASH_ALL with ANYONECANPAY
    assert!(!is_defined_hashtype(&[0x30, 0x00]));
    assert!(!is_defined_hashtype(&[0x30, 0x04]));
    assert!(!is_defined_hashtype(&[]));
}

#[test]
fn bip66_encoding_edge_cases() {
    assert!(!is_valid_signature_encoding(&[]));
    assert!(!is_valid_signature_encoding(&[0x30; 8])); // eight bytes is under the 9-byte minimum
    assert!(!is_valid_signature_encoding(&[0x30; 74])); // 74 bytes is over the 73-byte maximum
    let mut bad = valid_der_sig();
    bad[0] = 0x31;
    assert!(!is_valid_signature_encoding(&bad));
    // Byte 1 is the DER content length, and 0x05 does not match the body.
    let mut bad = valid_der_sig();
    bad[1] = 0x05;
    assert!(!is_valid_signature_encoding(&bad));
    // Byte 2 must be the integer marker 0x02.
    let mut bad = valid_der_sig();
    bad[2] = 0x03;
    assert!(!is_valid_signature_encoding(&bad));
    // The R integer length is zero.
    assert!(!is_valid_signature_encoding(&[
        0x30, 0x06, 0x02, 0x00, 0x02, 0x01, 0x01, 0x01
    ]));
    // The R integer has its high bit set, so it would be negative.
    let neg = vec![0x30, 0x07, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01, 0x01];
    assert!(!is_valid_signature_encoding(&neg));
    // R has a leading zero that is not required to keep the value positive.
    let pad = vec![0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01, 0x01];
    assert!(!is_valid_signature_encoding(&pad));
    // The S integer has its high bit set, so it would be negative.
    let sneg = vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x80, 0x01];
    assert!(!is_valid_signature_encoding(&sneg));
    // S has a leading zero that is not required to keep the value positive.
    let spad = vec![0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01, 0x01];
    assert!(!is_valid_signature_encoding(&spad));
    // The S integer length is zero.
    assert!(!is_valid_signature_encoding(&[
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x00, 0x01
    ]));
    // The S tag is not the integer marker.
    let mut sm = valid_der_sig();
    // Index 4 is R. Its length byte at index 3 is 1, so this write is not the S tag.
    sm[4] = 0x03;
    let mut sm = valid_der_sig();
    // The bytes are 30 06 02 01 01 02 01 01 01, so the S tag is at index 5.
    sm[5] = 0x03;
    assert!(!is_valid_signature_encoding(&sm));

    assert!(is_valid_signature_encoding(&valid_der_sig()));
    // BIP66 does not range-check the hashtype byte. STRICTENC does,
    // via `is_defined_hashtype`. `0x00`, `0x04`, `0x80`, and `0x85`
    // stay valid DER.
    for ht in [0x00u8, 0x04, 0x80, 0x85] {
        let mut sig = valid_der_sig();
        let last = sig.len() - 1;
        sig[last] = ht;
        assert!(
            is_valid_signature_encoding(&sig),
            "BIP66 keeps hashtype {ht:#x}"
        );
        assert!(
            !is_defined_hashtype(&sig),
            "STRICTENC rejects hashtype {ht:#x}"
        );
    }
    // A one-byte zero integer is minimal. `len > 1` must not become `>=`.
    assert!(is_valid_signature_encoding(&[
        0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x01
    ]));
    assert!(is_valid_signature_encoding(&[
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x01
    ]));
    let _ = (neg, pad, sneg, spad);
}

#[test]
fn parse_der_empty_and_strict() {
    assert!(parse_der_sig(&[], true).is_err());
    // non-BIP66 but lax may still fail parse — just exercise strict reject
    let bad = vec![0x30, 0x01, 0x00];
    assert!(parse_der_sig(&bad, true).is_err());
}

#[test]
fn spent_hashes_report_a_missing_wire_prevout() {
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let job = rbitcoin_consensus::block::ScriptCheckJob::from_parts(
        [0u8; 32],
        rbitcoin_consensus::block::JobPrevouts::Shared(vec![
            rbitcoin_consensus::block::SharedPrevout::Wire {
                tx_index: 0,
                vout: 0,
            },
        ]),
        rbitcoin_consensus::block::JobTx::owned(tx),
        rbitcoin_consensus::block::ScriptVerifyFlags::buried(false, false, false, true, true),
    );
    let err = TapSpentHashes::default().get(&job).unwrap_err();
    assert!(
        format!("{err}").contains("invariant") || format!("{err}").contains("Corrupt"),
        "{err}"
    );
}
