use bitcoin::script::Script;
use bitcoin::sighash::SighashCache;
use bitcoin::Transaction;
use rbitcoin_consensus::block::ScriptCheckJob;
use rbitcoin_consensus::script::p2pkh::*;

use bitcoin::absolute::LockTime;
use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};

#[test]
fn parse_two_pushes_errors() {
    assert!(parse_two_pushes(Script::from_bytes(&[0x51])).is_err()); // 0x51 is OP_1, which is not a data push
    assert!(parse_two_pushes(Script::from_bytes(&[0x00])).is_err()); // OP_0 is not the two data pushes this parser requires
    assert!(parse_two_pushes(Script::from_bytes(&[0x01, 0xaa])).is_err()); // one complete push is not the two pushes this parser requires
    assert!(parse_two_pushes(Script::from_bytes(&[0x05, 0x01])).is_err()); // the push is truncated, so it does not decode
    let mut big = vec![0x4d, 0x09, 0x02]; // OP_PUSHDATA2 claims 521 bytes
    big.extend([0u8; 521]);
    big.extend([0x01, 0xbb]);
    assert!(parse_two_pushes(Script::from_bytes(&big)).is_err()); // a push over 520 bytes is rejected
    let ok = parse_two_pushes(Script::from_bytes(&[0x01, 0xaa, 0x01, 0xbb])).unwrap();
    assert_eq!(ok, (vec![0xaa], vec![0xbb]));
}

#[test]
fn verify_pubkey_hash_mismatch() {
    let mut spk = vec![0x76, 0xa9, 0x14];
    spk.extend([0u8; 20]);
    spk.extend([0x88, 0xac]);
    let mut ss = vec![0x01, 0x30, 0x21];
    ss.extend([0x02; 33]); // 0x02 repeated has a compressed-key shape, not a real key
    let tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: rbitcoin_consensus::block::JobPrevouts::owned(vec![TxOut {
            value: Amount::from_sat(10),
            script_pubkey: ScriptBuf::from_bytes(spk),
        }]),
        tx: rbitcoin_consensus::block::JobTx::owned(tx.clone()),
        flags: rbitcoin_consensus::block::ScriptVerifyFlags {
            bip65_active: true,
            bip112_active: true,
            bip66_active: true,
            bip16_active: true,
            taproot_active: true,
            minimal_if: false,
            nullfail: false,
            low_s: false,
            strictenc: false,
            null_dummy: false,
            minimal_data: false,
            witness_pubkeytype: false,
            witness_active: true,
            discourage_upgradable_witness: false,
            const_scriptcode: false,
            cleanstack: false,
        },
        pre: std::sync::OnceLock::new(),
    };
    let mut cache = SighashCache::new(&*job.tx);
    let err = verify(&job, 0, &job.tx, &mut cache).unwrap_err();
    assert!(format!("{err}").contains("p2pkh"));
}
