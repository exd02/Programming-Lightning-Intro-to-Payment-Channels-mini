#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    unused_must_use,
    non_snake_case
)]
use crate::internal;
use bitcoin::script::{Builder, ScriptBuf, ScriptHash};
use internal::key_utils::{add_pubkeys, pubkey_multipication_tweak, pubkey_from_secret, add_privkeys, privkey_multipication_tweak, hash_pubkeys};
use internal::tx_utils::{build_output, build_transaction};
use internal::script_utils::{build_htlc_offerer_witness_script, p2wpkh_output_script};
use bitcoin::blockdata::opcodes::all as opcodes;
use bitcoin::secp256k1::{SecretKey, PublicKey as secp256k1PublicKey, Scalar};
use bitcoin::PublicKey;
use bitcoin::hashes::Hash;
use bitcoin::{Block, OutPoint, PubkeyHash, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin::transaction::Version;
use bitcoin::locktime::absolute::LockTime;

//
// Exercise 1
//

pub fn two_of_two_multisig_witness_script(
    pubkey1: &PublicKey,
    pubkey2: &PublicKey,
) -> ScriptBuf {
    // // convert pubkeys to compressed format
    // let mut keys = [*pubkey1, *pubkey2];
    // keys[0].compressed = true;
    // keys[1].compressed = true;
    
    // // sort compressed pubkeys lexicographically
    // keys.sort_unstable_by_key(|k| PublicKey::to_sort_key(*k));

    // build 2x2 multisig script
    Builder::new()
        .push_int(2)
        .push_key(&pubkey1)
        .push_key(&pubkey2)
        .push_int(2)
        .push_opcode(opcodes::OP_CHECKMULTISIG)
        .into_script()
}

//
// Exercise 2
//

pub fn build_funding_transaction(
    txins: Vec<TxIn>,
    alice_pubkey: &PublicKey,
    bob_pubkey: &PublicKey,
    amount: u64,
) -> Transaction {
    // Step 1: Build a Witness Script for the Multisig
    let witness_script = two_of_two_multisig_witness_script(alice_pubkey, bob_pubkey);
    
    // Step 2: Create the Funding Transaction Output
    let funding_txout = build_output(amount, witness_script.to_p2wsh());
    
    // Step 3: Define Version and Locktime
    let version = Version::TWO;
    let locktime = LockTime::ZERO;
    
    // Step 4: Build and Return the Transaction
    Transaction {
        version: version,
        lock_time: locktime,
        input: txins,
        output: vec![funding_txout]
    }
}

//
// Exercise 3
//

pub fn build_refund_transaction(
    funding_txin: TxIn,
    alice_pubkey: PublicKey,
    bob_pubkey: PublicKey,
    alice_balance: u64,
    bob_balance: u64
) -> Transaction {
    // Step 1: Build a Output Scripts
    let alice_script = p2wpkh_output_script(alice_pubkey);
    let bob_script = p2wpkh_output_script(bob_pubkey);

    // Step 2: Define Outputs
    let alice_output = build_output(alice_balance, alice_script);
    let bob_output = build_output(bob_balance, bob_script);

    // Order outputs
    let outputs = if alice_output < bob_output 
        { vec![alice_output, bob_output] }
        else { vec![bob_output, alice_output] };
    
    // Step 3: Define Version and Locktime
    let version = Version::TWO;
    let locktime = LockTime::ZERO;
    
    // Step 4: Build and Return the Transaction
    // -- remember, inputs and outputs must be passed in as vectors (vec![])
    Transaction {
        version: version,
        lock_time: locktime,
        input: vec![funding_txin],
        output: outputs
    }
}

//
// Exercise 4
//

pub fn generate_revocation_pubkey(
    countersignatory_basepoint: secp256k1PublicKey,
    per_commitment_point: secp256k1PublicKey,
) -> secp256k1PublicKey {
    unimplemented!()
}

//
// Exercise 5
//

pub fn generate_revocation_privkey(countersignatory_per_commitment_secret: SecretKey, revocation_base_secret: SecretKey) -> SecretKey {
    unimplemented!()
}

//
// Exercise 6
//

pub fn to_local(
    revocation_key: &PublicKey,
    to_local_delayed_pubkey: &PublicKey,
    to_self_delay: i64,
) -> ScriptBuf {
    unimplemented!()
}

//
// Exercise 7
//

pub fn build_commitment_transaction(
    funding_txin: TxIn,
    revocation_pubkey: &PublicKey,
    to_local_delayed_pubkey: &PublicKey,
    remote_pubkey: PublicKey,
    to_self_delay: i64,
    local_amount: u64,
    remote_amount: u64,
) -> Transaction {

    unimplemented!()
}

//
// Exercise 8
//

pub fn build_htlc_commitment_transaction(
    funding_txin: TxIn,
    revocation_pubkey: &PublicKey,
    remote_htlc_pubkey: &PublicKey,
    local_htlc_pubkey: &PublicKey,
    to_local_delayed_pubkey: &PublicKey,
    remote_pubkey: PublicKey,
    to_self_delay: i64,
    payment_hash160: &[u8; 20],
    htlc_amount: u64,
    local_amount: u64,
    remote_amount: u64,
) -> Transaction {
    unimplemented!()
}

//
// Exercise 9
//

pub fn build_htlc_timeout_transaction(
    htlc_txin: TxIn,
    revocation_pubkey: &PublicKey,
    to_local_delayed_pubkey: &PublicKey,
    to_self_delay: i64,
    cltv_expiry: u32,
    htlc_amount: u64,
) -> Transaction {
    unimplemented!()
}
