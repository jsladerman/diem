// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0
use diem_sdk::{
    crypto::{hash::CryptoHash, HashValue},
    transaction_builder::Currency,
    types::{
        account_config::xus_tag,
        event::EventKey,
        ledger_info::LedgerInfoWithSignatures,
        transaction::{Transaction, TransactionPayload},
        AccountKey, LocalAccount,
    },
};
use diem_transaction_builder::stdlib;
use std::error::Error;

use assert_json_diff::assert_json_eq;
use rand_core::OsRng;
use serde_json::json;

use std::ops::Deref;

pub struct CurrencyInfo;
mod helper;
use helper::JsonRpcTestHelper;

use crate::helper::FaucetClient;

#[test]
fn get_dd_preburn_test() {
    let factory = JsonRpcTestHelper::get_transaction_factory();
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let mut tc_account = JsonRpcTestHelper::get_tc_account(&env);
    let mut dd = LocalAccount::generate(&mut OsRng);
    let create_dd_account_txn =
        tc_account.sign_with_transaction_builder(factory.create_designated_dealer(
            Currency::XUS,
            0, // sliding_nonce
            dd.authentication_key(),
            &format!("No. {} DD", tc_account.sequence_number()),
            false, // add all currencies
        ));
    env.submit_and_wait(&create_dd_account_txn);
    let address = format!("{:x}", dd.address());
    let resp = env.send("get_account", json!([address]));
    let result = resp.result.unwrap();
    let human_name = result["role"]["human_name"].as_str().unwrap();

    // Without Preburns
    assert_json_eq!(
        result,
        json!({
            "address": address,
            "authentication_key": dd.authentication_key(),
            "balances": [
                {
                    "amount": 0_u64,
                    "currency": "XUS"
                },
            ],
            "delegated_key_rotation_capability": false,
            "delegated_withdrawal_capability": false,
            "is_frozen": false,
            "received_events_key": EventKey::new_from_address(&dd.address(), 3),
            "role": {
                "type": "designated_dealer",
                "base_url": "",
                "compliance_key": "",
                "expiration_time": 18446744073709551615_u64,
                "human_name": human_name,
                "preburn_balances": [
                    {
                        "amount": 0_u64,
                        "currency": "XUS"
                    }
                ],
                "preburn_queues": [
                    {
                        "preburns": [],
                        "currency": "XUS",
                    }
                ],
                "received_mint_events_key": EventKey::new_from_address(&dd.address(), 0),
                "compliance_key_rotation_events_key": EventKey::new_from_address(&dd.address(), 1),
                "base_url_rotation_events_key": EventKey::new_from_address(&dd.address(), 2),
            },
            "sent_events_key": EventKey::new_from_address(&dd.address(), 4),
            "sequence_number": dd.sequence_number(),
            "version": resp.diem_ledger_version,
        }),
    );

    // Fund the DD account and create some Pre-burns
    let faucet = FaucetClient::new(
        JsonRpcTestHelper::get_mint_url(),
        JsonRpcTestHelper::get_json_rpc_url(),
    );
    faucet
        .fund_with_auth_key(
            dd.authentication_key().to_string().as_str(),
            Currency::XUS.as_str(),
            400,
        )
        .unwrap();

    env.submit_and_wait(&dd.sign_with_transaction_builder(
        factory.script(stdlib::encode_preburn_script(xus_tag(), 100)),
    ));
    env.submit_and_wait(&dd.sign_with_transaction_builder(
        factory.script(stdlib::encode_preburn_script(xus_tag(), 40)),
    ));
    env.submit_and_wait(&dd.sign_with_transaction_builder(
        factory.script(stdlib::encode_preburn_script(xus_tag(), 60)),
    ));

    let resp = env.send("get_account", json!([address]));
    let result = resp.result.unwrap();

    // With Preburns
    assert_json_eq!(
        result,
        json!({
            "address": address,
            "authentication_key": dd.authentication_key(),
            "balances": [
                {
                    "amount": 200_u64,
                    "currency": "XUS"
                },
            ],
            "delegated_key_rotation_capability": false,
            "delegated_withdrawal_capability": false,
            "is_frozen": false,
            "received_events_key": EventKey::new_from_address(&dd.address(), 3),
            "role": {
                "type": "designated_dealer",
                "base_url": "",
                "compliance_key": "",
                "expiration_time": 18446744073709551615_u64,
                "human_name": human_name,
                "preburn_balances": [
                    {
                        "amount": 200_u64,
                        "currency": "XUS"
                    }
                ],
                "preburn_queues": [
                    {
                        "currency": "XUS",
                        "preburns": [
                            {
                                "preburn": {
                                    "amount": 100_u64,
                                    "currency": "XUS",
                                },
                                "metadata": "",
                            },
                            {
                                "preburn": {
                                    "amount": 40_u64,
                                    "currency": "XUS"
                                },
                                "metadata": "",
                            },
                            {
                                "preburn": {
                                    "amount": 60_u64,
                                    "currency": "XUS"
                                },
                                "metadata": "",
                            },
                        ],
                    }
                ],
                "received_mint_events_key": EventKey::new_from_address(&dd.address(), 0),
                "compliance_key_rotation_events_key": EventKey::new_from_address(&dd.address(), 1),
                "base_url_rotation_events_key": EventKey::new_from_address(&dd.address(), 2),
            },
            "sent_events_key": EventKey::new_from_address(&dd.address(), 4),
            "sequence_number": dd.sequence_number(),
            "version": resp.diem_ledger_version,
        }),
    );
}
#[test]
fn rotate_compliance_key_test() {
    let factory = JsonRpcTestHelper::get_transaction_factory();
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let mut tc_account = JsonRpcTestHelper::get_tc_account(&env);
    let (mut parent, _child1, _child2) =
        env.create_parent_and_two_child_accounts(&factory, 1_000_000_000, &mut tc_account);
    let compliance_key = AccountKey::generate(&mut OsRng);

    let txn = parent.sign_with_transaction_builder(factory.rotate_dual_attestation_info(
        b"http://hello.com".to_vec(),
        compliance_key.public_key().to_bytes().to_vec(),
    ));

    let result = env.submit_and_wait(&txn);
    let version = result["version"].as_u64().unwrap();
    let rotated_seconds = result["events"][0]["data"]["time_rotated_seconds"]
        .as_u64()
        .unwrap();
    assert_json_eq!(
        result["events"],
        json!([
            {
                "data":{
                    "new_base_url":"http://hello.com",
                    "time_rotated_seconds": rotated_seconds,
                    "type":"baseurlrotation"
                },
                "key": format!("0100000000000000{:x}", parent.address()),
                "sequence_number":0,
                "transaction_version":version
            },
            {
                "data":{
                    "new_compliance_public_key": hex::encode(compliance_key.public_key().to_bytes()),
                    "time_rotated_seconds": rotated_seconds,
                    "type":"compliancekeyrotation"
                },
                "key": format!("0000000000000000{:x}", parent.address()),
                "sequence_number":0,
                "transaction_version":version
            }
        ]),
    );
}
#[test]
fn resubmitting_transaction_wont_fail_test() {
    let factory = JsonRpcTestHelper::get_transaction_factory();
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let mut tc_account = JsonRpcTestHelper::get_tc_account(&env);
    let (_parent, mut child1, child2) =
        env.create_parent_and_two_child_accounts(&factory, 1_000_000_000, &mut tc_account);
    let txn = child1.sign_with_transaction_builder(factory.peer_to_peer(
        Currency::XUS,
        child2.address(),
        200,
    ));

    env.submit(&txn);
    env.submit(&txn);
    env.wait_for_txn(&txn);
}
#[test]
fn get_tressury_compliance_test() {
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let address = JsonRpcTestHelper::get_tc_account_address();
    let resp = env.send("get_account", json!([address]));
    let result = resp.result.unwrap();
    let authentication_key = result["authentication_key"].as_str().unwrap();
    let sequence_number = result["sequence_number"].as_u64().unwrap();
    assert_json_eq!(
        result,
        json!({
            "address": address,
            "authentication_key": authentication_key,
            "balances": [],
            "delegated_key_rotation_capability": false,
            "delegated_withdrawal_capability": false,
            "is_frozen": false,
            "received_events_key": format!("0100000000000000{}", address),
            "role": {
                "vasp_domain_events_key": format!("0000000000000000{}", address),
                "type": "treasury_compliance",
            },
            "sent_events_key": format!("0200000000000000{}", address),
            "sequence_number": sequence_number,
            "version": resp.diem_ledger_version,
        }),
    );
}
#[test]
fn peer_to_peer_with_events() {
    let factory = JsonRpcTestHelper::get_transaction_factory();
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let mut tc_account = JsonRpcTestHelper::get_tc_account(&env);

    let prev_ledger_version = env.send("get_metadata", json!([])).diem_ledger_version;

    let (_parent1, mut child1_1, _child1_2) =
        env.create_parent_and_two_child_accounts(&factory, 3_000_000_000, &mut tc_account);
    let (_parent2, child2_1, _child2_2) =
        env.create_parent_and_two_child_accounts(&factory, 3_000_000_000, &mut tc_account);

    let txn = child1_1.sign_with_transaction_builder(factory.peer_to_peer(
        Currency::XUS,
        child2_1.address(),
        200_000,
    ));

    env.submit_and_wait(&txn);
    let txn_hex = hex::encode(bcs::to_bytes(&txn).expect("bcs txn failed"));

    let sender = &child1_1;
    let receiver = &child2_1;

    let resp = env.send(
        "get_account_transaction",
        json!([sender.address(), 0, true]),
    );
    let result = resp.result.unwrap();
    let version = result["version"].as_u64().unwrap();
    assert_eq!(
        true,
        version > prev_ledger_version && version <= resp.diem_ledger_version
    );

    let gas_used = result["gas_used"].as_u64().expect("exist as u64");
    let txn_hash = Transaction::UserTransaction(txn.clone()).hash().to_hex();

    let script = match txn.payload() {
        TransactionPayload::Script(s) => s,
        _ => unreachable!(),
    };
    let script_hash = HashValue::sha3_256_of(script.code()).to_hex();
    let script_bytes = hex::encode(bcs::to_bytes(script).unwrap());
    println!("{:#?}", result);
    let expected = json!({
        "bytes": format!("00{}", txn_hex),
        "events": [
            {
                "data": {
                    "amount": {"amount": 200000_u64, "currency": "XUS"},
                    "metadata": "",
                    "receiver": format!("{:x}", receiver.address()),
                    "sender": format!("{:x}", sender.address()),
                    "type": "sentpayment"
                },
                "key": format!("0100000000000000{:x}", sender.address()),
                "sequence_number": 0,
                "transaction_version": version,
            },
            {
                "data": {
                    "amount": {"amount": 200000_u64, "currency": "XUS"},
                    "metadata": "",
                    "receiver": format!("{:x}", receiver.address()),
                    "sender": format!("{:x}", sender.address()),
                    "type": "receivedpayment"
                },
                "key": format!("0000000000000000{:x}", receiver.address()),
                "sequence_number": 1,
                "transaction_version": version
            }
        ],
        "gas_used": gas_used,
        "hash": txn_hash,
        "transaction": {
            "chain_id": 2,
            "expiration_timestamp_secs": txn.expiration_timestamp_secs(),
            "gas_currency": "XUS",
            "gas_unit_price": 0,
            "max_gas_amount": 1000000,
            "public_key": sender.public_key().to_string(),
            "script": {
                "type": "peer_to_peer_with_metadata",
                "type_arguments": [
                    "XUS"
                ],
                "arguments": [
                    format!("{{ADDRESS: {:?}}}", receiver.address()),
                    "{U64: 200000}",
                    "{U8Vector: 0x}",
                    "{U8Vector: 0x}"
                ],
                "code": hex::encode(script.code()),
                "amount": 200000,
                "currency": "XUS",
                "metadata": "",
                "metadata_signature": "",
                "receiver": format!("{:x}", receiver.address()),
            },
            "script_bytes": script_bytes,
            "script_hash": script_hash,
            "secondary_public_keys": [],
            "secondary_signature_schemes": [],
            "secondary_signatures": [],
            "secondary_signers": [],
            "sender": format!("{:x}", sender.address()),
            "sequence_number": 0,
            "signature": hex::encode(txn.authenticator().sender().signature_bytes()),
            "signature_scheme": "Scheme::Ed25519",
            "type": "user"
        },
        "version": version,
        "vm_status": {"type": "executed"}
    });
    assert_json_eq!(result, expected);
}
#[test]
fn no_unknown_events_test() -> Result<(), Box<dyn Error>> {
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let response = env.send("get_transactions", json!([0, 1000, true]));
    let txns = response.result.unwrap();
    for txn in txns.as_array().unwrap() {
        for event in txn["events"].as_array().unwrap() {
            let event_type = event["data"]["type"].as_str().unwrap();
            assert_ne!(event_type, "unknown", "{}", event);
        }
    }
    Ok(())
}
#[test]
fn get_account_transactions_without_events_test() -> Result<(), Box<dyn Error>> {
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());

    let response = env.send(
        "get_account_transactions",
        json!([JsonRpcTestHelper::get_tc_account_address(), 0, 1000, false]),
    );
    let txns = response.result.unwrap();
    assert!(!txns.as_array().unwrap().is_empty());

    for txn in txns.as_array().unwrap() {
        assert_eq!(txn["events"], json!([]));
    }
    Ok(())
}
#[test]
fn get_transactions_without_events_test() -> Result<(), Box<dyn Error>> {
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let response = env.send("get_transactions", json!([0, 1000, false]));
    let txns = response.result.unwrap();
    assert!(!txns.as_array().unwrap().is_empty());

    for (index, txn) in txns.as_array().unwrap().iter().enumerate() {
        assert_eq!(txn["version"], index);
        assert_eq!(txn["events"], json!([]));
    }
    Ok(())
}
#[test]
fn create_account_event_test() -> Result<(), Box<dyn Error>> {
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let response = env.send(
        "get_events",
        json!(["00000000000000000000000000000000000000000a550c18", 0, 2]),
    );
    let events = response.result.unwrap();
    assert_json_eq!(
        events,
        json!([
            {
                "data":{
                    "created_address":"0000000000000000000000000a550c18",
                    "role_id":0,
                    "type":"createaccount"
                },
                "key":"00000000000000000000000000000000000000000a550c18",
                "sequence_number":0,
                "transaction_version":0
            },
            {
                "data":{
                    "created_address":"0000000000000000000000000b1e55ed",
                    "role_id":1,
                    "type":"createaccount"
                },
                "key":"00000000000000000000000000000000000000000a550c18",
                "sequence_number":1,
                "transaction_version":0
            },
        ]),
    );
    Ok(())
}
#[test]
fn child_vasp_account_role_test() -> Result<(), Box<dyn Error>> {
    let factory = JsonRpcTestHelper::get_transaction_factory();
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let mut tc_account = JsonRpcTestHelper::get_tc_account(&env);
    let (parent, child) = env.create_parent_and_one_child_account(&factory, 500, &mut tc_account);

    let address = format!("{:x}", child.address());
    let resp = env.send("get_account", json!([address]));
    let result = resp.result.unwrap();

    assert_json_eq!(
        result,
        json!({
            "address": address,
            "authentication_key": child.authentication_key(),
            "balances": [{"amount": 0_u64, "currency": "XUS"}],
            "delegated_key_rotation_capability": false,
            "delegated_withdrawal_capability": false,
            "is_frozen": false,
            "received_events_key": EventKey::new_from_address(&child.address(), 0),
            "role": {
                "type": "child_vasp",
                "parent_vasp_address": parent.address(),
            },
            "sent_events_key": EventKey::new_from_address(&child.address(), 1),
            "sequence_number": 0,
            "version": resp.diem_ledger_version,
        }),
    );
    Ok(())
}

#[test]
fn get_account_by_version_test() -> Result<(), Box<dyn Error>> {
    let factory = JsonRpcTestHelper::get_transaction_factory();
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());

    let mut tc_account = JsonRpcTestHelper::get_tc_account(&env);
    let (vasp, child_1) = env.create_parent_and_one_child_account(&factory, 500, &mut tc_account);

    let txn1 = vasp.sign_transaction(
        factory
            .peer_to_peer(Currency::XUS, child_1.address(), 200)
            .sender(vasp.address())
            .sequence_number(vasp.sequence_number())
            .build(),
    );

    env.submit(&txn1);
    println!("{}", vasp.address().to_string().as_str());
    let resp = env.send(
        "get_account_transaction",
        json!([vasp.address().to_string().as_str(), 0, false]),
    );
    println!("{:?}", resp);
    let result = resp.result.unwrap();

    let prev_version: u64 = result["version"].as_u64().unwrap() - 1;
    let resp = env.send(
        "get_account",
        json!([vasp.address().to_string().as_str(), prev_version]),
    );
    let result = resp.result.unwrap();
    let human_name = result["role"]["human_name"].as_str().unwrap();
    println!("{:#?}", result);
    assert_json_eq!(
        result,
        json!({
            "address": vasp.address().to_string().to_lowercase().as_str(),
            "authentication_key": vasp.authentication_key().to_string(),
            "balances": [{"amount": 0_u64, "currency": "XUS"}],
            "delegated_key_rotation_capability": false,
            "delegated_withdrawal_capability": false,
            "is_frozen": false,
            "received_events_key": EventKey::new_from_address(&vasp.address(), 2),
            "role": {
                "base_url": "",
                "base_url_rotation_events_key": EventKey::new_from_address(&vasp.address(), 1),
                "compliance_key": "",
                "compliance_key_rotation_events_key": EventKey::new_from_address(&vasp.address(), 0),
                "vasp_domains": [],
                "expiration_time": 18446744073709551615_u64,
                "human_name": human_name,
                "num_children": 0,
                "type": "parent_vasp",
            },
            "sent_events_key": EventKey::new_from_address(&vasp.address(), 3),
            "sequence_number": 0,
            "version": prev_version,
        }),
    );
    Ok(())
}

#[test]
fn unknown_role_type_test() -> Result<(), Box<dyn Error>> {
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());

    let address = format!("{:x}", diem_sdk::types::account_config::diem_root_address());
    let resp = env.send("get_account", json!([address]));
    let mut result = resp.result.unwrap();
    // as we generate account auth key, ignore it in assertion
    assert_ne!(result["authentication_key"].as_str().unwrap(), "");
    result["authentication_key"] = json!(null);
    let sequence_number = result["sequence_number"].as_u64().unwrap();
    assert_json_eq!(
        result,
        json!({
            "address": address,
            "authentication_key": null,
            "balances": [],
            "delegated_key_rotation_capability": false,
            "delegated_withdrawal_capability": false,
            "is_frozen": false,
            "received_events_key": "02000000000000000000000000000000000000000a550c18",
            "role": { "type": "unknown" },
            "sent_events_key": "03000000000000000000000000000000000000000a550c18",
            "sequence_number": sequence_number,
            "version": resp.diem_ledger_version,
        }),
    );
    Ok(())
}
#[test]
fn account_not_found_test() -> Result<(), Box<dyn Error>> {
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let random_local_account = LocalAccount::generate(&mut OsRng);

    let resp = env.send(
        "get_account",
        json!([random_local_account.address().to_string().as_str()]),
    );
    println!("{:#?}", resp);
    assert!(resp.result.is_none());
    Ok(())
}
#[test]
fn block_metadata_test() -> Result<(), Box<dyn Error>> {
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());

    // batch request
    let resp = env.send_request(json!([
        {"jsonrpc": "2.0", "method": "get_metadata", "params": [], "id": 1},
        {"jsonrpc": "2.0", "method": "get_state_proof", "params": [0], "id": 2}
    ]));

    // extract both responses
    let resps: Vec<serde_json::Value> =
        serde_json::from_value(resp).expect("should be valid serde_json::Value");
    let metadata = &resps.iter().find(|g| g["id"] == 1).unwrap()["result"];
    let state_proof = &resps.iter().find(|g| g["id"] == 2).unwrap()["result"];

    // extract header and ensure they match in both responses
    let diem_chain_id = &resps[0]["diem_chain_id"];
    let diem_ledger_timestampusec = &resps[0]["diem_ledger_timestampusec"];
    let diem_ledger_version = &resps[0]["diem_ledger_version"];

    assert_eq!(diem_chain_id, &resps[1]["diem_chain_id"]);
    assert_eq!(
        diem_ledger_timestampusec,
        &resps[1]["diem_ledger_timestampusec"]
    );
    assert_eq!(diem_ledger_version, &resps[1]["diem_ledger_version"]);

    // parse metadata
    assert_eq!(&metadata["chain_id"], diem_chain_id);
    assert_eq!(&metadata["timestamp"], diem_ledger_timestampusec);
    assert_eq!(&metadata["version"], diem_ledger_version);

    // All genesis's start with closed publishing so this should be populated with a
    // list of allowed scripts and publishing off
    assert_ne!(metadata["script_hash_allow_list"], json!([]));
    assert_eq!(metadata["module_publishing_allowed"], false);
    //assert_eq!(metadata["diem_version"], DIEM_MAX_KNOWN_VERSION.major);
    assert_eq!(metadata["dual_attestation_limit"], 1000000000);
    assert_ne!(diem_ledger_timestampusec, 0);
    assert_ne!(diem_ledger_version, 0);

    // prove the accumulator_root_hash
    let info_hex = state_proof["ledger_info_with_signatures"].as_str().unwrap();
    let info: LedgerInfoWithSignatures = bcs::from_bytes(&hex::decode(&info_hex).unwrap()).unwrap();
    let expected_hash = info
        .deref()
        .ledger_info()
        .transaction_accumulator_hash()
        .to_hex();
    assert_eq!(
        expected_hash,
        metadata["accumulator_root_hash"].as_str().unwrap()
    );
    Ok(())
}
#[test]
fn old_metadata_test() -> Result<(), Box<dyn Error>> {
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let resp = env.send("get_metadata", json!([1]));
    let metadata = resp.result.unwrap();
    // no data provided for the following fields when requesting older version
    assert_eq!(metadata["script_hash_allow_list"], json!(null));
    assert_eq!(metadata["module_publishing_allowed"], json!(null));
    assert_eq!(metadata["diem_version"], json!(null));
    Ok(())
}

#[test]
fn currency_info_test() -> Result<(), Box<dyn Error>> {
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());

    let resp = env.send("get_currencies", json!([]));
    assert_json_eq!(
        resp.result.unwrap(),
        json!([
            {
                "burn_events_key": "06000000000000000000000000000000000000000a550c18",
                "cancel_burn_events_key": "08000000000000000000000000000000000000000a550c18",
                "code": "XUS",
                "exchange_rate_update_events_key": "09000000000000000000000000000000000000000a550c18",
                "fractional_part": 100,
                "mint_events_key": "05000000000000000000000000000000000000000a550c18",
                "preburn_events_key": "07000000000000000000000000000000000000000a550c18",
                "scaling_factor": 1000000,
                "to_xdx_exchange_rate": 1.0,
            },
            {
                "burn_events_key": "0b000000000000000000000000000000000000000a550c18",
                "cancel_burn_events_key": "0d000000000000000000000000000000000000000a550c18",
                "code": "XDX",
                "exchange_rate_update_events_key": "0e000000000000000000000000000000000000000a550c18",
                "fractional_part": 1000,
                "mint_events_key": "0a000000000000000000000000000000000000000a550c18",
                "preburn_events_key": "0c000000000000000000000000000000000000000a550c18",
                "scaling_factor": 1000000,
                "to_xdx_exchange_rate": 1.0
            }
        ])
    );
    Ok(())
}
#[test]
fn mempool_validation_error_test() -> Result<(), Box<dyn Error>> {
    let factory = JsonRpcTestHelper::get_transaction_factory();

    let mut env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let mut tc_account = JsonRpcTestHelper::get_tc_account(&env);
    let (_, child_1, child_2) =
        env.create_parent_and_two_child_accounts(&factory, 500, &mut tc_account);
    let txn1 = child_1.sign_transaction(
        factory
            .peer_to_peer(Currency::XUS, child_2.address(), 200)
            .sender(child_1.address())
            .sequence_number(child_1.sequence_number())
            .build(),
    );
    let txn2 = child_1.sign_transaction(
        factory
            .peer_to_peer(Currency::XUS, child_2.address(), 300)
            .sender(child_1.address())
            .sequence_number(child_1.sequence_number())
            .build(),
    );

    env.submit(&txn1);
    env.allow_execution_failures(|env| {
        let resp = env.submit(&txn2);
        println!("{:?}", resp);
        assert!(resp.result.is_none())
        // assert_eq!(
        //     resp.error.expect("error").message,
        //     "Server error: Mempool submission error: \"Transaction already in mempool\""
        //         .to_string(),
        // );
    });
    Ok(())
    //env.wait_for_txn(&txn1);
}
#[test]
fn expired_transaction_test() -> Result<(), Box<dyn Error>> {
    let factory = JsonRpcTestHelper::get_transaction_factory();

    let mut env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let mut tc_account = JsonRpcTestHelper::get_tc_account(&env);
    let (_, child_1, child_2) =
        env.create_parent_and_two_child_accounts(&factory, 500, &mut tc_account);

    env.allow_execution_failures(|env| {
        let txn = child_1.sign_transaction(
            factory
                .peer_to_peer(Currency::XUS, child_2.address(), 200)
                .sender(child_1.address())
                .sequence_number(child_1.sequence_number() + 100)
                .expiration_timestamp_secs(0)
                .build(),
        );
        println!("{:?}", txn);
        let resp = env.submit(&txn);
        println!("{:?}", resp);
        assert_eq!(
            resp.error.expect("error").message,
            "Server error: VM Validation error: TRANSACTION_EXPIRED".to_string(),
        );
    });
    Ok(())
}
#[test]
fn parent_vasp_account_role_test() -> Result<(), Box<dyn Error>> {
    let vasp = LocalAccount::generate(&mut OsRng);
    let factory = JsonRpcTestHelper::get_transaction_factory();

    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());

    let mut tc_account = JsonRpcTestHelper::get_tc_account(&env);
    let create_account_txn =
        tc_account.sign_with_transaction_builder(factory.create_parent_vasp_account(
            Currency::XUS,
            0,
            vasp.authentication_key(),
            &format!("No. {} VASP", tc_account.sequence_number()),
            false,
        ));
    env.submit_and_wait(&create_account_txn);

    let address = format!("{:x}", vasp.address());
    let resp = env.send("get_account", json!([address]));
    let result = resp.result.unwrap();
    let human_name = result["role"]["human_name"].as_str().unwrap();

    assert_eq!(
        result,
        json!({
            "address": address,
            "authentication_key": vasp.authentication_key().to_string(),
            "balances": [{"amount": 0_u64, "currency": "XUS"}], // balance changes
            "delegated_key_rotation_capability": false,
            "delegated_withdrawal_capability": false,
            "is_frozen": false,
            "received_events_key": EventKey::new_from_address(&vasp.address(), 2),
            "role": {
                "base_url": "",
                "base_url_rotation_events_key": EventKey::new_from_address(&vasp.address(), 1),
                "compliance_key": "",
                "compliance_key_rotation_events_key": EventKey::new_from_address(&vasp.address(), 0),
                "vasp_domains": [],
                "expiration_time": 18446744073709551615_u64,
                "human_name": human_name,
                "num_children": 0,
                "type": "parent_vasp",
            },
            "sent_events_key": EventKey::new_from_address(&vasp.address(), 3),
            "sequence_number": 0, // no of transaction also changes
            "version": resp.diem_ledger_version,
        }),
    );
    Ok(())
}
#[test]
fn peer_to_peer_error_explination() -> Result<(), Box<dyn Error>> {
    let factory = JsonRpcTestHelper::get_transaction_factory();

    let mut env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let mut tc_account = JsonRpcTestHelper::get_tc_account(&env);
    let (_, mut child_1, child_2) =
        env.create_parent_and_two_child_accounts(&factory, 500, &mut tc_account);

    let txn = child_1.sign_with_transaction_builder(factory.peer_to_peer(
        Currency::XUS,
        child_2.address(),
        2000,
    ));

    env.allow_execution_failures(|env| {
        env.submit_and_wait(&txn);
    });

    let sender = &child_1;

    let resp = env.send(
        "get_account_transaction",
        json!([sender.address(), 0, true]),
    );
    let result = resp.result.unwrap();
    let vm_status = result["vm_status"].clone();
    assert_eq!(
        vm_status,
        json!({
            "abort_code": 1288,
            "explanation": {
                "category": "LIMIT_EXCEEDED",
                "category_description": " A limit on an amount, e.g. a currency, is exceeded. Example: withdrawal of money after account limits window\n is exhausted.",
                "reason": "EINSUFFICIENT_BALANCE",
                "reason_description": " The account does not hold a large enough balance in the specified currency"
            },
            "location": "00000000000000000000000000000001::DiemAccount",
            "type": "move_abort"
        })
    );
    Ok(())
}
#[test]
fn multi_agent_payment_over_dual_attestation_limit_test() -> Result<(), Box<dyn Error>> {
    let factory = JsonRpcTestHelper::get_transaction_factory();
    let chain_id = JsonRpcTestHelper::get_chain_id();
    let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url());
    let mut tc_account = JsonRpcTestHelper::get_tc_account(&env);
    let limit = env.get_metadata()["dual_attestation_limit"]
        .as_u64()
        .unwrap();

    let amount = limit + 1_000_000;
    let sender_initial_balance = amount;
    let receiver_initial_balance = amount;

    let (_parent1, mut sender, _child1_2) =
        env.create_parent_and_two_child_accounts(&factory, sender_initial_balance, &mut tc_account);
    let (_parent2, mut receiver, _child1_2) = env.create_parent_and_two_child_accounts(
        &factory,
        receiver_initial_balance,
        &mut tc_account,
    );

    let transfer_amount = 1;
    let script =
        stdlib::encode_peer_to_peer_by_signers_script_function(xus_tag(), transfer_amount, vec![]);
    let txn = env.create_multi_agent_txn(&mut sender, &[&mut receiver], script, chain_id);

    let txn_view = env.submit_and_wait(&txn);
    let sender_balance = env.get_balance(sender.address(), "XUS");
    let receiver_balance = env.get_balance(receiver.address(), "XUS");

    let events = txn_view["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["data"]["type"], "sentpayment");
    assert_eq!(events[1]["data"]["type"], "receivedpayment");

    for event in events.iter() {
        assert_eq!(
            event["data"]["amount"],
            json!({"amount": transfer_amount, "currency": "XUS"})
        );
        assert_eq!(event["data"]["sender"], format!("{:x}", sender.address()));
        assert_eq!(
            event["data"]["receiver"],
            format!("{:x}", receiver.address())
        );
    }

    assert_eq!(sender_initial_balance - transfer_amount, sender_balance);
    assert_eq!(receiver_initial_balance + transfer_amount, receiver_balance);
    Ok(())
}
