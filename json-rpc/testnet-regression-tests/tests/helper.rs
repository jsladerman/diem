// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0
use diem_json_rpc_types::response::JsonRpcResponse;
use diem_sdk::{
    client::BlockingClient,
    crypto::{ed25519::Ed25519PrivateKey, hash::CryptoHash},
    transaction_builder::{Currency, TransactionFactory},
    types::{
        account_address::AccountAddress,
        account_config::XUS_NAME,
        chain_id::{ChainId, NamedChain},
        transaction::{SignedTransaction, Transaction},
        LocalAccount,
    },
};

use anyhow::{format_err, Result};
use rand_core::OsRng;
use reqwest::{StatusCode, Url};
use serde_json::{json, Value};
use std::{convert::TryFrom, env, env::VarError};

pub struct FaucetClient {
    url: String,
    json_rpc_client: BlockingClient,
}

impl FaucetClient {
    pub fn new(url: String, json_rpc_url: String) -> Self {
        Self {
            url,
            json_rpc_client: BlockingClient::new(json_rpc_url),
        }
    }
    pub fn fund_with_auth_key(
        &self,
        auth_key: &str,
        currency_code: &str,
        amount: u64,
    ) -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let mut url = Url::parse(&self.url).unwrap();
        //println!("URL:{}",url);
        let query = format!(
            "auth_key={}&currency_code={}&amount={}&return_txns=true",
            auth_key, currency_code, amount
        );
        url.set_query(Some(&query));
        // Faucet returns the transaction that creates the account and needs to be waited on before
        // returning.
        let response = client.post(url).send().unwrap();

        match response.status() {
            // TODO: add retry logic for failed transaction
            StatusCode::OK => println!("success! {}", amount,),
            s => println!("Received response status: {:?}", s),
        };
        let body = response.text().unwrap();

        let txns: Vec<SignedTransaction> =
            bcs::from_bytes(&hex::decode(body).expect("hex encoded response body"))
                .expect("valid bcs vec");
        assert!(txns.len() <= 2);

        /*  self.json_rpc_client
        .wait_for_signed_transaction(&txns[0], None, None)
         .map_err(Error::unknown)?;
         */
        Ok(())
    }
}

pub struct JsonRpcTestHelper {
    url: String,
    client: reqwest::blocking::Client,
    allow_execution_failures: bool,
}

impl JsonRpcTestHelper {
    pub fn new(url: String) -> Self {
        Self {
            url,
            client: reqwest::blocking::Client::new(),
            allow_execution_failures: false,
        }
    }
    pub fn get_chain_id() -> ChainId {
        ChainId::new(NamedChain::TESTNET.id())
    }
    pub fn get_transaction_factory() -> TransactionFactory {
        TransactionFactory::new(JsonRpcTestHelper::get_chain_id()).with_diem_version(0)
    }
    pub fn get_tc_account_address() -> String {
        let addr: Result<String, VarError> = env::var("TC_ACCT_ADDR");
        return addr
            .unwrap_or("no tc account address".to_string())
            .to_string();
    }
    pub fn get_tc_account_private_key() -> String {
        let key = env::var("TC_ACCT_PRIV_KEY");
        return key
            .unwrap_or("no tc account private key".to_string())
            .to_string();
    }
    pub fn get_json_rpc_url() -> String {
        return env::var("JSON_RPC_URL").unwrap_or("https://testnet.diem.com/v1".to_string());
    }
    pub fn get_mint_url() -> String {
        return env::var("FAUCET_URL").unwrap_or("https://testnet.diem.com/mint".to_string());
    }
    pub fn get_metadata(&self) -> Value {
        self.send("get_metadata", json!([])).result.unwrap()
    }

    pub fn get_balance(&self, address: AccountAddress, currency: &str) -> u64 {
        let resp = self.send("get_account", json!([address]));
        let account = resp.result.unwrap();
        let balances = account["balances"].as_array().unwrap();
        for balance in balances.iter() {
            if balance["currency"].as_str().unwrap() == currency {
                return balance["amount"].as_u64().unwrap();
            }
        }
        0
    }

    pub fn allow_execution_failures<F, T>(&mut self, mut f: F) -> T
    where
        F: FnMut(&mut JsonRpcTestHelper) -> T,
    {
        self.allow_execution_failures = true;
        let ret = f(self);
        self.allow_execution_failures = false;
        ret
    }

    pub fn send(&self, method: &'static str, params: Value) -> JsonRpcResponse {
        let request = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
        let resp = self
            .client
            .post(self.url.as_str())
            .json(&request)
            .send()
            .expect("request success");
        assert_eq!(resp.status(), 200);
        let headers = resp.headers().clone();
        let json: serde_json::Value = resp.json().unwrap();
        if !self.allow_execution_failures {
            assert_eq!(json.get("error"), None);
        }
        let rpc_resp: JsonRpcResponse =
            serde_json::from_value(json).expect("should be valid JsonRpcResponse");

        assert_eq!(
            headers.get("X-Diem-Chain-Id").unwrap().to_str().unwrap(),
            rpc_resp.diem_chain_id.to_string()
        );
        assert_eq!(
            headers
                .get("X-Diem-Ledger-Version")
                .unwrap()
                .to_str()
                .unwrap(),
            rpc_resp.diem_ledger_version.to_string()
        );
        assert_eq!(
            headers
                .get("X-Diem-Ledger-TimestampUsec")
                .unwrap()
                .to_str()
                .unwrap(),
            rpc_resp.diem_ledger_timestampusec.to_string()
        );
        rpc_resp
    }

    pub fn send_request(&self, request: Value) -> Value {
        let resp = self
            .client
            .post(self.url.as_str())
            .json(&request)
            .send()
            .expect("request success");
        assert_eq!(resp.status(), 200);

        resp.json().unwrap()
    }

    pub fn submit_and_wait(&self, txn: &SignedTransaction) -> Value {
        self.submit(txn);
        self.wait_for_txn(txn)
    }

    pub fn submit(&self, txn: &SignedTransaction) -> JsonRpcResponse {
        let txn_hex = hex::encode(bcs::to_bytes(txn).expect("bcs txn failed"));
        self.send("submit", json!([txn_hex]))
    }

    pub fn wait_for_txn(&self, txn: &SignedTransaction) -> Value {
        let txn_hash = Transaction::UserTransaction(txn.clone()).hash().to_hex();
        for _i in 0..60 {
            let resp = self.get_account_transaction(&txn.sender(), txn.sequence_number(), true);
            if let Some(result) = resp.result {
                if result.is_object() {
                    if !self.allow_execution_failures {
                        assert_eq!(result["vm_status"]["type"], "executed", "{:#}", result);
                    }
                    assert_eq!(result["hash"], txn_hash);
                    // assert_eq!(result["hash"], txn_hash, "{:#}", result);
                    return result;
                }
            }
            ::std::thread::sleep(::std::time::Duration::from_millis(500));
        }
        panic!("transaction not executed?");
    }

    pub fn get_account_transaction(
        &self,
        address: &AccountAddress,
        seq_num: u64,
        include_events: bool,
    ) -> JsonRpcResponse {
        self.send(
            "get_account_transaction",
            json!([hex::encode(address), seq_num, include_events]),
        )
    }

    pub fn get_account_sequence(&self, address: AccountAddress) -> Result<u64> {
        let resp = self.send("get_account", json!([address]));
        if let Some(result) = resp.result {
            if result.is_object() {
                return Ok(result["sequence_number"].as_u64().unwrap());
            }
        }
        Err(format_err!("account not found: {}", address))
    }

    pub fn get_tc_account(env: &JsonRpcTestHelper) -> LocalAccount {
        let treasury_account_address =
            AccountAddress::from_hex(JsonRpcTestHelper::get_tc_account_address()).unwrap();
        let encoded_str = JsonRpcTestHelper::get_tc_account_private_key();

        let decoded_key_bytes = base64::decode(encoded_str).unwrap();
        let private_key_bytes = &decoded_key_bytes[0..32];
        let private_key = Ed25519PrivateKey::try_from(private_key_bytes).unwrap();
        let address1 = format!("{:x}", treasury_account_address);
        let resp = env.send("get_account", json!([address1]));
        let result = resp.result.unwrap();
        let sequence_number = &result["sequence_number"];
        println!("{}", sequence_number);
        let tc_account = LocalAccount::new(
            treasury_account_address,
            private_key,
            sequence_number.as_u64().unwrap(),
        );
        tc_account
    }
    pub fn create_parent_vasp_account(
        &self,
        factory: &TransactionFactory,
        amount: u64,
        tc_account: &mut LocalAccount,
    ) -> LocalAccount {
        let faucet = FaucetClient::new(
            JsonRpcTestHelper::get_mint_url().to_owned(),
            JsonRpcTestHelper::get_json_rpc_url().to_owned(),
        );
        let env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url().to_owned());

        let vasp = LocalAccount::generate(&mut OsRng);

        let create_account_txn =
            tc_account.sign_with_transaction_builder(factory.create_parent_vasp_account(
                Currency::XUS,
                0,
                vasp.authentication_key(),
                &format!("No. {} VASP", tc_account.sequence_number()),
                false,
            ));
        env.submit_and_wait(&create_account_txn);
        println!("{:?}", vasp.address());
        let vasp_amount = amount;
        faucet
            .fund_with_auth_key(
                vasp.authentication_key().to_string().as_str(),
                Currency::XUS.as_str(),
                vasp_amount,
            )
            .unwrap();

        return vasp;
    }

    pub fn create_parent_and_one_child_account(
        &self,
        factory: &TransactionFactory,
        amount: u64,
        tc_account: &mut LocalAccount,
    ) -> (LocalAccount, LocalAccount) {
        let faucet = FaucetClient::new(
            JsonRpcTestHelper::get_mint_url().to_owned(),
            JsonRpcTestHelper::get_json_rpc_url().to_owned(),
        );
        let mut env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url().to_owned());

        let mut vasp = LocalAccount::generate(&mut OsRng);
        let child_1 = LocalAccount::generate(&mut OsRng);

        let create_account_txn =
            tc_account.sign_with_transaction_builder(factory.create_parent_vasp_account(
                Currency::XUS,
                0,
                vasp.authentication_key(),
                &format!("No. {} VASP", tc_account.sequence_number()),
                false,
            ));
        env.submit_and_wait(&create_account_txn);
        env.submit_and_wait(&vasp.sign_with_transaction_builder(
            factory.create_child_vasp_account(
                Currency::XUS,
                child_1.authentication_key(),
                false,
                0,
            ),
        ));
        println!("{:?}", vasp.address());
        println!("{:?}", child_1.address());
        let vasp_amount = amount;
        let ch1_amount = amount;
        faucet
            .fund_with_auth_key(
                vasp.authentication_key().to_string().as_str(),
                Currency::XUS.as_str(),
                vasp_amount,
            )
            .unwrap();
        faucet
            .fund_with_auth_key(
                child_1.authentication_key().to_string().as_str(),
                Currency::XUS.as_str(),
                ch1_amount,
            )
            .unwrap();

        return (vasp, child_1);
    }

    pub fn create_parent_and_two_child_accounts(
        &self,
        factory: &TransactionFactory,
        amount: u64,
        tc_account: &mut LocalAccount,
    ) -> (LocalAccount, LocalAccount, LocalAccount) {
        let faucet = FaucetClient::new(
            JsonRpcTestHelper::get_mint_url().to_owned(),
            JsonRpcTestHelper::get_json_rpc_url().to_owned(),
        );
        let mut env = JsonRpcTestHelper::new(JsonRpcTestHelper::get_json_rpc_url().to_owned());

        let mut vasp = LocalAccount::generate(&mut OsRng);
        let child_1 = LocalAccount::generate(&mut OsRng);
        let child_2 = LocalAccount::generate(&mut OsRng);

        let create_account_txn =
            tc_account.sign_with_transaction_builder(factory.create_parent_vasp_account(
                Currency::XUS,
                0,
                vasp.authentication_key(),
                &format!("No. {} VASP", tc_account.sequence_number()),
                false,
            ));
        env.submit_and_wait(&create_account_txn);
        env.submit_and_wait(&vasp.sign_with_transaction_builder(
            factory.create_child_vasp_account(
                Currency::XUS,
                child_1.authentication_key(),
                false,
                0,
            ),
        ));
        env.submit_and_wait(&vasp.sign_with_transaction_builder(
            factory.create_child_vasp_account(
                Currency::XUS,
                child_2.authentication_key(),
                false,
                0,
            ),
        ));
        println!("{:?}", vasp.address());
        println!("{:?}", child_1.address());
        println!("{:?}", child_2.address());
        let vasp_amount = amount;
        let ch1_amount = amount;
        let ch2_amount = amount;
        faucet
            .fund_with_auth_key(
                vasp.authentication_key().to_string().as_str(),
                Currency::XUS.as_str(),
                vasp_amount,
            )
            .unwrap();
        faucet
            .fund_with_auth_key(
                child_1.authentication_key().to_string().as_str(),
                Currency::XUS.as_str(),
                ch1_amount,
            )
            .unwrap();
        faucet
            .fund_with_auth_key(
                child_2.authentication_key().to_string().as_str(),
                Currency::XUS.as_str(),
                ch2_amount,
            )
            .unwrap();

        return (vasp, child_1, child_2);
    }
    pub fn update_testnet_attestation_limit(
        &self,
        mut tc_account: LocalAccount,
        factory: &TransactionFactory,
        env: &JsonRpcTestHelper,
    ) {
        let update_attestation_limit = tc_account
            .sign_with_transaction_builder(factory.update_attestation_limit(0, 1_000_000_000));
        env.submit_and_wait(&update_attestation_limit);
    }

    pub fn create_multi_agent_txn(
        &self,
        sender: &mut LocalAccount,
        secondary_signers: &[&mut LocalAccount],
        payload: diem_sdk::types::transaction::TransactionPayload,
        chainId: ChainId,
    ) -> SignedTransaction {
        let seq_onchain = self
            .get_account_sequence(sender.address())
            .expect("account should exist onchain for create transaction");
        let seq = sender.sequence_number();
        assert_eq!(seq, seq_onchain);
        *sender.sequence_number_mut() += 1;
        let raw_txn = diem_sdk::types::transaction::helpers::create_unsigned_txn(
            payload,
            sender.address(),
            seq,
            1_000_000,
            0,
            XUS_NAME.to_owned(),
            60,
            chainId,
        );
        raw_txn
            .sign_multi_agent(
                sender.private_key(),
                secondary_signers
                    .iter()
                    .map(|signer| signer.address())
                    .collect(),
                secondary_signers
                    .iter()
                    .map(|signer| signer.private_key())
                    .collect(),
            )
            .unwrap()
            .into_inner()
    }
}
