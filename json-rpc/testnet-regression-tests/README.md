# Component Name

Testnet Regression Testsuite:- This testsuite executes regression test cases against the testnet.

## Overview

* This testsuite is derived from JSONRPC integeration testcases, but it uses Rust SDK and targets Testnet.
* All stable JSONRPC integeration testcases are ported here.

## Implementation Details

* This testsuite uses environment variables to set treseaury account address and its private key, to avoid security risk.
* These test cases must be run in a single execution thread.
* Dual attestation limit must be set for testnet before executing this testcases.

## Execution
```
TC_ACCT_ADDR="<treasury account address>" TC_ACCT_PRIV_KEY="<treasury account 64 byte private key>" JSON_RPC_URL="<testnet json rpc url>" FAUCET_URL="<mint url>" cargo x test --package testnet-regression-tests -- --test-threads 1 --exact --nocapture
```
Both JSON_RPC_URL & FAUCET_URL environment variables are optional.

## Contributing

Refer to the Diem Project contributing guide [LINK].

## License

Refer to the Diem Project License [LINK].
