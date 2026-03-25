# Contributing Tests

This guide covers test-only helpers used in `contracts/credit/src/lib.rs` for
draw/repay integration scenarios.

## Mock Liquidity Token Helper

The test module exposes `MockLiquidityToken` (test-only) to reduce repeated
token setup boilerplate.

Use it to:
- deploy a Stellar asset contract for tests;
- mint balances to reserve/borrower addresses;
- set and inspect allowances for repay-path simulations;
- inspect balances after draw/repay calls.

Example usage inside tests:

```rust
let liquidity = MockLiquidityToken::deploy(&env);
client.set_liquidity_token(&liquidity.address());

liquidity.mint(&contract_id, 500);
liquidity.mint(&borrower, 250);
liquidity.approve(&borrower, &contract_id, 200, 1_000);
```

## When To Use It

- Draw scenarios that need explicit reserve funding checks.
- Repay scenarios that need borrower balance/allowance fixtures.
- Any new integration-style test that currently duplicates token setup code.

## Scope Boundary

`MockLiquidityToken` is test-only (`#[cfg(test)]`) and must not be imported
into contract runtime logic.
