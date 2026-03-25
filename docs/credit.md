  # Credit Contract Documentation

The `Credit` contract implements on-chain credit lines for the Creditra protocol on Stellar Soroban. It manages the full lifecycle of a borrower's credit line — from opening to closing or defaulting — and emits events at each stage.

---

## Data Model

### `CreditLineData`
Stored in persistent storage keyed by the borrower's address.

| Field                | Type     | Description |
|----------------------|----------|-----------|
| `borrower`           | `Address` | The borrower's Stellar address |
| `credit_limit`       | `i128`   | Maximum amount the borrower can draw |
| `utilized_amount`    | `i128`   | Amount currently drawn |
| `interest_rate_bps`  | `u32`    | Annual interest rate in basis points (e.g. 300 = 3%) |
| `risk_score`         | `u32`    | Risk score assigned by the risk engine (0–100) |
| `status`             | `CreditStatus` | Current status of the credit line |
| `last_rate_update_ts`| `u64`    | Ledger timestamp of the last interest-rate change (0 = never updated) |

### `RateChangeConfig`
Stored in instance storage under the `"rate_cfg"` key. Optional — when absent, no rate-change limits are enforced.

| Field                     | Type  | Description |
|---------------------------|-------|-----------|
| `max_rate_change_bps`     | `u32` | Maximum absolute change in `interest_rate_bps` allowed per update |
| `rate_change_min_interval`| `u64` | Minimum elapsed seconds between consecutive rate changes |

### `CreditStatus`

| Variant    | Value | Description |
|------------|-------|-----------|
| `Active`   | 0     | Credit line is open and available |
| `Suspended`| 1     | Credit line is temporarily suspended |
| `Defaulted`| 2     | Borrower has defaulted; draw disabled, repay allowed |
| `Closed`   | 3     | Credit line has been permanently closed |

### Status transitions

| From       | To         | Trigger |
|------------|------------|---------|
| Active     | Defaulted  | Admin calls `default_credit_line` |
| Suspended  | Defaulted  | Admin calls `default_credit_line` |
| Defaulted  | Active     | Admin calls `reinstate_credit_line` |
| Defaulted  | Suspended  | Admin calls `suspend_credit_line` |
| Defaulted  | Closed     | Admin or borrower (when `utilized_amount == 0`) calls `close_credit_line` |

When status is **Defaulted**: `draw_credit` is disabled; `repay_credit` is still allowed.

---

## Methods

### `init(env, admin)`
Initializes the contract with an admin address. Must be called exactly once.

### `set_liquidity_token(env, token_address)`
Sets the Stellar Asset Contract token used for draws and repayments (admin only).

### `set_liquidity_source(env, reserve_address)`
Sets the address that holds liquidity for draws and receives repayments (defaults to contract address).

### `open_credit_line(env, borrower, credit_limit, interest_rate_bps, risk_score)`
Opens a new credit line for a borrower. Called by the backend/risk engine.

Emits: `("credit", "opened")` event.

### `draw_credit(env, borrower, amount)`
Draw funds from an **Active** credit line. Caller must be the borrower.

- Reverts if line is Closed, Suspended, Defaulted, or does not exist.
- Reverts if draw would exceed `credit_limit`.
- Transfers tokens from liquidity source → borrower.

Emits: `("credit", "drawn")` event.

### `repay_credit(env, borrower, amount)`
Repay outstanding drawn funds.

**Allowed on**: Active, Suspended, or Defaulted credit lines.  
**Not allowed on**: Closed credit lines.

- The borrower must have approved the contract to pull tokens via `transfer_from`.
- Effective repayment = `min(amount, utilized_amount)` (over-payments are safe).
- Tokens are transferred **before** state is updated. If the transfer fails, the call reverts with no state change.
- Works even when no liquidity token is configured (state-only update).

Emits: `("credit", "repay")` event with `RepaymentEvent` payload containing the effective amount transferred and new `utilized_amount`.

### `update_risk_parameters(env, borrower, credit_limit, interest_rate_bps, risk_score)`
Update credit limit, interest rate, and risk score (admin only).

When `RateChangeConfig` is set, rate changes are subject to:
- Maximum delta ≤ `max_rate_change_bps`
- Minimum time interval ≥ `rate_change_min_interval`

Emits: `("credit", "risk_updated")` event.

### `set_rate_change_limits(env, max_rate_change_bps, rate_change_min_interval)`
Configure rate-change limits (admin only).

### `get_rate_change_limits(env) -> Option<RateChangeConfig>`
Returns the current rate-change configuration (or `None` if not set).

### `suspend_credit_line(env, borrower)`
Suspend an Active credit line (admin only).

Emits: `("credit", "suspend")` event.

### `close_credit_line(env, borrower, closer)`
Close a credit line.

- Admin can close any time.
- Borrower can close only when `utilized_amount == 0`.

Emits: `("credit", "closed")` event.

### `default_credit_line(env, borrower)`
Mark credit line as Defaulted (admin only).

Emits: `("credit", "default")` event.

### `reinstate_credit_line(env, borrower)`
Reinstate a Defaulted credit line to Active (admin only).

Emits: `("credit", "reinstate")` event.

### `get_credit_line(env, borrower) -> Option<CreditLineData>`
View function — returns credit line data or `None`.

---

## Events

| Topic                      | Event Type | Emitted By                  | Description |
|----------------------------|------------|-----------------------------|-----------|
| `("credit", "opened")`     | `opened`   | `open_credit_line`          | New credit line created |
| `("credit", "drawn")`      | `drawn`    | `draw_credit`               | Funds drawn |
| `("credit", "repay")`      | `repay`    | `repay_credit`              | Repayment made |
| `("credit", "suspend")`    | `suspend`  | `suspend_credit_line`       | Line suspended |
| `("credit", "closed")`     | `closed`   | `close_credit_line`         | Line closed |
| `("credit", "default")`    | `default`  | `default_credit_line`       | Line defaulted |
| `("credit", "reinstate")`  | `reinstate`| `reinstate_credit_line`     | Line reinstated |
| `("credit", "risk_updated")`| `risk_updated` | `update_risk_parameters` | Risk parameters changed |

---

## Access Control

| Function                    | Authorized Caller          |
|-----------------------------|----------------------------|
| `init`                      | Deployer (once)            |
| `set_liquidity_token`       | Admin                      |
| `set_liquidity_source`      | Admin                      |
| `open_credit_line`          | Backend / Risk Engine      |
| `draw_credit`               | Borrower                   |
| `repay_credit`              | Borrower                   |
| `update_risk_parameters`    | Admin                      |
| `set_rate_change_limits`    | Admin                      |
| `suspend_credit_line`       | Admin                      |
| `close_credit_line`         | Admin or Borrower          |
| `default_credit_line`       | Admin                      |
| `reinstate_credit_line`     | Admin                      |
| View functions              | Anyone                     |

All sensitive functions enforce authorization via `require_auth()`.

---

## Storage

| Key                  | Type       | Value                     |
|----------------------|------------|---------------------------|
| `"admin"`            | Instance   | Admin `Address`           |
| `borrower: Address`  | Persistent | `CreditLineData`          |
| `"rate_cfg"`         | Instance   | `RateChangeConfig` (optional) |
| `"reentrancy"`       | Instance   | Reentrancy guard (internal) |

---

## Deployment and CLI Usage

(Examples unchanged — still valid)

---

## Running Tests
```bash
cargo test --workspace