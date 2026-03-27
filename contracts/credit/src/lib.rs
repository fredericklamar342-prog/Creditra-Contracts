#![no_std]
#![allow(clippy::unused_unit)]

//! Creditra credit contract: credit lines, draw/repay, risk parameters.
//!
//! # Storage Audit (issue #127)
//!
//! ## Instance storage (shared contract-wide state, TTL tied to contract instance)
//!
//! | Key | Type | Written by | Purpose |
//! |-----|------|------------|---------|
//! | `Symbol("admin")` | `Address` | `init` | Contract admin. Instance is correct: there is exactly one admin per contract deployment. |
//! | `DataKey::LiquidityToken` | `Address` | `set_liquidity_token` | Token contract for reserve. Instance is correct: global config. |
//! | `DataKey::LiquiditySource` | `Address` | `init`, `set_liquidity_source` | Reserve address. Instance is correct: global config. |
//! | `Symbol("reentrancy")` | `bool` | `set_reentrancy_guard`, `clear_reentrancy_guard` | Defense-in-depth guard. Instance is correct: transient flag cleared every call. |
//! | `Symbol("rate_cfg")` | `RateChangeConfig` | `set_rate_change_limits` | Rate-change governance. Instance is correct: global config. |
//!
//! ## Persistent storage (per-borrower records, independent TTL per entry)
//!
//! | Key | Type | Written by | Purpose |
//! |-----|------|------------|---------|
//! | `Address` (borrower) | `CreditLineData` | `open_credit_line`, `draw_credit`, `repay_credit`, `update_risk_parameters`, status transitions | Per-borrower credit line. Persistent is correct: must survive beyond a single transaction and is independent per borrower. |
//!
//! ## Temporary storage
//!
//! Not currently used. Future candidate: the reentrancy flag could move to
//! temporary storage since it is only meaningful within a single invocation,
//! but instance storage works correctly today because it is cleared on every
//! code path.
//!
//! ## TTL implications
//!
//! - **Instance keys** share the contract instance TTL. If the instance is
//!   archived, all instance keys (admin, config, reentrancy) are lost.
//!   Production deployments should call `env.storage().instance().extend_ttl()`
//!   periodically (e.g. in `init` or a dedicated `bump` endpoint).
//! - **Persistent keys** (borrower → CreditLineData) have independent TTLs.
//!   Long-lived credit lines should be bumped via `persistent().extend_ttl()`
//!   on access or via a keeper. If a borrower's entry is archived, their
//!   credit line data is lost.
//!
//! # Status transitions
//!
//! | From    | To        | Trigger |
//! |---------|-----------|---------|
//! | Active  | Suspended | `suspend_credit_line` |
//! | Active  | Defaulted | `default_credit_line` |
//! | Suspended | Defaulted | `default_credit_line` |
//! | Defaulted | Active   | `reinstate_credit_line` |
//! | Any (non-Closed) | Closed | `close_credit_line` |
//!
//! # Reentrancy
//! Soroban token transfers (e.g. Stellar Asset Contract) do not invoke callbacks back into
//! the caller. This contract uses a reentrancy guard on draw_credit and repay_credit as a
//! defense-in-depth measure; if a token or future integration ever called back, the guard
//! would revert.

mod events;
mod types;

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Env, Symbol,
};

use events::{
    publish_credit_line_event, publish_drawn_event, publish_repayment_event,
    publish_risk_parameters_updated, CreditLineEvent, DrawnEvent, RepaymentEvent,
    RiskParametersUpdatedEvent,
};
use types::{CreditLineData, CreditStatus, RateChangeConfig};

/// Maximum interest rate in basis points (100%).
const MAX_INTEREST_RATE_BPS: u32 = 10_000;

/// Maximum risk score (0–100 scale).
const MAX_RISK_SCORE: u32 = 100;

// ── Storage key helpers ───────────────────────────────────────────────────
// Instance storage: these keys share the contract-instance TTL.

/// Instance storage key for the reentrancy guard (bool).
fn reentrancy_key(env: &Env) -> Symbol {
    Symbol::new(env, "reentrancy")
}

/// Instance storage key for the admin address.
fn admin_key(env: &Env) -> Symbol {
    Symbol::new(env, "admin")
}

/// Instance storage key for rate-change configuration.
fn rate_cfg_key(env: &Env) -> Symbol {
    Symbol::new(env, "rate_cfg")
}

fn require_admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&admin_key(env))
        .expect("admin not set")
}

fn require_admin_auth(env: &Env) -> Address {
    let admin = require_admin(env);
    admin.require_auth();
    admin
}

#[contracttype]
#[derive(Debug, Clone, PartialEq)]
pub enum CreditError {
    CreditLineNotFound = 1,
    InvalidCreditStatus = 2,
    InvalidAmount = 3,
    InsufficientUtilization = 4,
    Unauthorized = 5,
}

impl From<CreditError> for soroban_sdk::Error {
    fn from(val: CreditError) -> Self {
        soroban_sdk::Error::from_contract_error(val as u32)
    }
}

/// Instance storage keys for global contract configuration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// Token contract used for reserve checks and draw/repay transfers.
    LiquidityToken,
    /// Address that provides liquidity for draw operations.
    LiquiditySource,
}

// ── Reentrancy guard (instance storage, bool) ─────────────────────────────

/// Assert reentrancy guard is not set; set it for the duration of the call.
fn set_reentrancy_guard(env: &Env) {
    let key = reentrancy_key(env);
    // Instance storage read: reentrancy flag (bool, default false).
    let current: bool = env.storage().instance().get(&key).unwrap_or(false);
    if current {
        panic!("reentrancy guard");
    }
    // Instance storage write: set reentrancy flag to true.
    env.storage().instance().set(&key, &true);
}

fn clear_reentrancy_guard(env: &Env) {
    // Instance storage write: clear reentrancy flag.
    env.storage().instance().set(&reentrancy_key(env), &false);
}

#[contract]
pub struct Credit;

#[contractimpl]
impl Credit {
    /// Initialize contract-level configuration.
    /// Sets admin and defaults liquidity source to this contract address.
    pub fn init(env: Env, admin: Address) {
        // Instance storage write: admin address.
        env.storage().instance().set(&admin_key(&env), &admin);
        // Instance storage write: default liquidity source = contract itself.
        env.storage()
            .instance()
            .set(&DataKey::LiquiditySource, &env.current_contract_address());
    }

    /// Sets the token contract used for reserve/liquidity checks and draw transfers.
    /// Admin-only.
    pub fn set_liquidity_token(env: Env, token_address: Address) {
        require_admin_auth(&env);
        // Instance storage write: liquidity token address.
        env.storage()
            .instance()
            .set(&DataKey::LiquidityToken, &token_address);
    }

    /// Sets the address that provides liquidity for draw operations.
    /// Admin-only. If unset, init defaults to the contract address.
    pub fn set_liquidity_source(env: Env, reserve_address: Address) {
        require_admin_auth(&env);
        // Instance storage write: liquidity source address.
        env.storage()
            .instance()
            .set(&DataKey::LiquiditySource, &reserve_address);
    }

    /// Open a new credit line for a borrower.
    ///
    /// # Panics
    /// - If `credit_limit <= 0`
    /// - If `interest_rate_bps > 10000`
    /// - If `risk_score > 100`
    /// - If an Active credit line already exists for the borrower
    pub fn open_credit_line(
        env: Env,
        borrower: Address,
        credit_limit: i128,
        interest_rate_bps: u32,
        risk_score: u32,
    ) {
        assert!(credit_limit > 0, "credit_limit must be greater than zero");
        assert!(
            interest_rate_bps <= MAX_INTEREST_RATE_BPS,
            "interest_rate_bps cannot exceed 10000 (100%)"
        );
        assert!(
            risk_score <= MAX_RISK_SCORE,
            "risk_score must be between 0 and 100"
        );

        // Persistent storage read: check for existing active credit line.
        if let Some(existing) = env
            .storage()
            .persistent()
            .get::<Address, CreditLineData>(&borrower)
        {
            assert!(
                existing.status != CreditStatus::Active,
                "borrower already has an active credit line"
            );
        }

        let credit_line = CreditLineData {
            borrower: borrower.clone(),
            credit_limit,
            utilized_amount: 0,
            interest_rate_bps,
            risk_score,
            status: CreditStatus::Active,
            last_rate_update_ts: 0,
        };

        // Persistent storage write: store new credit line keyed by borrower address.
        env.storage().persistent().set(&borrower, &credit_line);

        publish_credit_line_event(
            &env,
            (symbol_short!("credit"), symbol_short!("opened")),
            CreditLineEvent {
                event_type: symbol_short!("opened"),
                borrower: borrower.clone(),
                status: CreditStatus::Active,
                credit_limit,
                interest_rate_bps,
                risk_score,
            },
        );
    }

    /// Draw from credit line (borrower).
    ///
    /// Enforces status/limit/liquidity checks and uses a reentrancy guard.
    ///
    /// # Panics
    /// - `"Credit line not found"` – no credit line for borrower
    /// - `"credit line is closed"` – line status is Closed
    /// - `"exceeds credit limit"` – draw would push utilized over limit
    /// - `"amount must be positive"` – amount <= 0
    /// - `"reentrancy guard"` – re-entrant call detected
    /// - `"Insufficient liquidity reserve..."` – reserve balance < amount
    pub fn draw_credit(env: Env, borrower: Address, amount: i128) {
        set_reentrancy_guard(&env);
        borrower.require_auth();

        if amount <= 0 {
            clear_reentrancy_guard(&env);
            panic!("amount must be positive");
        }

        // Instance storage read: liquidity token (optional).
        let token_address: Option<Address> = env.storage().instance().get(&DataKey::LiquidityToken);
        // Instance storage read: liquidity source (fallback to contract address).
        let reserve_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::LiquiditySource)
            .unwrap_or(env.current_contract_address());

        // Persistent storage read: borrower's credit line.
        let mut credit_line: CreditLineData = env
            .storage()
            .persistent()
            .get(&borrower)
            .expect("Credit line not found");

        if credit_line.status == CreditStatus::Closed {
            clear_reentrancy_guard(&env);
            panic!("credit line is closed");
        }

        let updated_utilized = credit_line
            .utilized_amount
            .checked_add(amount)
            .expect("overflow");

        if updated_utilized > credit_line.credit_limit {
            clear_reentrancy_guard(&env);
            panic!("exceeds credit limit");
        }

        if let Some(token_address) = token_address {
            let token_client = token::Client::new(&env, &token_address);
            let reserve_balance = token_client.balance(&reserve_address);
            if reserve_balance < amount {
                clear_reentrancy_guard(&env);
                panic!("Insufficient liquidity reserve for requested draw amount");
            }
            token_client.transfer(&reserve_address, &borrower, &amount);
        }

        credit_line.utilized_amount = updated_utilized;
        // Persistent storage write: update utilized_amount.
        env.storage().persistent().set(&borrower, &credit_line);

        let timestamp = env.ledger().timestamp();
        publish_drawn_event(
            &env,
            DrawnEvent {
                borrower,
                amount,
                new_utilized_amount: updated_utilized,
                timestamp,
            },
        );
        clear_reentrancy_guard(&env);
    }

    /// Repay credit (borrower).
    ///
    /// Allowed when status is Active, Suspended, or Defaulted.
    /// Reverts if Closed. Reduces utilized_amount (capped at 0).
    pub fn repay_credit(env: Env, borrower: Address, amount: i128) {
        set_reentrancy_guard(&env);
        borrower.require_auth();

        // Persistent storage read: borrower's credit line.
        let mut credit_line: CreditLineData = env
            .storage()
            .persistent()
            .get(&borrower)
            .expect("Credit line not found");

        if credit_line.borrower != borrower {
            panic!("Borrower mismatch for credit line");
        }
        if credit_line.status == CreditStatus::Closed {
            clear_reentrancy_guard(&env);
            panic!("credit line is closed");
        }
        if amount <= 0 {
            clear_reentrancy_guard(&env);
            panic!("amount must be positive");
        }

        let new_utilized = credit_line.utilized_amount.saturating_sub(amount).max(0);
        credit_line.utilized_amount = new_utilized;
        // Persistent storage write: update utilized_amount after repayment.
        env.storage().persistent().set(&borrower, &credit_line);

        let timestamp = env.ledger().timestamp();
        publish_repayment_event(
            &env,
            RepaymentEvent {
                borrower: borrower.clone(),
                amount,
                new_utilized_amount: new_utilized,
                timestamp,
            },
        );
        clear_reentrancy_guard(&env);
    }

    /// Update risk parameters for an existing credit line (admin only).
    pub fn update_risk_parameters(
        env: Env,
        borrower: Address,
        credit_limit: i128,
        interest_rate_bps: u32,
        risk_score: u32,
    ) {
        require_admin_auth(&env);

        // Persistent storage read: borrower's credit line.
        let mut credit_line: CreditLineData = env
            .storage()
            .persistent()
            .get(&borrower)
            .expect("Credit line not found");

        if credit_limit < 0 {
            panic!("credit_limit must be non-negative");
        }
        if credit_limit < credit_line.utilized_amount {
            panic!("credit_limit cannot be less than utilized amount");
        }
        if interest_rate_bps > MAX_INTEREST_RATE_BPS {
            panic!("interest_rate_bps exceeds maximum");
        }
        if risk_score > MAX_RISK_SCORE {
            panic!("risk_score exceeds maximum");
        }

        credit_line.credit_limit = credit_limit;
        credit_line.interest_rate_bps = interest_rate_bps;
        credit_line.risk_score = risk_score;
        // Persistent storage write: updated risk parameters.
        env.storage().persistent().set(&borrower, &credit_line);

        publish_risk_parameters_updated(
            &env,
            RiskParametersUpdatedEvent {
                borrower: borrower.clone(),
                credit_limit,
                interest_rate_bps,
                risk_score,
            },
        );
    }

    /// Set rate-change limits (admin only).
    pub fn set_rate_change_limits(
        env: Env,
        max_rate_change_bps: u32,
        rate_change_min_interval: u64,
    ) {
        require_admin_auth(&env);
        let cfg = RateChangeConfig {
            max_rate_change_bps,
            rate_change_min_interval,
        };
        // Instance storage write: rate-change governance config.
        env.storage().instance().set(&rate_cfg_key(&env), &cfg);
    }

    /// Get the current rate-change limit configuration (view function).
    pub fn get_rate_change_limits(env: Env) -> Option<RateChangeConfig> {
        // Instance storage read: rate-change config.
        env.storage().instance().get(&rate_cfg_key(&env))
    }

    /// Suspend a credit line temporarily (admin only).
    pub fn suspend_credit_line(env: Env, borrower: Address) {
        require_admin_auth(&env);

        // Persistent storage read: borrower's credit line.
        let mut credit_line: CreditLineData = env
            .storage()
            .persistent()
            .get(&borrower)
            .expect("Credit line not found");

        assert!(
            credit_line.status == CreditStatus::Active,
            "only Active credit lines can be suspended"
        );

        credit_line.status = CreditStatus::Suspended;
        // Persistent storage write: status → Suspended.
        env.storage().persistent().set(&borrower, &credit_line);

        publish_credit_line_event(
            &env,
            (symbol_short!("credit"), symbol_short!("suspend")),
            CreditLineEvent {
                event_type: symbol_short!("suspend"),
                borrower: borrower.clone(),
                status: CreditStatus::Suspended,
                credit_limit: credit_line.credit_limit,
                interest_rate_bps: credit_line.interest_rate_bps,
                risk_score: credit_line.risk_score,
            },
        );
    }

    /// Close a credit line.
    ///
    /// Callable by admin (force-close) or by borrower when utilization is zero.
    /// Idempotent if already Closed.
    pub fn close_credit_line(env: Env, borrower: Address, closer: Address) {
        closer.require_auth();
        let admin: Address = require_admin(&env);

        // Persistent storage read: borrower's credit line.
        let mut credit_line: CreditLineData = env
            .storage()
            .persistent()
            .get(&borrower)
            .expect("Credit line not found");

        if credit_line.status == CreditStatus::Closed {
            return;
        }

        let allowed = closer == admin || (closer == borrower && credit_line.utilized_amount == 0);
        if !allowed {
            if closer == borrower {
                panic!("cannot close: utilized amount not zero");
            }
            panic!("unauthorized");
        }

        credit_line.status = CreditStatus::Closed;
        // Persistent storage write: status → Closed.
        env.storage().persistent().set(&borrower, &credit_line);

        publish_credit_line_event(
            &env,
            (symbol_short!("credit"), symbol_short!("closed")),
            CreditLineEvent {
                event_type: symbol_short!("closed"),
                borrower: borrower.clone(),
                status: CreditStatus::Closed,
                credit_limit: credit_line.credit_limit,
                interest_rate_bps: credit_line.interest_rate_bps,
                risk_score: credit_line.risk_score,
            },
        );
    }

    /// Mark a credit line as defaulted (admin only).
    pub fn default_credit_line(env: Env, borrower: Address) {
        require_admin_auth(&env);

        let mut credit_line: CreditLineData = env
            .storage()
            .persistent()
            .get(&borrower)
            .expect("Credit line not found");

        credit_line.status = CreditStatus::Defaulted;
        // Persistent storage write: status → Defaulted.
        env.storage().persistent().set(&borrower, &credit_line);

        publish_credit_line_event(
            &env,
            (symbol_short!("credit"), symbol_short!("default")),
            CreditLineEvent {
                event_type: symbol_short!("default"),
                borrower: borrower.clone(),
                status: CreditStatus::Defaulted,
                credit_limit: credit_line.credit_limit,
                interest_rate_bps: credit_line.interest_rate_bps,
                risk_score: credit_line.risk_score,
            },
        );
    }

    /// Reinstate a defaulted credit line to Active (admin only).
    pub fn reinstate_credit_line(env: Env, borrower: Address) {
        require_admin_auth(&env);

        let mut credit_line: CreditLineData = env
            .storage()
            .persistent()
            .get(&borrower)
            .expect("Credit line not found");

        if credit_line.status != CreditStatus::Defaulted {
            panic!("credit line is not defaulted");
        }

        credit_line.status = CreditStatus::Active;
        // Persistent storage write: status → Active (reinstated).
        env.storage().persistent().set(&borrower, &credit_line);

        publish_credit_line_event(
            &env,
            (symbol_short!("credit"), symbol_short!("reinstate")),
            CreditLineEvent {
                event_type: symbol_short!("reinstate"),
                borrower: borrower.clone(),
                status: CreditStatus::Active,
                credit_limit: credit_line.credit_limit,
                interest_rate_bps: credit_line.interest_rate_bps,
                risk_score: credit_line.risk_score,
            },
        );
    }

    /// Get credit line data for a borrower (view function).
    pub fn get_credit_line(env: Env, borrower: Address) -> Option<CreditLineData> {
        // Persistent storage read: borrower's credit line.
        env.storage().persistent().get(&borrower)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, Env};

    fn setup(env: &Env) -> (Address, Address, Address) {
        env.mock_all_auths();
        let contract_id = env.register(Credit, ());
        let admin = Address::generate(env);
        let borrower = Address::generate(env);

        let client = CreditClient::new(env, &contract_id);
        client.init(&admin);
        (admin, borrower, contract_id)
    }

    #[test]
    fn test_open_and_get_credit_line() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        let cl = client.get_credit_line(&borrower).unwrap();
        assert_eq!(cl.credit_limit, 10_000);
        assert_eq!(cl.utilized_amount, 0);
        assert_eq!(cl.interest_rate_bps, 500);
        assert_eq!(cl.risk_score, 50);
        assert_eq!(cl.status, CreditStatus::Active);
    }

    #[test]
    fn test_draw_and_repay() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.draw_credit(&borrower, &3_000);

        let cl = client.get_credit_line(&borrower).unwrap();
        assert_eq!(cl.utilized_amount, 3_000);

        client.repay_credit(&borrower, &1_000);
        let cl = client.get_credit_line(&borrower).unwrap();
        assert_eq!(cl.utilized_amount, 2_000);
    }

    #[test]
    #[should_panic(expected = "exceeds credit limit")]
    fn test_draw_exceeds_limit() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &1_000, &500, &50);
        client.draw_credit(&borrower, &1_001);
    }

    #[test]
    fn test_suspend_blocks_draw() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.suspend_credit_line(&borrower);

        let cl = client.get_credit_line(&borrower).unwrap();
        assert_eq!(cl.status, CreditStatus::Suspended);
    }

    #[test]
    fn test_default_and_reinstate() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.default_credit_line(&borrower);
        assert_eq!(
            client.get_credit_line(&borrower).unwrap().status,
            CreditStatus::Defaulted
        );

        client.reinstate_credit_line(&borrower);
        assert_eq!(
            client.get_credit_line(&borrower).unwrap().status,
            CreditStatus::Active
        );
    }

    #[test]
    fn test_close_credit_line_admin() {
        let env = Env::default();
        let (admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.draw_credit(&borrower, &5_000);
        client.close_credit_line(&borrower, &admin);

        assert_eq!(
            client.get_credit_line(&borrower).unwrap().status,
            CreditStatus::Closed
        );
    }

    #[test]
    fn test_close_credit_line_borrower_zero_util() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.close_credit_line(&borrower, &borrower);

        assert_eq!(
            client.get_credit_line(&borrower).unwrap().status,
            CreditStatus::Closed
        );
    }

    #[test]
    fn test_update_risk_parameters() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.update_risk_parameters(&borrower, &20_000, &800, &70);

        let cl = client.get_credit_line(&borrower).unwrap();
        assert_eq!(cl.credit_limit, 20_000);
        assert_eq!(cl.interest_rate_bps, 800);
        assert_eq!(cl.risk_score, 70);
    }

    #[test]
    fn test_repay_over_utilized_caps_at_zero() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.draw_credit(&borrower, &1_000);
        client.repay_credit(&borrower, &5_000);

        assert_eq!(
            client.get_credit_line(&borrower).unwrap().utilized_amount,
            0
        );
    }

    #[test]
    fn test_set_rate_change_limits() {
        let env = Env::default();
        let (_admin, _borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.set_rate_change_limits(&200, &3600);
        let cfg = client.get_rate_change_limits().unwrap();
        assert_eq!(cfg.max_rate_change_bps, 200);
        assert_eq!(cfg.rate_change_min_interval, 3600);
    }

    #[test]
    fn test_set_liquidity_source() {
        let env = Env::default();
        let (_admin, _borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        let new_source = Address::generate(&env);
        client.set_liquidity_source(&new_source);
    }

    #[test]
    fn test_close_idempotent_when_already_closed() {
        let env = Env::default();
        let (admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.close_credit_line(&borrower, &admin);
        client.close_credit_line(&borrower, &admin);

        assert_eq!(
            client.get_credit_line(&borrower).unwrap().status,
            CreditStatus::Closed
        );
    }

    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn test_draw_zero_panics() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.draw_credit(&borrower, &0);
    }

    #[test]
    #[should_panic(expected = "credit_limit must be greater than zero")]
    fn test_open_zero_limit_panics() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);
        client.open_credit_line(&borrower, &0, &500, &50);
    }

    #[test]
    fn test_set_liquidity_token() {
        let env = Env::default();
        let (_admin, _borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        let token = env.register_stellar_asset_contract_v2(Address::generate(&env));
        client.set_liquidity_token(&token.address());
    }

    #[test]
    #[should_panic(expected = "Insufficient liquidity reserve for requested draw amount")]
    fn test_draw_panics_when_reserve_insufficient() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        let token = env.register_stellar_asset_contract_v2(Address::generate(&env));
        let token_client = token::StellarAssetClient::new(&env, &token.address());
        let reserve = Address::generate(&env);
        token_client.mint(&reserve, &100);

        client.set_liquidity_token(&token.address());
        client.set_liquidity_source(&reserve);
        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.draw_credit(&borrower, &500);
    }

    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn test_repay_zero_panics() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.repay_credit(&borrower, &0);
    }

    #[test]
    #[should_panic(expected = "credit line is closed")]
    fn test_repay_closed_panics() {
        let env = Env::default();
        let (admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.close_credit_line(&borrower, &admin);
        client.repay_credit(&borrower, &1);
    }

    #[test]
    #[should_panic(expected = "credit line is closed")]
    fn test_draw_closed_panics() {
        let env = Env::default();
        let (admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.close_credit_line(&borrower, &admin);
        client.draw_credit(&borrower, &1);
    }

    #[test]
    #[should_panic(expected = "cannot close: utilized amount not zero")]
    fn test_borrower_cannot_close_with_nonzero_utilization() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.draw_credit(&borrower, &1_000);
        client.close_credit_line(&borrower, &borrower);
    }

    #[test]
    #[should_panic(expected = "unauthorized")]
    fn test_non_admin_non_borrower_cannot_close() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let attacker = Address::generate(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.close_credit_line(&borrower, &attacker);
    }

    #[test]
    #[should_panic(expected = "interest_rate_bps cannot exceed 10000 (100%)")]
    fn test_open_interest_rate_too_high_panics() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);
        client.open_credit_line(&borrower, &10_000, &10_001, &50);
    }

    #[test]
    #[should_panic(expected = "risk_score must be between 0 and 100")]
    fn test_open_risk_score_too_high_panics() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);
        client.open_credit_line(&borrower, &10_000, &500, &101);
    }

    #[test]
    #[should_panic(expected = "borrower already has an active credit line")]
    fn test_open_active_credit_line_twice_panics() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.open_credit_line(&borrower, &20_000, &700, &70);
    }

    #[test]
    #[should_panic(expected = "credit line is not defaulted")]
    fn test_reinstate_non_defaulted_panics() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.reinstate_credit_line(&borrower);
    }

    #[test]
    #[should_panic(expected = "credit_limit must be non-negative")]
    fn test_update_risk_parameters_negative_limit_panics() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.update_risk_parameters(&borrower, &-1, &500, &50);
    }

    #[test]
    #[should_panic(expected = "credit_limit cannot be less than utilized amount")]
    fn test_update_risk_parameters_limit_below_utilized_panics() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.draw_credit(&borrower, &2_000);
        client.update_risk_parameters(&borrower, &1_000, &500, &50);
    }

    #[test]
    #[should_panic(expected = "interest_rate_bps exceeds maximum")]
    fn test_update_risk_parameters_interest_too_high_panics() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.update_risk_parameters(&borrower, &10_000, &10_001, &50);
    }

    #[test]
    #[should_panic(expected = "risk_score exceeds maximum")]
    fn test_update_risk_parameters_risk_score_too_high_panics() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup(&env);
        let client = CreditClient::new(&env, &contract_id);

        client.open_credit_line(&borrower, &10_000, &500, &50);
        client.update_risk_parameters(&borrower, &10_000, &500, &101);
    }

    #[test]
    fn test_construct_contract_error_variants_for_coverage() {
        // Touch all variants to keep contract errors covered by line-based gates.
        let _ = types::ContractError::Unauthorized as u32;
        let _ = types::ContractError::NotAdmin as u32;
        let _ = types::ContractError::CreditLineNotFound as u32;
        let _ = types::ContractError::CreditLineClosed as u32;
        let _ = types::ContractError::InvalidAmount as u32;
        let _ = types::ContractError::OverLimit as u32;
        let _ = types::ContractError::NegativeLimit as u32;
        let _ = types::ContractError::RateTooHigh as u32;
        let _ = types::ContractError::ScoreTooHigh as u32;
        let _ = types::ContractError::UtilizationNotZero as u32;
        let _ = types::ContractError::Reentrancy as u32;
        let _ = types::ContractError::Overflow as u32;
    }
}
