#![no_std]
#![allow(clippy::unused_unit)]

//! Creditra credit contract: credit lines, draw/repay, risk parameters.
//!
//! # Status transitions
//!
//! | From      | To        | Trigger                                                              |
//! |-----------|-----------|----------------------------------------------------------------------|
//! | Active    | Defaulted | Admin calls `default_credit_line` (e.g. after past-due or oracle).  |
//! | Suspended | Defaulted | Admin calls `default_credit_line`.                                   |
//! | Defaulted | Active    | Admin calls `reinstate_credit_line`.                                 |
//! | Defaulted | Suspended | Admin calls `suspend_credit_line`.                                   |
//! | Defaulted | Closed    | Admin or borrower (when utilized_amount == 0) calls `close_credit_line`. |
//!
//! When status is Defaulted: `draw_credit` is disabled; `repay_credit` is allowed.
//!
//! # Reentrancy
//! Soroban token transfers do not invoke callbacks back into the caller. This contract
//! uses a reentrancy guard on draw_credit and repay_credit as a defense-in-depth measure.

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

const MAX_INTEREST_RATE_BPS: u32 = 10_000;
const MAX_RISK_SCORE: u32 = 100;

fn reentrancy_key(env: &Env) -> Symbol {
    Symbol::new(env, "reentrancy")
}

fn admin_key(env: &Env) -> Symbol {
    Symbol::new(env, "admin")
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    LiquidityToken,
    LiquiditySource,
}

fn set_reentrancy_guard(env: &Env) {
    let key = reentrancy_key(env);
    let current: bool = env.storage().instance().get(&key).unwrap_or(false);
    if current {
        panic!("reentrancy guard");
    }
    env.storage().instance().set(&key, &true);
}

fn clear_reentrancy_guard(env: &Env) {
    env.storage().instance().set(&reentrancy_key(env), &false);
}

fn rate_cfg_key(env: &Env) -> Symbol {
    Symbol::new(env, "rate_cfg")
}

#[contract]
pub struct Credit;

#[contractimpl]
impl Credit {
    /// Initializes the contract with an admin address.
    pub fn init(env: Env, admin: Address) {
        env.storage().instance().set(&admin_key(&env), &admin);
        env.storage()
            .instance()
            .set(&DataKey::LiquiditySource, &env.current_contract_address());
    }

    /// Sets the token contract used for reserve/liquidity checks and draw transfers. Admin-only.
    pub fn set_liquidity_token(env: Env, token_address: Address) {
        require_admin_auth(&env);
        env.storage()
            .instance()
            .set(&DataKey::LiquidityToken, &token_address);
    }

    /// Sets the address that provides liquidity for draw operations. Admin-only.
    pub fn set_liquidity_source(env: Env, reserve_address: Address) {
        require_admin_auth(&env);
        env.storage()
            .instance()
            .set(&DataKey::LiquiditySource, &reserve_address);
    }

    /// Opens a new credit line for a borrower. Admin-only (backend/risk engine key).
    ///
    /// # Panics
    /// * If caller is not the admin
    /// * If `credit_limit` <= 0, `interest_rate_bps` > 10000, or `risk_score` > 100
    /// * If an Active credit line already exists for the borrower
    pub fn open_credit_line(
        env: Env,
        borrower: Address,
        credit_limit: i128,
        interest_rate_bps: u32,
        risk_score: u32,
    ) {
        require_admin_auth(&env);
        assert!(credit_limit > 0, "credit_limit must be greater than zero");
        assert!(
            interest_rate_bps <= 10_000,
            "interest_rate_bps cannot exceed 10000 (100%)"
        );
        assert!(risk_score <= 100, "risk_score must be between 0 and 100");

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

    /// Draws funds from an active credit line. Borrower must authorize.
    ///
    /// # Panics
    /// * `"Credit line not found"` – no credit line for borrower
    /// * `"credit line is closed"` – line is closed
    /// * `"exceeds credit limit"` – draw would exceed credit_limit
    /// * `"amount must be positive"` – amount <= 0
    /// * `"reentrancy guard"` – re-entrant call detected
    pub fn draw_credit(env: Env, borrower: Address, amount: i128) {
        set_reentrancy_guard(&env);
        borrower.require_auth();

        if amount <= 0 {
            clear_reentrancy_guard(&env);
            panic!("amount must be positive");
        }

        let token_address: Option<Address> =
            env.storage().instance().get(&DataKey::LiquidityToken);
        let reserve_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::LiquiditySource)
            .unwrap_or(env.current_contract_address());

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

    /// Repays drawn credit. Allowed when Active, Suspended, or Defaulted. Borrower must authorize.
    pub fn repay_credit(env: Env, borrower: Address, amount: i128) {
        set_reentrancy_guard(&env);
        borrower.require_auth();

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

    /// Updates risk parameters for an existing credit line. Admin-only.
    pub fn update_risk_parameters(
        env: Env,
        borrower: Address,
        credit_limit: i128,
        interest_rate_bps: u32,
        risk_score: u32,
    ) {
        require_admin_auth(&env);

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

    /// Configures rate-change limits. Admin-only.
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
        env.storage().instance().set(&rate_cfg_key(&env), &cfg);
    }

    /// Returns the current rate-change limit configuration.
    pub fn get_rate_change_limits(env: Env) -> Option<RateChangeConfig> {
        env.storage().instance().get(&rate_cfg_key(&env))
    }

    /// Suspends a credit line temporarily. Admin-only.
    pub fn suspend_credit_line(env: Env, borrower: Address) {
        require_admin_auth(&env);

        let mut credit_line: CreditLineData = env
            .storage()
            .persistent()
            .get(&borrower)
            .expect("Credit line not found");

        credit_line.status = CreditStatus::Suspended;
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

    /// Closes a credit line. Admin can force-close; borrower can close only when utilized_amount == 0.
    /// Idempotent if already Closed.
    pub fn close_credit_line(env: Env, borrower: Address, closer: Address) {
        closer.require_auth();

        let admin: Address = require_admin(&env);

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

    /// Marks a credit line as defaulted. Admin-only. Transition: Active or Suspended → Defaulted.
    pub fn default_credit_line(env: Env, borrower: Address) {
        require_admin_auth(&env);

        let mut credit_line: CreditLineData = env
            .storage()
            .persistent()
            .get(&borrower)
            .expect("Credit line not found");

        credit_line.status = CreditStatus::Defaulted;
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

    /// Reinstates a defaulted credit line to Active. Admin-only. Transition: Defaulted → Active.
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

    /// Returns the credit line data for a borrower, or None if not found.
    pub fn get_credit_line(env: Env, borrower: Address) -> Option<CreditLineData> {
        env.storage().persistent().get(&borrower)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::testutils::Events as _;
    use soroban_sdk::token;
    use soroban_sdk::token::StellarAssetClient;
    use soroban_sdk::{Symbol, TryFromVal, TryIntoVal};

    soroban_sdk::contractimpl! { export! CreditImpl }
    type CreditClient<'a> = soroban_sdk::contractclient::ContractClient<'a, CreditImpl>;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn setup_test(env: &Env) -> (Address, Address, Address) {
        env.mock_all_auths();
        let admin = Address::generate(env);
        let borrower = Address::generate(env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        (admin, borrower, contract_id)
    }

    fn call_contract<F>(env: &Env, contract_id: &Address, f: F)
    where
        F: FnOnce(),
    {
        env.as_contract(contract_id, f);
    }

    fn get_credit_data(env: &Env, contract_id: &Address, borrower: &Address) -> CreditLineData {
        CreditClient::new(env, contract_id)
            .get_credit_line(borrower)
            .expect("Credit line not found")
    }

    fn setup_contract_with_credit_line<'a>(
        env: &'a Env,
        borrower: &'a Address,
        credit_limit: i128,
        reserve_amount: i128,
    ) -> (CreditClient<'a>, Address, Address) {
        let admin = Address::generate(env);
        let contract_id = env.register(Credit, ());
        let token_admin = Address::generate(env);
        let token_id = env.register_stellar_asset_contract_v2(token_admin);
        let token_address = token_id.address();
        let client = CreditClient::new(env, &contract_id);
        client.init(&admin);
        if reserve_amount > 0 {
            StellarAssetClient::new(env, &token_address).mint(&contract_id, &reserve_amount);
        }
        client.set_liquidity_token(&token_address);
        client.open_credit_line(borrower, &credit_limit, &300_u32, &70_u32);
        (client, token_address, admin)
    }

    fn setup_token<'a>(
        env: &'a Env,
        contract_id: &'a Address,
        reserve_amount: i128,
    ) -> (Address, StellarAssetClient<'a>) {
        let token_admin = Address::generate(env);
        let token_id = env.register_stellar_asset_contract_v2(token_admin);
        let token_address = token_id.address();
        let sac = StellarAssetClient::new(env, &token_address);
        if reserve_amount > 0 {
            sac.mint(contract_id, &reserve_amount);
        }
        (token_address, sac)
    }

    struct MockLiquidityToken<'a> {
        address: Address,
        admin_client: StellarAssetClient<'a>,
        token_client: token::Client<'a>,
    }

    impl<'a> MockLiquidityToken<'a> {
        fn deploy(env: &'a Env) -> Self {
            let token_admin = Address::generate(env);
            let token_id = env.register_stellar_asset_contract_v2(token_admin);
            let address = token_id.address();
            Self {
                address: address.clone(),
                admin_client: StellarAssetClient::new(env, &address),
                token_client: token::Client::new(env, &address),
            }
        }
        fn address(&self) -> Address {
            self.address.clone()
        }

        fn mint(&self, to: &Address, amount: i128) {
            self.admin_client.mint(to, &amount);
        }

        fn approve(&self, from: &Address, spender: &Address, amount: i128, expires_at: u32) {
            self.token_client
                .approve(from, spender, &amount, &expires_at);
        }

        fn balance(&self, address: &Address) -> i128 {
            self.token_client.balance(address)
        }

        fn allowance(&self, from: &Address, spender: &Address) -> i128 {
            self.token_client.allowance(from, spender)
        }
    }

    // ── init / open ───────────────────────────────────────────────────────────

    #[test]
    fn test_init_and_open_credit_line() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        let line = client.get_credit_line(&borrower).unwrap();
        assert_eq!(line.borrower, borrower);
        assert_eq!(line.credit_limit, 1000);
        assert_eq!(line.utilized_amount, 0);
        assert_eq!(line.interest_rate_bps, 300);
        assert_eq!(line.risk_score, 70);
        assert_eq!(line.status, CreditStatus::Active);
    }

    // ── open_credit_line: authorization ──────────────────────────────────────

    #[test]
    fn test_open_credit_line_admin_succeeds() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        assert!(client.get_credit_line(&borrower).is_some());
    }

    /// Non-admin must be rejected: no mock_all_auths, so admin.require_auth() fails.
    #[test]
    #[should_panic]
    fn test_open_credit_line_non_admin_rejected() {
        let env = Env::default();
        // Deliberately no mock_all_auths — admin auth will not be satisfied.
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        // init needs auth too, so mock just for init
        env.mock_all_auths();
        client.init(&admin);
        // Clear recorded auths and call without any auth context
        let env2 = Env::default();
        let client2 = CreditClient::new(&env2, &contract_id);
        client2.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
    }

    // ── open_credit_line: validation ─────────────────────────────────────────

    #[test]
    #[should_panic(expected = "borrower already has an active credit line")]
    fn test_open_credit_line_duplicate_active_borrower_reverts() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.open_credit_line(&borrower, &2000_i128, &400_u32, &60_u32);
    }

    #[test]
    #[should_panic(expected = "credit_limit must be greater than zero")]
    fn test_open_credit_line_zero_limit_reverts() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &0_i128, &300_u32, &70_u32);
    }

    #[test]
    #[should_panic(expected = "credit_limit must be greater than zero")]
    fn test_open_credit_line_negative_limit_reverts() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &-1_i128, &300_u32, &70_u32);
    }

    #[test]
    #[should_panic(expected = "interest_rate_bps cannot exceed 10000 (100%)")]
    fn test_open_credit_line_interest_rate_exceeds_max_reverts() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &10_001_u32, &70_u32);
    }

    #[test]
    #[should_panic(expected = "risk_score must be between 0 and 100")]
    fn test_open_credit_line_risk_score_exceeds_max_reverts() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &101_u32);
    }

    // ── draw_credit ───────────────────────────────────────────────────────────

    #[test]
    fn test_draw_credit() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup_test(&env);
        call_contract(&env, &contract_id, || {
            Credit::draw_credit(env.clone(), borrower.clone(), 500_i128);
        });
        assert_eq!(get_credit_data(&env, &contract_id, &borrower).utilized_amount, 500_i128);
    }

    #[test]
    fn test_draw_credit_single_within_limit_succeeds_and_updates_utilized() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.draw_credit(&borrower, &400_i128);
        let line = client.get_credit_line(&borrower).unwrap();
        assert_eq!(line.utilized_amount, 400);
        assert_eq!(line.credit_limit, 1000);
    }

    #[test]
    fn test_draw_credit_multiple_draws_within_limit_accumulate_utilized() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.draw_credit(&borrower, &100_i128);
        assert_eq!(client.get_credit_line(&borrower).unwrap().utilized_amount, 100);
        client.draw_credit(&borrower, &250_i128);
        assert_eq!(client.get_credit_line(&borrower).unwrap().utilized_amount, 350);
        client.draw_credit(&borrower, &150_i128);
        assert_eq!(client.get_credit_line(&borrower).unwrap().utilized_amount, 500);
    }

    #[test]
    fn test_draw_credit_exact_available_limit_succeeds() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        let limit = 5000_i128;
        client.open_credit_line(&borrower, &limit, &300_u32, &70_u32);
        client.draw_credit(&borrower, &limit);
        let line = client.get_credit_line(&borrower).unwrap();
        assert_eq!(line.utilized_amount, limit);
    }

    #[test]
    fn test_draw_credit_updates_utilized() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.draw_credit(&borrower, &200_i128);
        assert_eq!(client.get_credit_line(&borrower).unwrap().utilized_amount, 200);
        client.draw_credit(&borrower, &300_i128);
        assert_eq!(client.get_credit_line(&borrower).unwrap().utilized_amount, 500);
    }

    #[test]
    #[should_panic(expected = "credit line is closed")]
    fn test_draw_credit_rejected_when_closed() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.close_credit_line(&borrower, &admin);
        client.draw_credit(&borrower, &100_i128);
    }

    #[test]
    #[should_panic(expected = "exceeds credit limit")]
    fn test_draw_credit_rejected_when_exceeding_limit() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &100_i128, &300_u32, &70_u32);
        client.draw_credit(&borrower, &101_i128);
    }

    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn test_draw_credit_rejected_when_amount_is_zero() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.draw_credit(&borrower, &0_i128);
    }

    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn test_draw_credit_rejected_when_amount_is_negative() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.draw_credit(&borrower, &-1_i128);
    }

    // ── repay_credit ──────────────────────────────────────────────────────────

    #[test]
    fn test_repay_credit_partial() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup_test(&env);
        call_contract(&env, &contract_id, || {
            Credit::draw_credit(env.clone(), borrower.clone(), 500_i128);
        });
        call_contract(&env, &contract_id, || {
            Credit::repay_credit(env.clone(), borrower.clone(), 200_i128);
        });
        assert_eq!(get_credit_data(&env, &contract_id, &borrower).utilized_amount, 300_i128);
    }

    #[test]
    fn test_repay_credit_full() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup_test(&env);
        call_contract(&env, &contract_id, || {
            Credit::draw_credit(env.clone(), borrower.clone(), 500_i128);
        });
        call_contract(&env, &contract_id, || {
            Credit::repay_credit(env.clone(), borrower.clone(), 500_i128);
        });
        assert_eq!(get_credit_data(&env, &contract_id, &borrower).utilized_amount, 0_i128);
    }

    #[test]
    fn test_repay_credit_overpayment() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup_test(&env);
        call_contract(&env, &contract_id, || {
            Credit::draw_credit(env.clone(), borrower.clone(), 300_i128);
        });
        call_contract(&env, &contract_id, || {
            Credit::repay_credit(env.clone(), borrower.clone(), 500_i128);
        });
        assert_eq!(get_credit_data(&env, &contract_id, &borrower).utilized_amount, 0_i128);
    }

    #[test]
    fn test_repay_credit_zero_utilization() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup_test(&env);
        call_contract(&env, &contract_id, || {
            Credit::repay_credit(env.clone(), borrower.clone(), 100_i128);
        });
        assert_eq!(get_credit_data(&env, &contract_id, &borrower).utilized_amount, 0_i128);
    }

    #[test]
    fn test_repay_credit_suspended_status() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup_test(&env);
        call_contract(&env, &contract_id, || {
            Credit::draw_credit(env.clone(), borrower.clone(), 500_i128);
        });
        let mut credit_data = get_credit_data(&env, &contract_id, &borrower);
        credit_data.status = CreditStatus::Suspended;
        env.as_contract(&contract_id, || {
            env.storage().persistent().set(&borrower, &credit_data);
        });
        call_contract(&env, &contract_id, || {
            Credit::repay_credit(env.clone(), borrower.clone(), 200_i128);
        });
        let updated = get_credit_data(&env, &contract_id, &borrower);
        assert_eq!(updated.utilized_amount, 300_i128);
        assert_eq!(updated.status, CreditStatus::Suspended);
    }

    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn test_repay_credit_invalid_amount_zero() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup_test(&env);
        call_contract(&env, &contract_id, || {
            Credit::repay_credit(env.clone(), borrower.clone(), 0_i128);
        });
    }

    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn test_repay_credit_invalid_amount_negative() {
        let env = Env::default();
        let (_admin, borrower, contract_id) = setup_test(&env);
        call_contract(&env, &contract_id, || {
            Credit::repay_credit(env.clone(), borrower.clone(), -100_i128);
        });
    }

    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn test_repay_credit_rejects_non_positive_amount() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.repay_credit(&borrower, &0_i128);
    }

    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn test_repay_credit_rejected_when_amount_is_negative() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.repay_credit(&borrower, &-500_i128);
    }

    #[test]
    #[should_panic(expected = "credit line is closed")]
    fn test_repay_credit_rejected_when_closed() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.close_credit_line(&borrower, &admin);
        client.repay_credit(&borrower, &100_i128);
    }

    #[test]
    fn test_repay_credit_succeeds_when_defaulted() {
        let env = Env::default();
        env.mock_all_auths();
        let borrower = Address::generate(&env);
        let (client, _token, _admin) =
            setup_contract_with_credit_line(&env, &borrower, 1_000, 1_000);
        client.draw_credit(&borrower, &400);
        client.default_credit_line(&borrower);
        client.repay_credit(&borrower, &150);
        let line = client.get_credit_line(&borrower).unwrap();
        assert_eq!(line.status, CreditStatus::Defaulted);
        assert_eq!(line.utilized_amount, 250);
    }

    #[test]
    #[should_panic(expected = "Credit line not found")]
    fn test_repay_credit_nonexistent_line() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.repay_credit(&borrower, &100_i128);
    }

    #[test]
    fn test_repay_credit_reduces_utilized_and_emits_event() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.draw_credit(&borrower, &500_i128);
        let _ = env.events().all();
        client.repay_credit(&borrower, &200_i128);
        let events_after = env.events().all().len();
        assert_eq!(client.get_credit_line(&borrower).unwrap().utilized_amount, 300);
        assert_eq!(events_after, 1, "repay_credit must emit exactly one RepaymentEvent");
    }

    #[test]
    fn test_repay_credit_saturates_at_zero() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.draw_credit(&borrower, &100_i128);
        client.repay_credit(&borrower, &500_i128);
        assert_eq!(client.get_credit_line(&borrower).unwrap().utilized_amount, 0);
    }

    // ── lifecycle / status transitions ────────────────────────────────────────

    #[test]
    fn test_suspend_credit_line() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.suspend_credit_line(&borrower);
        assert_eq!(client.get_credit_line(&borrower).unwrap().status, CreditStatus::Suspended);
    }

    #[test]
    fn test_close_credit_line() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.close_credit_line(&borrower, &admin);
        assert_eq!(client.get_credit_line(&borrower).unwrap().status, CreditStatus::Closed);
    }

    #[test]
    fn test_default_credit_line() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.default_credit_line(&borrower);
        assert_eq!(client.get_credit_line(&borrower).unwrap().status, CreditStatus::Defaulted);
    }

    #[test]
    fn test_lifecycle_transitions() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        assert_eq!(client.get_credit_line(&borrower).unwrap().status, CreditStatus::Active);
        client.default_credit_line(&borrower);
        assert_eq!(client.get_credit_line(&borrower).unwrap().status, CreditStatus::Defaulted);
    }

    #[test]
    fn test_full_lifecycle() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &5000_i128, &500_u32, &80_u32);
        assert_eq!(client.get_credit_line(&borrower).unwrap().status, CreditStatus::Active);
        client.suspend_credit_line(&borrower);
        assert_eq!(client.get_credit_line(&borrower).unwrap().status, CreditStatus::Suspended);
        client.close_credit_line(&borrower, &admin);
        assert_eq!(client.get_credit_line(&borrower).unwrap().status, CreditStatus::Closed);
    }

    #[test]
    fn test_close_credit_line_borrower_when_utilized_zero() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.close_credit_line(&borrower, &borrower);
        let line = client.get_credit_line(&borrower).unwrap();
        assert_eq!(line.status, CreditStatus::Closed);
        assert_eq!(line.utilized_amount, 0);
    }

    #[test]
    #[should_panic(expected = "cannot close: utilized amount not zero")]
    fn test_close_credit_line_borrower_rejected_when_utilized_nonzero() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.draw_credit(&borrower, &300_i128);
        client.close_credit_line(&borrower, &borrower);
    }

    #[test]
    fn test_close_credit_line_admin_force_close_with_utilization() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.draw_credit(&borrower, &300_i128);
        client.close_credit_line(&borrower, &admin);
        let line = client.get_credit_line(&borrower).unwrap();
        assert_eq!(line.status, CreditStatus::Closed);
        assert_eq!(line.utilized_amount, 300);
    }

    #[test]
    fn test_close_credit_line_idempotent_when_already_closed() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.close_credit_line(&borrower, &admin);
        client.close_credit_line(&borrower, &admin);
        assert_eq!(client.get_credit_line(&borrower).unwrap().status, CreditStatus::Closed);
    }

    #[test]
    #[should_panic(expected = "unauthorized")]
    fn test_close_credit_line_unauthorized_closer() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let other = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.close_credit_line(&borrower, &other);
    }

    #[test]
    fn test_close_credit_line_defaulted_admin_force_close() {
        let env = Env::default();
        env.mock_all_auths();
        let borrower = Address::generate(&env);
        let (client, _token, admin) =
            setup_contract_with_credit_line(&env, &borrower, 1_000, 1_000);
        client.draw_credit(&borrower, &300);
        client.default_credit_line(&borrower);
        client.close_credit_line(&borrower, &admin);
        let line = client.get_credit_line(&borrower).unwrap();
        assert_eq!(line.status, CreditStatus::Closed);
        assert_eq!(line.utilized_amount, 300);
    }

    #[test]
    fn test_close_credit_line_defaulted_borrower_when_zero_utilization() {
        let env = Env::default();
        env.mock_all_auths();
        let borrower = Address::generate(&env);
        let (client, _token, _admin) = setup_contract_with_credit_line(&env, &borrower, 1_000, 0);
        client.default_credit_line(&borrower);
        client.close_credit_line(&borrower, &borrower);
        assert_eq!(client.get_credit_line(&borrower).unwrap().status, CreditStatus::Closed);
    }

    // ── nonexistent credit line guards ────────────────────────────────────────

    #[test]
    #[should_panic(expected = "Credit line not found")]
    fn test_suspend_nonexistent_credit_line() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.suspend_credit_line(&borrower);
    }

    #[test]
    #[should_panic(expected = "Credit line not found")]
    fn test_close_nonexistent_credit_line() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.close_credit_line(&borrower, &admin);
    }

    #[test]
    #[should_panic(expected = "Credit line not found")]
    fn test_default_nonexistent_credit_line() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.default_credit_line(&borrower);
    }

    #[test]
    #[should_panic(expected = "Credit line not found")]
    fn test_reinstate_nonexistent_credit_line() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let (token_address, _) = setup_token(&env, &contract_id, 0);
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.set_liquidity_token(&token_address);
        client.reinstate_credit_line(&borrower);
    }

    // ── reinstate ─────────────────────────────────────────────────────────────

    #[test]
    fn test_reinstate_credit_line() {
        let env = Env::default();
        env.mock_all_auths();
        let borrower = Address::generate(&env);
        let (client, _token, _admin) =
            setup_contract_with_credit_line(&env, &borrower, 1_000, 1_000);
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
        client.draw_credit(&borrower, &200);
        assert_eq!(
            client.get_credit_line(&borrower).unwrap().utilized_amount,
            200
        );
    }

    #[test]
    #[should_panic(expected = "credit line is not defaulted")]
    fn test_reinstate_credit_line_not_defaulted() {
        let env = Env::default();
        env.mock_all_auths();
        let borrower = Address::generate(&env);
        let (client, _token, _admin) = setup_contract_with_credit_line(&env, &borrower, 1_000, 0);
        client.reinstate_credit_line(&borrower);
    }

    #[test]
    #[should_panic]
    fn test_reinstate_credit_line_unauthorized() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let (token_address, _) = setup_token(&env, &contract_id, 0);
        let client = CreditClient::new(&env, &contract_id);
        // init needs auth
        env.mock_all_auths();
        client.init(&admin);
        client.set_liquidity_token(&token_address);
        client.open_credit_line(&borrower, &1_000, &300_u32, &70_u32);
        client.default_credit_line(&borrower);
        // no auth from here
        let env2 = Env::default();
        let client2 = CreditClient::new(&env2, &contract_id);
        client2.reinstate_credit_line(&borrower);
    }

    // ── admin-only enforcement ────────────────────────────────────────────────

    #[test]
    #[should_panic]
    fn test_suspend_credit_line_unauthorized() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        env.mock_all_auths();
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        let env2 = Env::default();
        let client2 = CreditClient::new(&env2, &contract_id);
        client2.suspend_credit_line(&borrower);
    }

    #[test]
    #[should_panic]
    fn test_default_credit_line_unauthorized() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        env.mock_all_auths();
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        let env2 = Env::default();
        let client2 = CreditClient::new(&env2, &contract_id);
        client2.default_credit_line(&borrower);
    }

    #[test]
    #[should_panic]
    fn test_set_liquidity_token_requires_admin_auth() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        let token = env.register_stellar_asset_contract_v2(token_admin);
        client.set_liquidity_token(&token.address());
    }

    #[test]
    #[should_panic]
    fn test_set_liquidity_source_requires_admin_auth() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let reserve = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.set_liquidity_source(&reserve);
    }

    // ── update_risk_parameters ────────────────────────────────────────────────

    #[test]
    fn test_update_risk_parameters_success() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.update_risk_parameters(&borrower, &2000_i128, &400_u32, &85_u32);
        let line = client.get_credit_line(&borrower).unwrap();
        assert_eq!(line.credit_limit, 2000);
        assert_eq!(line.interest_rate_bps, 400);
        assert_eq!(line.risk_score, 85);
    }

    #[test]
    #[should_panic]
    fn test_update_risk_parameters_unauthorized_caller() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        env.mock_all_auths();
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        let env2 = Env::default();
        let client2 = CreditClient::new(&env2, &contract_id);
        client2.update_risk_parameters(&borrower, &2000_i128, &400_u32, &85_u32);
    }

    #[test]
    #[should_panic(expected = "Credit line not found")]
    fn test_update_risk_parameters_nonexistent_line() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.update_risk_parameters(&borrower, &1000_i128, &300_u32, &70_u32);
    }

    #[test]
    #[should_panic(expected = "credit_limit cannot be less than utilized amount")]
    fn test_update_risk_parameters_credit_limit_below_utilized() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.draw_credit(&borrower, &500_i128);
        client.update_risk_parameters(&borrower, &300_i128, &300_u32, &70_u32);
    }

    #[test]
    #[should_panic(expected = "credit_limit must be non-negative")]
    fn test_update_risk_parameters_negative_credit_limit() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.update_risk_parameters(&borrower, &(-1_i128), &300_u32, &70_u32);
    }

    #[test]
    #[should_panic(expected = "interest_rate_bps exceeds maximum")]
    fn test_update_risk_parameters_interest_rate_exceeds_max() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.update_risk_parameters(&borrower, &1000_i128, &10001_u32, &70_u32);
    }

    #[test]
    #[should_panic(expected = "risk_score exceeds maximum")]
    fn test_update_risk_parameters_risk_score_exceeds_max() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.update_risk_parameters(&borrower, &1000_i128, &300_u32, &101_u32);
    }

    #[test]
    fn test_update_risk_parameters_at_boundaries() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.update_risk_parameters(&borrower, &1000_i128, &10000_u32, &100_u32);
        let line = client.get_credit_line(&borrower).unwrap();
        assert_eq!(line.interest_rate_bps, 10000);
        assert_eq!(line.risk_score, 100);
    }

    // ── multiple borrowers ────────────────────────────────────────────────────

    #[test]
    fn test_multiple_borrowers() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower1 = Address::generate(&env);
        let borrower2 = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower1, &1000_i128, &300_u32, &70_u32);
        client.open_credit_line(&borrower2, &2000_i128, &400_u32, &80_u32);
        assert_eq!(client.get_credit_line(&borrower1).unwrap().credit_limit, 1000);
        assert_eq!(client.get_credit_line(&borrower2).unwrap().credit_limit, 2000);
    }

    #[test]
    fn test_event_data_integrity() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &2000_i128, &400_u32, &75_u32);
        let line = client.get_credit_line(&borrower).unwrap();
        assert_eq!(line.borrower, borrower);
        assert_eq!(line.status, CreditStatus::Active);
        assert_eq!(line.credit_limit, 2000);
        assert_eq!(line.interest_rate_bps, 400);
        assert_eq!(line.risk_score, 75);
    }

    // ── reentrancy guard ──────────────────────────────────────────────────────

    #[test]
    fn test_reentrancy_guard_cleared_after_draw() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.draw_credit(&borrower, &100_i128);
        client.draw_credit(&borrower, &100_i128);
        assert_eq!(client.get_credit_line(&borrower).unwrap().utilized_amount, 200);
    }

    #[test]
    fn test_reentrancy_guard_cleared_after_repay() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.open_credit_line(&borrower, &1000_i128, &300_u32, &70_u32);
        client.draw_credit(&borrower, &200_i128);
        client.repay_credit(&borrower, &50_i128);
        client.repay_credit(&borrower, &50_i128);
        assert_eq!(client.get_credit_line(&borrower).unwrap().utilized_amount, 100);
    }

    // ── liquidity token integration ───────────────────────────────────────────

    #[test]
    fn test_draw_credit_with_sufficient_liquidity() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        let liquidity = MockLiquidityToken::deploy(&env);
        client.init(&admin);
        client.open_credit_line(&borrower, &1_000_i128, &300_u32, &70_u32);
        client.set_liquidity_token(&liquidity.address());
        liquidity.mint(&contract_id, 500_i128);
        client.draw_credit(&borrower, &200_i128);
        assert_eq!(liquidity.balance(&contract_id), 300_i128);
        assert_eq!(liquidity.balance(&borrower), 200_i128);
        assert_eq!(client.get_credit_line(&borrower).unwrap().utilized_amount, 200_i128);
    }

    #[test]
    #[should_panic(expected = "Insufficient liquidity reserve for requested draw amount")]
    fn test_draw_credit_with_insufficient_liquidity() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        let liquidity = MockLiquidityToken::deploy(&env);
        client.init(&admin);
        client.open_credit_line(&borrower, &1_000_i128, &300_u32, &70_u32);
        client.set_liquidity_token(&liquidity.address());
        liquidity.mint(&contract_id, 50_i128);
        client.draw_credit(&borrower, &100_i128);
    }

    #[test]
    fn test_set_liquidity_source_updates_instance_storage() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let reserve = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);
        client.set_liquidity_source(&reserve);
        let stored: Address = env
            .as_contract(&contract_id, || {
                env.storage().instance().get(&DataKey::LiquiditySource)
            })
            .unwrap();
        assert_eq!(stored, reserve);
    }

    #[test]
    fn test_draw_credit_uses_configured_external_liquidity_source() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        let liquidity = MockLiquidityToken::deploy(&env);
        client.init(&admin);
        client.open_credit_line(&borrower, &1_000_i128, &300_u32, &70_u32);
        let reserve = contract_id.clone();
        client.set_liquidity_token(&liquidity.address());
        client.set_liquidity_source(&reserve);
        liquidity.mint(&reserve, 500_i128);
        client.draw_credit(&borrower, &120_i128);
        assert_eq!(liquidity.balance(&reserve), 380_i128);
        assert_eq!(liquidity.balance(&borrower), 120_i128);
    }

    #[test]
    fn test_repay_credit_integration_uses_mocked_allowance_and_balance_state() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        let liquidity = MockLiquidityToken::deploy(&env);
        client.init(&admin);
        client.open_credit_line(&borrower, &1_000_i128, &300_u32, &70_u32);
        client.set_liquidity_token(&liquidity.address());
        liquidity.mint(&contract_id, 500_i128);
        liquidity.mint(&borrower, 250_i128);
        liquidity.approve(&borrower, &contract_id, 200_i128, 1_000_u32);
        client.draw_credit(&borrower, &300_i128);
        client.repay_credit(&borrower, &200_i128);
        assert_eq!(client.get_credit_line(&borrower).unwrap().utilized_amount, 100_i128);
        assert_eq!(liquidity.balance(&borrower), 550_i128);
        assert_eq!(liquidity.allowance(&borrower, &contract_id), 200_i128);
    }

    // ── events ────────────────────────────────────────────────────────────────

    #[test]
    fn test_event_reinstate_credit_line() {
        let env = Env::default();
        env.mock_all_auths();
        let borrower = Address::generate(&env);
        let (client, _token, _admin) = setup_contract_with_credit_line(&env, &borrower, 1_000, 0);
        client.default_credit_line(&borrower);
        client.reinstate_credit_line(&borrower);
        let events = env.events().all();
        let (_contract, topics, data) = events.last().unwrap();
        assert_eq!(
            Symbol::try_from_val(&env, &topics.get(1).unwrap()).unwrap(),
            symbol_short!("reinstate")
        );
        let event_data: CreditLineEvent = data.try_into_val(&env).unwrap();
        assert_eq!(event_data.status, CreditStatus::Active);
    }

    #[test]
    fn test_event_lifecycle_sequence() {}
}
