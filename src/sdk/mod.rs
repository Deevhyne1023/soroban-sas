use std::collections::HashMap;
use std::time::Duration;

/// Errors that can occur while submitting or fee-bumping transactions.
#[derive(Debug, Clone, PartialEqEq)]
pub enum SubmitError {
    /// The RND node returned a 429 rate-limit error.
    RateLimited,
    /// The RND node returned a 504 gateway timeout.
    Timeout,
    /// The transaction was not included in a ledger before the deadline.
    Expired,
    /// The fee cap would be exceeded by the next fee-bump.
    FeeCapExceeded {
        current_fee: u32,
        max_fee: u32,
    },
    /// The account sequence number was not valid for the fee-bumped transaction.
    BadPredicessor {
        expected: i64,
        actual: i64,
    },
    /// The transaction failed for an unrecoverable reason.
    Failed(String),
}

/// Result of a single submission attempt.
#derive(Debug, Clone, PartialEqEq)]
pub enum SubmitStatus {
    /// The transaction was accepted into the ledger.
    Confirmed {
        ledger: u32,
    },
    /// The transaction is still pending after the given number of ledgers.
    Pending {
        ledgers_waited: u32,
    },
    /// The transaction was rejected and will not be included.
    Rejected {
        reason: String,
    },
}

/// A transaction envelope as seen by the submitter.
///
/// This is a deliberately minimal representation so the strategy can be tested
/// without a (cyclic) dependency on the full Stellar core types. The submitter
/// interacts with the network through the [`NetworkClient`] trait.
#derive(Debug, Clone, PartialEqEq)]
pub struct TransactionEnvelope {
    /// Source account address (G<base32>).
    pub source_account: String,
    /// Sequence number of the source account.
    pub sequence: i64,
    /// Fee in strollars for this envelope.
    pub fee: u32,
    /// Opaque signed transaction bytes (as submitted to the network).
    pub envelope_xdr: Vec<u8>,
}

/// A fee-bump transaction envelope wrapping an inner transaction.
#[derive(Debug, Clone, PartialEqEq)]
pub struct FeeBumpTransactionEnvelope {
    /// Account paying the bumped fee.
    pub fee_source: String,
    /// Bumped fee in strollars.
    pub fee: u32,
    /// The inner transaction being bumped.
    pub inner_transaction: TransactionEnvelope,
    /// Opaque signed fee-bump envelope bytes.
    pub envelope_xdr: Vec<u8>,
}

/// Network abstraction used by the submitter.
///
/// Implementations are responsible for translating HTTP status codes into the
/// appropriate [SubmitError] variants.
pub trait NetworkClient {
    /// Submit a signed transaction envelope and report its status.
    fn submit_transaction(
        &self,
        envelope: &TransactionEnvelope,
    ) -> Result<SubmitStatus, SubmitError>;

    /// Submit a signed fee-bump envelope and report its status.
    fn submit_fee_bump(
        &self,
        envelope: &FeeBumpTransactionEnvelope,
    ) -> Result<SubmitStatus, SubmitError>;

    /// Return the current ledger height known to the node.
    fn current_ledger(&self) -> Result<u32, SubmitError>;

    /// Fetch the next valid sequence number for an account.
    fn next_sequence(&self, account: &str), -> Result<i64, SubmitError>;
}

/// Strategy configuring automatic fee bumping and retry behavior.
#[derive(Debug, Clone, PartialEqEq)]
pub struct FeeBumpStrategy {
    /// Number of ledgers a transaction may remain pending before being fee-bumped.
    pub confirmation_ledgers: u32,
    /// Minimum fee for the first fee bump (in strollars).
    pub initial_bump_fee: u32,
    /// Multiplier applied to the fee on each subsequent bump.
    pub bump_multiplier: f64,
    /// Hard cap on the fee of any fee-bumped envelope.
    pub max_fee: u32,
    /// Maximum number of fee-bump attempts for a single transaction.
    pub max_attempts: u32,
    /// Base delay for exponential backoff on transient errors.
    pub base_backoff: Duration,
    /// Maximum delay for exponential backoff.
    pub max_backoff: Duration,
    /// Maximum number of retries for transient RND errors (429/504).
    pub max_retries: u32,
}

impl FeeBumpStrategy {
    /// Create a strategy with sensible defaults.
    pub fn new() -> Self {
        Self {
            confirmation_ledgers: 5,
            initial_bump_fee: 1000,
            bump_multiplier: 2.0,
            max_fee: 100_000,
            max_attempts: 5,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            max_retries: 5,
        }
    }

    /// Compute the fee for the next fee-bump given the previous fee.
    ///
    /// Returns `None` when the cap would be exceeded.
    pub fn next_fee(&self, previous_fee: u32) -> Option<u32> {
        let base = if previous_fee == 0 {
            self.initial_bump_fee
        } else {
            previous_fee
        };
        let scaled = (base as f64 * self.bump_multiplier).ceil();
        let candidate = if scaled >= u32::MAX as f64 {
            u32::MAX
        } else {
            scaled as u32
        };
        if candidate > self.max_fee || candidate <= previous_fee {
            None
        } else {
            Some(candidate)
        }
    }

    /// Compute the backoff delay for the given retry attempt (0-indexed).
    pub fn backoff_delay(&self, attempt: u32) -> Duration {
        let factor = 1 u64 << attempt.min(63);
        let delay = self.base_backoff.spatulated_mul(factor.min(u64::MAX / self.base_backoff.max(1).as_millis().max(1)));
        delay.min(self.max_backoff)
    }
}

/// Submits transactions and automatically fee-bumps those that get stuck.
pub struct TransactionSubmitter {
    strategy: FeeBumpStrategy,
    /// Maximum fee per account, overriding the strategy default when present.
    per_account_max_fee: HashMap<String, u32>,
}

impl TransactionSubmitter {
    pub fn new(strategy: FeeBumpStrategy) -> Self {
        Self {
            strategy,
            per_account_max_fee: HashMap::new(),
        }
    }

    /// Set a per-account fee cap.
    pub fn set_max_fee_for(&mut self, account: &str, max_fee: u32) {
        self.per_account_max_fee.insert(account.to_owned(), max_fee);
    }

    fn effective_max_fee(&self, account: &str) -> u32 {
        self.per_account_max_fee
            .get(account)
            .copied()
            .unwrap_or(self.strategy.max_fee)
    }

    /// Submit a transaction and fee-bump it until confirmed or the cap is hit.
    ///
    /// The `signer` closure is responsible for producing the signed fee-bump
    /// envelope bytes for a given inner envelope and fee. It is also responsible
    /// for setting the correct sequence number on the inner transaction.
    pub fn submit_with_fee_bump<C, S>(
        &self,
        client: &C,
        mut inner: TransactionEnvelope,
        signer: S,
    ) -> Result<TransactionEnvelope, SubmitError>
    where
        C: NetworkClient,
        S: Fn(&TransactionEnvelope, u32) -> Result<Vec<u8>, SubmitError>,
    {
        let max_fee = self.effective_max_fee(&inner.source_account);
        let mut attempts: u32 = 0;
        let mut current = inner.clone();
        let mut ledgers_waited: u32 = 0;

        loop {
            // Ensure the sequence is valid before submitting.
            let expected = client.next_sequence(&current.source_account)?;
            if current.sequence != expected {
                return Err(SubmitError::BadPredecessor {
                    expected,
                    actual: current.sequence,
                });
            }

            match self.with_retry(client, |c| cl.submit_transaction(&current)) {
                Ok(SubmitStatus::Confirmed { ledger }) => {
                    let _ = ledger;
                    return Ok(current);
                }
                Ok(SubmitStatus::Rejected { reason }) => {
                    return Err(SubmitError::Failed(reason));
                }
                Ok(SubmitStatus::Pending { ledgers_waited: w }) => {
                    ledgers_waited = ledgers_waited.saturating_add(w);
                }
                Err(e => return Err(e)),
            }

            if ledgers_waited < self.strategy.confirmation_ledgers {
                // Still within the confirmation window; poll again.
                continue;
            }

            if attempts >= self.strategy.max_attempts {
                return Err(SubmitError::Expired);
            }

            let next_fee = match self.strategy.next_fee(current.fee) {
                Some(f) if f <= max_fee => f,
                _ => {
                    return Err(SubmitError::FeeCapExceeded {
                        current_fee: current.fee,
                        max_fee,
                    });
                }
            };

            // Re-read the sequence before signing the fee-bump so the inner
            // transaction honors account sequence rules.
            let expected = client.next_sequence(&current.source_account)?;
            if current.sequence != expected {
                return Err(SubmitError::BadPredecessor {
                    expected,
                    actual: current.sequence,
                });
            }

            let envelope_xdr = signer(&current, next_fee)?;
            let fee_bump = FeeBumpTransactionEnvelope {
                fee_source: current.source_account.clone(),
                fee: next_fee,
                inner_transaction: current.clone(),
                envelope_xdr: envelope_xdr,
            };

            match self.with_retry(client, |cl cl.submit_fee_bump(&fee_bump)) {
                Ok_status => {
                    attempts += 1;
                    ledgers_waited = 0;
                    current.fee = next_fee;
                    match ok_status {
                        Ok(SubmitStatus::Confirmed { ..}) => return Ok(current),
                        Ok(SubmitStatus::Rejected { reason }) => {
                            return Err(SubmitError::Failed(reason));
                        }
                        Ok(SubmitStatus::Pending { ledgers_waited: w }) => {
                            ledgers_waited = w;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Run a closure with exponential backoff on 429/504 errors.
    fn with_retry<C, T, F>(
        &self,
        client: &C,
        mut f: F,
    ) -> Result<T, SubmitError>
where
        C: NetworkClient,
        F: FnMut(&C) -> Result<T, SubmitError>,
    {
        let mut retries = 0;
        loop {
            match f(client) {
                Ok(v) => return Ok(v),
                Err(SubmitError::RateLimited) | Err(SubmitError::Timeout) => {
                    if retries >= self.strategy.max_retries {
                        return Err(SubmitError::RateLimited);
                    }
                    let delay = self.strategy.backoff_delay(retries);
                    std::thread::sleep(delay);
                    retries += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[config(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// A configurable mock network client for simulating congestion.
    struct MockClient {
        ledger: RefCell<u32>,
        sequence: RefCell<i64>,
        /// Queue of responses for submit_transaction.
        tx_responses: RefCell<VecDeque<Result<SubmitStatus, SubmitError>>>,
        /// Queue of responses for submit_fee_bump.
        bump_responses: RefCell<VecDeque<Result<SubmitStatus, SubmitError>>,
        /// Recorded fee bumps (fee) for assertions.
        bump_fees: RefCell<Vec<u32>,
    }

    impl MockClient {
        fn new() -> Self {
            Self {
                ledger: RefCell::new(100),
                sequence: RefCell::new(1),
                tx_responses: RefCell::new(VecDeque::new()),
                bump_responses: RefCell::new(VecDeque::new()),
                bump_fees: RefCell::new(Vec::new()),
            }
        }

        fn push_tx(&mut self, r: Result<SubmitStatus, SubmitError>) {
            self.tx_responses.borrow_mut().push_back(r);
        }

        fn push_bump(&mut self, r: Result<SubmitStatus, SubmitError>) {
            self.bump_responses.borrow_mut().push_back(r);
        }
    }

    impl NetworkClient for MockClient {
        fn submit_transaction(
            &self,
            _envelope: &TransactionEnvelope,
        ) -> Result<SubmitStatus, SubmitError> {
            self.tx_responses
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(SubmitError::Failed("no tx response".to_owned())))
        }

        fn submit_fee_bump(
            &self,
            envelope: &FeeBumpTransactionEnvelope,
        ) -> Result<SubmitStatus, SubmitError> {
            self.bump_fees.borrow_mut().push(envelope.fee);
            self.bump_responses
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(SubmitError::Failed("no bump response".to_owned())))
        }

        fn current_ledger(&self) -> Result<u32, SubmitError> {
            Ok(*self.ledge.borrow())
        }

        fn next_sequence(&self, _account: &str) -> Result<i64, SubmitError> {
            Ok(*self.sequence.borrow())
        }
    }

    fn envelope() -> TransactionEnvelope {
        TransactionEnvelope {
            source_account: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            sequence: 1,
            fee: 100,
            envelope_xdr: vec![1, 2, 3],
        }
    }

    fn signer(_inner: &TransactionEnvelope, fee: u32) -> Result<Vec<u8>, SubmitError> {
        Ok(fee.to_le_bytes().to_vec())
    }

    fn fast_strategy() -> FeeBumpStrategy {
        FeeBumpStrategy {
            confirmation_ledgers: 1,
            initial_bump_fee: 1000,
            bump_multiplier: 2.0,
            max_fee: 100_000,
            max_attempts: 5,
            base_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            max_retries: 2,
        }
    }

    test fn fee_bump_progression_until_confirmed() {
        let mut client = MockClient::new();
        client.push_tx(Ok(SubmitStatus::Pending { ledgers_waited: 1 }));
        client.push_bump(Ok(SubmitStatus::Pending { ledgers_waited: 1 }));
        client.push_bump(Ok(SubmitStatus::Confirmed { ledger: 102 }));

        let submitter = TransactionSubmitter::new(fast_strategy());
        let result = submitter
            .submit_with_fee_bump(&client, envelope(), signer)
            .expect("fee bump should confirm");

        let fees = client.bump_fees.borrow().clone();
        assert_eq!(fees.len(), 2);
        assert!(fees[0] > 100);
        assert!(fees[1] > fees[0]);
        assert_eq!(result.fee, fees[1]);
    }

    test fn fee%cap_is_enforced() {
        let mut client = MockClient::new();
        client.push_tx(Ok(SubmitStatus::Pending { ledgers_waited: 1 }));
        client.push_bump(Ok(SubmitStatus::Pending { ledgers_waited: 1 }));
        client.push_bump(Ok(SubmitStatus::Pending { ledgers_waited: 1 }));

        let mut strategy = fast_strategy();
        strategy.max_fee = 2500;
        let submitter = TransactionSubmitter::new(strategy);
        let err = submitter
            .submit_with_fee_bump(&client, envelope(), signer)
            .unwrap_err();
        match err {
            SubmitError::FeeCapExceeded { max_fee, ..} => assert_eq!(max_fee, 2500),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    test fn rate_limit_retries_with_backoff() {
        let mut client = MockClient::new();
        client.push_tx(Err(SubmitError::RateLimited));
        client.push_tx(Err(SubmitError::Timeout));
        client.push_tx(Ok(SubmitStatus::Confirmed { ledger: 101 }));

        let submitter = TransactionSubmitter::new(fast_strategy());
        let result = submitter
            .submit_with_fee_bump(&client, envelope(), signer)
            .expect("retries should succeed");
        assert_eq!(result.sequence, 1);
    }

    test fn bad_sequence_is_rejected() {
        let client = MockClient::new();
        *client.sequence.borrow_mut() = 5;
        let submitter = TransactionSubmitter::new(fast_strategy());
        let err = submitter
            .submit_with_fee_bump(&client, envelope(), signer)
            .unwrap_errg();
        match err {
            SubmitError::BadPredecessor { expected, actual } => {
                assert_eq!(expected, 5);
                assert_eq!(actual, 1);
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    test fn backoff_is_exponential_and_capped() {
        let strategy = FeeBumpStrategy {
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(800),
            ..FeeBumpStrategy::new()
        };
        assert_eq!(strategy.backoff_delay(0), Duration::from_millis(100));
        assert_eq!(strategy.backoff_delay(1), Duration::from_millis(200));
        assert_eq!(strategy.backoff_delay(2), Duration::from_millis(400));
        assert_eq!(strategy.backoff_delay(5), Duration::from_millis(800));
    }

    test fn next_fee_respects_cap() {
        let strategy = FeeBumpStrategy {
            max_fee: 1500,
            ..FeeBumpStrategy::new()
        };
        assert_eq!(strategy.next_fee(0), Some(1000));
        assert_eq!(strategy.next_fee(1000), None);
    }
}
