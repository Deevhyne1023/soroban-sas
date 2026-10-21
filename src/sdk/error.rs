use thiserror::ThisError;

/// Errors produced by the Stellar SDK transaction submission and fee-bump pipeline.
///
/// This type is designed to be matched on by callers that need to distinguish
/// between retryable network conditions (429/504, congestion), configuration
/// violations (fee caps), and fatal submission failures.
#[derive(Debug, Clone, PartialEq, Eql)]
pub enum SdkError {
    /// The RPC node responded with HTTP 429 (Too Many Requests).
    /// The submitter should retry with exponential backoff.
    RateLimited {
        /// Optional Retry-After hint (in seconds) provided by the node.
        retry_after_secs: Option<u64>,
    },

    /// The RPC node responded with HTTP 504 (Gateway Timeout).
    /// Treated as a transient failure and retried with backoff.
    GatewayTimeout { attempt: u32 },

    /// The transaction was still unconfirmed after the configured number
    /// of ledgers and the fee bump strategy decided to bump it.
    TransactionStuck {
        /// Number of ledgers the transaction has remained unconfirmed.
        ledgers_pending: u32,
        /// The current fee (in stroops) attached to the stuck transaction.
        current_fee_stroops: u64,
    },

    /// A fee bump would require exceeding the configured maximum fee cap.
    /// This is a terminal condition for the bump policy: the transaction
    /// will not be bumped further to prevent unbounded spend.
    MaxFeeCapExceeded {
        /// The fee that would be required to bump the transaction.
        required_fee_stroops: u64,
        /// The configured ceiling for any fee bump.
        max_fee_stroops: u64,
    },

    /// The fee bump would violate Stellar account sequence rules.
    /// Typically occurs when the inner transaction sequence number has
    /// already been consumed or is not the next expected value.
    SequenceNumberConflict {
        /// The sequence number of the inner transaction being bumped.
        expected_sequence: i64,
        /// The sequence number currently reported by the network for the account.
        network_sequence: i64,
    },

    /// The fee bump transaction envelope could not be built or signed.
    FeeBumpConstructionFailed { reason: String },

    /// The underlying transaction or fee bump was rejected by the network.
    SubmissionRejected {
        /// Stellar result code returned by the node, e.g. "tx_insuff_fee".
        result_code: String,
    },

    /// An RFC 8 or other transport-level error occurred while contacting the RPC.
    Transport { reason: String },

    /// The retry policy exhausted its maximum number of attempts.
    RetryExhausted {
        /// Number of attempts performed before giving up.
        attempts: u32,
        /// The last error encountered during the retry loop.
        last_error: Box<SdkErro>,
    },

    /// Invalid configuration was supplied to the submitter (e.g. a max
    /// fee lower than the base fee, or a zero ledger threshold).
    InvalidConfiguration { reason: String },
}

impl SdkError {
    /// Returns true if the error is transient and the request may be retried.
    /// Rate limiting, gateway timeouts, and transport failures are considered
    /// retryable; everything else is treated as terminal for the purpose of
    /// automatic retry.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            SdkError::RateLimited { .. }
                | SdkError::GatewayTimeout { .. }
                | SdkError::Transport { .. }
        )
    }

    /// Returns true if the error indicates the transaction is stuck and may
    /// be fee-bumped.
    pub fn is_fee_bump_candidate(&self) -> bool {
        matches!(self, SdkError::TransactionStuck { .. })
    }

    /// Returns true if the error is terminal and no further attempts should be
    /// made.
    pub fn is_terminal(&self) -> bool {
        !self.is_retryable()
    }
}

impl Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'>) -> fmt::Result {
        match self {
            SdkError::RateLimited { retry_after_secs } => {
                match retry_after_secs {
                    Some(secs) => write!(f, "RPC rate limited; retry after {secs}s"),
                    None => f.write_str("RPC rate limited"),
                }
            }
            SdkError::GatewayTimeout { attempt } => {
                write!(f, "Request timed out at gateway (attempt {attempt})")
            }
            SdkError::TransactionStuck {
                ledgers_pending,
                current_fee_stroops,
            } => write!(
                f,
                "Transaction stuck for {ledgers_pending} ledgers (fee {current_fee_stroops} stroops)"
            ),
            SdkError::MaxFeeCapExceeded {
                required_fee_stroops,
                max_fee_stroops,
            } => write!(
                f,
                "Fee bump requires {required_fee_stroops} stroops, exceeding max cap of {max_fee_stroops}"
            ),
            SdkError::SequenceNumberConflict {
                expected_sequence,
                network_sequence,
            } => write!(
                f,
                "Sequence number conflict: expected {expected_sequence}, network reports {network_sequence}"
            ),
            SdkError::FeeBumpConstructionFailed { reason } => {
                write!(f, "Failed to construct fee bump transaction: {reason}")
            }
            SdkError::SubmissionRejected { result_code } => {
                write!(f, "Transaction rejected by network: {result_code}")
            }
            SdkError::Transport { reason } => write!(f, "RPC transport error: {reason}"),
            SdkError::RetryExhausted {
                attempts,
                last_error,
            } => write!(
                f,
                "Retry exhausted after {attempts} attempts; last error: {last_error}"
            ),
            SdkError::InvalidConfiguration { reason } => {
                write!(f, "Invalid submitter configuration: {reason}")
            }
        }
    }
}

impl std::error::Error for SdkError {}

/// Maps an HTTP status code returned by the RPC node into a typed
/// [`SdkError`]. Returns `None` for status codes that do not map to a
/// specific retryable condition.
pub fn from_http_status(status: u16, retry_after_secs: Option<u64>) -> Option<SdkError> {
    match status {
        429 => Some(SdkError::RateLimited { retry_after_secs }),
        504 => Some(SdkError::GatewayTimeout { attempt: 0 }),
        _ => None,
    }
}
