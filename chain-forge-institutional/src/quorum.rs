//! BFT quorum calculation for institutional chains.
//!
//! Implements the standard `n >= 3f + 1` Byzantine fault model where:
//!   n = total validators
//!   f = maximum tolerated Byzantine (faulty/adversarial) validators
//!   quorum = n - f (minimum votes needed to make progress)

use crate::{InstError, InstResult};
use serde::{Deserialize, Serialize};

/// Byzantine fault tolerance parameters for a validator set of size `n`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BftParams {
    /// Total number of validators.
    pub n: u32,
    /// Maximum number of Byzantine (faulty) validators tolerated.
    pub f: u32,
    /// Minimum votes required to reach consensus (quorum).
    pub quorum: u32,
}

impl BftParams {
    /// Verify the standard BFT invariant: n >= 3f + 1 and quorum = n - f.
    pub fn verify_invariant(&self) -> bool {
        self.n >= 3 * self.f + 1 && self.quorum == self.n - self.f
    }
}

/// Compute BFT quorum parameters for `n` validators.
///
/// Requires n >= 4 (the minimum to tolerate f=1 Byzantine fault with the
/// standard 3f+1 model). Returns an error for n < 4.
///
/// # Examples
/// ```
/// use chain_forge_institutional::quorum::bft_quorum;
/// let p = bft_quorum(7).unwrap();
/// assert_eq!(p.f, 2);
/// assert_eq!(p.quorum, 5);
/// ```
pub fn bft_quorum(n: u32) -> InstResult<BftParams> {
    if n < 4 {
        return Err(InstError::InvalidValidatorCount {
            count: n,
            reason: format!(
                "n={n} is below the minimum of 4 required for BFT quorum (3f+1 with f≥1)"
            ),
        });
    }
    // f = floor((n - 1) / 3)
    let f = (n - 1) / 3;
    // quorum = n - f  (equivalently ceil((2n + 1) / 3))
    let quorum = n - f;
    let params = BftParams { n, f, quorum };
    debug_assert!(params.verify_invariant(), "BFT invariant violated for n={n}");
    Ok(params)
}

#[cfg(test)]
mod quorum_tests {
    use super::*;

    #[test]
    fn test_bft_quorum_table() {
        // Exact values from the Phase 2 directive.
        let cases = [(4u32, 1u32, 3u32), (7, 2, 5), (10, 3, 7)];
        for (n, expected_f, expected_quorum) in cases {
            let p = bft_quorum(n).unwrap_or_else(|e| panic!("bft_quorum({n}) failed: {e}"));
            assert_eq!(p.f, expected_f, "n={n}: expected f={expected_f}, got {}", p.f);
            assert_eq!(p.quorum, expected_quorum, "n={n}: expected quorum={expected_quorum}, got {}", p.quorum);
            assert!(p.verify_invariant(), "BFT invariant failed for n={n}");
        }
    }

    #[test]
    fn test_bft_quorum_rejects_insufficient() {
        for n in [1u32, 2, 3] {
            assert!(
                bft_quorum(n).is_err(),
                "n={n} should be rejected (below minimum 4)"
            );
        }
    }

    #[test]
    fn test_bft_quorum_larger_sets() {
        // Spot-check larger sets still satisfy the invariant.
        for n in [13u32, 19, 31, 100] {
            let p = bft_quorum(n).unwrap();
            assert!(p.verify_invariant(), "BFT invariant violated for n={n}");
            assert!(p.f >= 1);
            assert!(p.quorum > p.n / 2, "quorum must be > n/2 for safety");
        }
    }
}
