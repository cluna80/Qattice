//! Shared execution framework for institutional blockchain templates.
//!
//! # Privacy invariant
//! No real patient, student, inmate, or employee data is stored in chain state.
//! All `StateEntry` values are commitment hashes (hex-encoded SHA-256) or
//! policy metadata. Applications must keep plaintext data off-chain.
//!
//! # Cross-template isolation
//! A `TxBody` variant from one template is rejected by any other template's
//! executor. Errors are deterministic and do not leak state.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::templates::InstitutionalTemplate;

// ── State types ───────────────────────────────────────────────────────────────

/// A single key-value entry in the chain's state store.
/// Keys are namespaced by template: `edu/`, `hc/`, `cor/`, `ent/`.
/// Values are hex-encoded commitment hashes or small metadata strings.
/// Values MUST NOT contain identifiable personal information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateEntry {
    pub key: String,
    pub value: String,
}

impl StateEntry {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self { key: key.into(), value: value.into() }
    }
}

/// Mutable view of the template's key-value state store for one block.
#[derive(Debug, Default, Clone)]
pub struct TemplateState {
    inner: HashMap<String, String>,
}

impl TemplateState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.inner.get(key).map(|s| s.as_str())
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.inner.insert(key.into(), value.into());
    }

    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.inner.remove(key)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.inner.contains_key(key)
    }

    pub fn entries(&self) -> Vec<StateEntry> {
        let mut v: Vec<StateEntry> = self.inner.iter()
            .map(|(k, v)| StateEntry::new(k, v))
            .collect();
        v.sort_by(|a, b| a.key.cmp(&b.key));
        v
    }
}

// ── Execution result ──────────────────────────────────────────────────────────

/// Result of applying a single transaction to template state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxResult {
    pub success: bool,
    pub error: Option<String>,
    /// State mutations produced by this transaction.
    pub mutations: Vec<StateEntry>,
}

impl TxResult {
    pub fn ok(mutations: Vec<StateEntry>) -> Self {
        Self { success: true, error: None, mutations }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self { success: false, error: Some(msg.into()), mutations: vec![] }
    }

    pub fn cross_template_rejected() -> Self {
        Self::err("cross-template transaction rejected")
    }
}

// ── Execution context ─────────────────────────────────────────────────────────

/// Contextual metadata passed to each transaction application.
/// Does not contain private data; used for policy checks only.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub chain_id: String,
    pub block_height: u64,
    pub submitter_id: String,
    pub template: InstitutionalTemplate,
}

impl ExecutionContext {
    pub fn new(
        chain_id: impl Into<String>,
        block_height: u64,
        submitter_id: impl Into<String>,
        template: InstitutionalTemplate,
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            block_height,
            submitter_id: submitter_id.into(),
            template,
        }
    }
}

// ── Template domain label ─────────────────────────────────────────────────────

/// Template-scoped domain label used to tag transactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateDomain {
    pub chain_id: String,
    pub template_id: String,
}

impl TemplateDomain {
    pub fn new(chain_id: impl Into<String>, template_id: impl Into<String>) -> Self {
        Self { chain_id: chain_id.into(), template_id: template_id.into() }
    }

    pub fn accepts(&self, other: &Self) -> bool {
        self.chain_id == other.chain_id && self.template_id == other.template_id
    }
}

// ── Transaction body ──────────────────────────────────────────────────────────

/// Top-level transaction envelope dispatched to a template executor.
///
/// Each variant maps to exactly one template. The executor for that template
/// accepts it; all others return `TxResult::cross_template_rejected()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "template", rename_all = "snake_case")]
pub enum TxBody {
    Healthcare(crate::healthcare::HealthcareTx),
    Corrections(crate::corrections::CorrectionsTx),
    Education(crate::education::EducationTx),
    Enterprise(crate::enterprise::EnterpriseTx),
}

impl TxBody {
    /// Template identifier string for routing and logging.
    pub fn template_id(&self) -> &'static str {
        match self {
            Self::Healthcare(_)  => "healthcare-l1",
            Self::Corrections(_) => "corrections-l1",
            Self::Education(_)   => "education-l1",
            Self::Enterprise(_)  => "enterprise-l1",
        }
    }
}
