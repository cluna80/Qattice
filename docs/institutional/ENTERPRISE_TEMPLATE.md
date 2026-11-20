# Enterprise L1 Template

**Template ID**: `enterprise-l1`  
**Phase**: CF-INST-004

## Purpose

Enterprise L1 chains provide a permissioned blockchain for multi-organization
consortiums needing member identity management, AI agent authorization,
supply chain provenance anchoring, and governance proposal tracking.
Sensitive business records remain off-chain.

## Privacy architecture

Trade secrets, pricing, and business-sensitive records must stay off-chain.
On-chain state contains only:
- Member identity key hashes and role assignments
- Agent capability grants
- Supply chain event commitment hashes
- Governance proposal commitment hashes

## Transaction types

### `EnrollMember`
Registers a member at `ent/member/<org_id>/<member_id>`.
Value encodes `<role>:<key_hash>`. Re-enrollment overwrites the previous entry
(allows role changes and key rotation without an explicit revocation step).

### `AuthorizeAgent`
Registers an AI agent's capability grant at `ent/agent/<org_id>/<agent_id>`.
At least one `AgentCapability` must be provided. Capabilities are:
- `ReadState` — read-only access to chain state
- `AnchorProvenance` — write supply chain provenance events
- `SubmitProposals` — submit governance proposal commitments

### `AnchorProvenance`
Writes a supply chain event at `ent/provenance/<item_id>/<block_height>`.
Multiple events at different block heights are permitted for the same item.

### `SubmitGovernanceProposal`
Writes a governance proposal anchor at `ent/proposal/<proposal_id>`.
Duplicate proposal IDs are rejected.

## Configuration (`EnterpriseConfig`)

| Field | Default | Description |
|-------|---------|-------------|
| `multi_org_governance` | `true` | Support multi-organization governance |
| `ai_agent_support` | `true` | Enable AI agent authorization |
| `supply_chain_provenance` | `true` | Enable supply chain anchoring |
| `privacy_audit` | `true` | Enforce commitment-only audit evidence |

## AI agent authorization model

Agents are granted explicit, least-privilege capability sets at authorization time.
No capability inheritance exists. Agents cannot grant capabilities to other agents.
An agent's key_hash must be a SHA-256 hash of its signing public key material.
No private keys are stored on-chain.
