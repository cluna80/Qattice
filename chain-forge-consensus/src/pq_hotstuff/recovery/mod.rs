//! Snapshot-recovery COMPONENTS (isolated; disabled). **Nothing here is wired into the operational node**: `netmsg::decode` still rejects kinds 7 to 14 as
//! unknown, the driver does not call any of this, and no snapshot is installed over the network. These are the codecs (`codec`), bounded request handling
//! (`requests`), local record formats (`records`), a directory-tree filesystem abstraction (`tree`) and the staged, generation-bound installer (`install`)
//! specified in `docs/pq-hotstuff-2/phase5-snapshot-spec.md`. Checkpoint references and rule R6 are a separate consensus change and are NOT implemented.
pub mod codec;
pub mod install;
pub mod records;
pub mod requests;
pub mod tree;
pub mod transfer;
pub mod retention;
