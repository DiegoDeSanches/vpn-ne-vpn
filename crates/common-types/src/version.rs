//! Contract-version primitives.

/// Version of an in-process public contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct ContractVersion {
    /// Breaking interface generation.
    pub major: u16,
    /// Backward-compatible interface revision.
    pub minor: u16,
}

impl ContractVersion {
    /// Creates a contract version.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Returns true when `other` can be used by a consumer compiled for `self`.
    pub const fn accepts(self, other: Self) -> bool {
        self.major == other.major && other.minor >= self.minor
    }
}

/// Initial OnionRoute Rust contract version.
pub const CONTRACT_V1: ContractVersion = ContractVersion::new(1, 0);

/// Implemented by every public component contract.
pub trait VersionedContract {
    /// Returns the contract version implemented by this instance.
    fn contract_version(&self) -> ContractVersion;
}

