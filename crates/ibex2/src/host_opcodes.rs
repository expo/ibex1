//! Host-operation assignments shared by platform dispatchers and their tests.
//!
//! Linux Intl is conditionally compiled, but its assignments live here on
//! every platform so the global collision test can still cover them on macOS.

#[cfg_attr(not(all(feature = "hermes", target_os = "linux")), allow(dead_code))]
pub(crate) mod intl_number {
    pub(crate) const CREATE: u32 = 90;
    pub(crate) const FORMAT: u32 = 91;
    pub(crate) const FORMAT_PARTS: u32 = 92;
    pub(crate) const PART_TYPE: u32 = 93;
    pub(crate) const PART_VALUE: u32 = 94;
    pub(crate) const RESOLVED: u32 = 95;
    pub(crate) const SUPPORTED_LOCALES: u32 = 96;
    pub(crate) const CURRENCY_DIGITS: u32 = 98;

    #[cfg(test)]
    pub(crate) const ALL: &[u32] = &[
        CREATE,
        FORMAT,
        FORMAT_PARTS,
        PART_TYPE,
        PART_VALUE,
        RESOLVED,
        SUPPORTED_LOCALES,
        CURRENCY_DIGITS,
    ];
}

#[cfg_attr(not(all(feature = "hermes", target_os = "linux")), allow(dead_code))]
pub(crate) mod intl_case {
    pub(crate) const MAP: u32 = 97;
    #[cfg(test)]
    pub(crate) const ALL: &[u32] = &[MAP];
}

#[cfg_attr(not(all(feature = "hermes", target_os = "linux")), allow(dead_code))]
pub(crate) mod intl_datetime {
    pub(crate) const CREATE: u32 = 130;
    pub(crate) const FORMAT: u32 = 131;
    pub(crate) const FORMAT_PARTS: u32 = 132;
    pub(crate) const PART_TYPE: u32 = 133;
    pub(crate) const PART_VALUE: u32 = 134;
    pub(crate) const RESOLVED: u32 = 135;
    pub(crate) const SUPPORTED_LOCALES: u32 = 136;
    pub(crate) const CANONICAL_TIME_ZONE: u32 = 137;

    #[cfg(test)]
    pub(crate) const ALL: &[u32] = &[
        CREATE,
        FORMAT,
        FORMAT_PARTS,
        PART_TYPE,
        PART_VALUE,
        RESOLVED,
        SUPPORTED_LOCALES,
        CANONICAL_TIME_ZONE,
    ];
}

pub(crate) mod sqlite_async {
    pub(crate) const OPEN: u32 = 150;
    pub(crate) const PREPARE: u32 = 151;
    pub(crate) const EXECUTE: u32 = 152;
    pub(crate) const QUERY: u32 = 153;
    pub(crate) const STATEMENT_EXECUTE: u32 = 154;
    pub(crate) const STATEMENT_QUERY: u32 = 155;
    pub(crate) const TRANSACTION: u32 = 156;
    pub(crate) const CLOSE: u32 = 157;
    pub(crate) const STATEMENT_CLOSE: u32 = 158;

    #[cfg(test)]
    pub(crate) const ALL: &[u32] = &[
        OPEN,
        PREPARE,
        EXECUTE,
        QUERY,
        STATEMENT_EXECUTE,
        STATEMENT_QUERY,
        TRANSACTION,
        CLOSE,
        STATEMENT_CLOSE,
    ];
}

pub(crate) mod subtle {
    pub(crate) const DIGEST: u32 = 160;
    pub(crate) const IMPORT_KEY: u32 = 161;
    pub(crate) const EXPORT_KEY: u32 = 162;
    pub(crate) const GENERATE_KEY: u32 = 163;
    pub(crate) const SIGN: u32 = 164;
    pub(crate) const VERIFY: u32 = 165;
    pub(crate) const ENCRYPT: u32 = 166;
    pub(crate) const DECRYPT: u32 = 167;
    pub(crate) const DERIVE_BITS: u32 = 168;
    pub(crate) const DERIVE_KEY: u32 = 169;

    #[cfg(test)]
    pub(crate) const ALL: &[u32] = &[
        DIGEST,
        IMPORT_KEY,
        EXPORT_KEY,
        GENERATE_KEY,
        SIGN,
        VERIFY,
        ENCRYPT,
        DECRYPT,
        DERIVE_BITS,
        DERIVE_KEY,
    ];
}
