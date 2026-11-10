// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! Subresource Integrity (SRI) metadata parsing and body validation.

/// Hash algorithm named in a Subresource Integrity metadata entry.
enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    /// Parse the algorithm name (case-insensitive, e.g. "sha256").
    fn parse(name: &str) -> Option<HashAlg> {
        match name.to_ascii_lowercase().as_str() {
            "sha256" => Some(HashAlg::Sha256),
            "sha384" => Some(HashAlg::Sha384),
            "sha512" => Some(HashAlg::Sha512),
            _ => None,
        }
    }
    /// Strength ordering — stronger algorithms win per the SRI spec.
    fn strength(&self) -> u8 {
        match self {
            HashAlg::Sha256 => 0,
            HashAlg::Sha384 => 1,
            HashAlg::Sha512 => 2,
        }
    }
}

/// Validate `body` against a Subresource Integrity `integrity` metadata string
/// (space-separated `alg-base64value` tokens). Returns `Err` with a message if
/// the body matches none of the (parsable) entries — per spec, the response is
/// rejected in that case.
pub(super) fn check_integrity(body: &[u8], integrity: &str) -> Result<(), String> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256, Sha384, Sha512};

    // Collect every well-formed (`alg-value`) entry. A value may be base64
    // (standard, padded or unpadded) or base64url (with or without padding);
    // try each decoder in turn. Entries are kept with their algorithm strength
    // so we can try the strongest first, per the SRI spec.
    let mut entries: Vec<(u8, HashAlg, Vec<u8>)> = Vec::new();
    for tok in integrity.split_whitespace() {
        let (alg_name, b64) = match tok.split_once('-') {
            Some((a, b)) => (a, b),
            None => continue,
        };
        let alg = match HashAlg::parse(alg_name) {
            Some(a) => a,
            None => continue,
        };
        let expected = STANDARD
            .decode(b64)
            .or_else(|_| STANDARD_NO_PAD.decode(b64))
            .or_else(|_| URL_SAFE.decode(b64))
            .or_else(|_| URL_SAFE_NO_PAD.decode(b64));
        let expected = match expected {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        entries.push((alg.strength(), alg, expected));
    }
    if entries.is_empty() {
        return Err(format!(
            "integrity metadata contained no usable entry: {integrity}"
        ));
    }

    // SRI "get the strongest metadata": only entries using the strongest
    // algorithm present are considered. Weaker entries are discarded, so a
    // valid sha384 cannot rescue an invalid sha512 in the same metadata set.
    let strongest = entries.iter().map(|(s, _, _)| *s).max().unwrap_or(0);

    // Within the strongest set any single match is enough to pass.
    for (strength, alg, expected) in &entries {
        if *strength != strongest {
            continue;
        }

        let actual: Vec<u8> = match alg {
            HashAlg::Sha256 => Sha256::digest(body).to_vec(),
            HashAlg::Sha384 => Sha384::digest(body).to_vec(),
            HashAlg::Sha512 => Sha512::digest(body).to_vec(),
        };
        if &actual == expected {
            return Ok(());
        }
    }
    Err(format!(
        "subresource integrity check failed: no entry matched for {}",
        integrity
    ))
}
