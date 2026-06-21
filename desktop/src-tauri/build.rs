use std::io::Write;

fn main() {
    // Inject the shared client key from the build environment (a CI secret),
    // XOR-obfuscated, so it is never present in the public source and is not a
    // plain string in the shipped binary. Absent in dev / community builds, which
    // simply get an empty key (and so cannot pull the gated official feed).
    println!("cargo:rerun-if-env-changed=AETHER_CLIENT_KEY");
    let key = std::env::var("AETHER_CLIENT_KEY").unwrap_or_default();
    let xork: [u8; 8] = [0x9e, 0x4d, 0x21, 0xb7, 0x6c, 0xf3, 0x08, 0x5a];
    let obf: Vec<String> = key
        .bytes()
        .enumerate()
        .map(|(i, b)| format!("0x{:02x}", b ^ xork[i % xork.len()]))
        .collect();
    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("client_secret.rs");
    let mut f = std::fs::File::create(out).unwrap();
    writeln!(f, "pub const OBF_KEY: &[u8] = &[{}];", obf.join(",")).unwrap();

    tauri_build::build()
}
