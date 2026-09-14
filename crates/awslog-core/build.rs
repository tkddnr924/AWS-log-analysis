use std::path::PathBuf;

/// Embeds `rules/*.yar` (repo root) into the crate as `SHIPPED_RULES`, so
/// the app is one executable with no rules directory beside it (docs/07).
fn main() {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    println!("cargo:rerun-if-changed={}", source.display());

    let mut files: Vec<PathBuf> = std::fs::read_dir(&source)
        .expect("read shipped rules dir")
        .map(|entry| entry.expect("rules dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yar"))
        .collect();
    // Deterministic order so rule precedence and reports are reproducible.
    files.sort();

    let mut generated = String::from("pub const SHIPPED_RULES: &[(&str, &str)] = &[\n");
    for path in &files {
        println!("cargo:rerun-if-changed={}", path.display());
        let name = path.file_name().expect("file name").to_string_lossy();
        generated.push_str(&format!(
            "    ({name:?}, include_str!({:?})),\n",
            path.display().to_string()
        ));
    }
    generated.push_str("];\n");

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("shipped_rules.rs");
    std::fs::write(out, generated).expect("write shipped_rules.rs");
}
