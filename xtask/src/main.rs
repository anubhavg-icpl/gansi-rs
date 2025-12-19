use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

type DynError = Box<dyn std::error::Error>;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{}", e);
        std::process::exit(-1);
    }
}

fn try_main() -> Result<(), DynError> {
    let task = env::args().nth(1);
    match task.as_deref() {
        Some("dist") => dist()?,
        _ => print_help(),
    }
    Ok(())
}

fn print_help() {
    eprintln!(
        "Tasks:

dist            builds release binaries into dist/
"
    )
}

fn dist() -> Result<(), DynError> {
    let _ = fs::remove_dir_all(dist_dir());
    fs::create_dir_all(dist_dir())?;

    dist_binary("gansi-com", "gansi_com.dll")?;
    dist_binary("gansi-cli", "gansi-cli.exe")?;

    Ok(())
}

fn dist_binary(package: &str, binary: &str) -> Result<(), DynError> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
        .current_dir(project_root())
        .args(["build", "--release", "-p", package])
        .status()?;

    if !status.success() {
        Err("cargo build failed")?;
    }

    let dst = project_root().join("target\\release").join(binary);
    fs::copy(&dst, dist_dir().join(binary))?;

    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
}

fn dist_dir() -> PathBuf {
    project_root().join("dist")
}
