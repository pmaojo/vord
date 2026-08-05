use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub enum KickoffError {
    UnknownTemplate(String),
    CreateDirFailed(String, std::io::Error),
    WriteFileFailed(String, std::io::Error),
}

impl fmt::Display for KickoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTemplate(t) => write!(
                f,
                "unknown template {:?}. Supported templates: react-bulletproof, rust-clean, python-clean, typescript-clean",
                t
            ),
            Self::CreateDirFailed(dir, err) => {
                write!(f, "failed to create directory {:?}: {}", dir, err)
            }
            Self::WriteFileFailed(file, err) => {
                write!(f, "failed to write file {:?}: {}", file, err)
            }
        }
    }
}

impl std::error::Error for KickoffError {}

pub fn run_kickoff(template: &str, target_dir: &Path) -> Result<(), KickoffError> {
    match template.to_lowercase().as_str() {
        "react-bulletproof" | "react" => kickoff_react_bulletproof(target_dir),
        "rust-clean" | "rust" => kickoff_rust_clean(target_dir),
        "python-clean" | "python" => kickoff_python_clean(target_dir),
        "typescript-clean" | "ts" => kickoff_typescript_clean(target_dir),
        "fullstack-hexagonal" | "hexagonal" => kickoff_fullstack_hexagonal(target_dir),
        other => Err(KickoffError::UnknownTemplate(other.to_string())),
    }
}

fn kickoff_react_bulletproof(base: &Path) -> Result<(), KickoffError> {
    let dirs = [
        "src/assets",
        "src/components",
        "src/config",
        "src/features/auth/api",
        "src/features/auth/components",
        "src/features/auth/hooks",
        "src/features/auth/routes",
        "src/features/auth/types",
        "src/hooks",
        "src/providers",
        "src/routes",
        "src/types",
        "src/utils",
    ];

    for d in &dirs {
        let p = base.join(d);
        fs::create_dir_all(&p)
            .map_err(|e| KickoffError::CreateDirFailed(p.display().to_string(), e))?;
    }

    let auth_index = base.join("src/features/auth/index.ts");
    let auth_index_content = "// Public API for the auth feature module\nexport * from './components';\nexport * from './types';\n";
    fs::write(&auth_index, auth_index_content)
        .map_err(|e| KickoffError::WriteFileFailed(auth_index.display().to_string(), e))?;

    let vord_toml = base.join("vord.toml");
    if !vord_toml.exists() {
        let default_config = r#"# vord configuration for Bulletproof React project
[profile]
name = "recommended"

[rules]
"react:bulletproof-folder-structure" = "major"
"react:feature-directory-isolation" = "major"
"react:no-default-export" = "minor"
"react:no-fetch-in-useeffect" = "major"
"naming:component-pascal-case" = "minor"
"naming:event-handler-prefix" = "minor"
"#;
        fs::write(&vord_toml, default_config)
            .map_err(|e| KickoffError::WriteFileFailed(vord_toml.display().to_string(), e))?;
    }

    println!(
        "Successfully initialized Bulletproof React template at {:?}",
        base
    );
    Ok(())
}

fn kickoff_rust_clean(base: &Path) -> Result<(), KickoffError> {
    let dirs = ["core/src", "infra/src", "bin/cli/src", "tests"];

    for d in &dirs {
        let p = base.join(d);
        fs::create_dir_all(&p)
            .map_err(|e| KickoffError::CreateDirFailed(p.display().to_string(), e))?;
    }

    let lib_rs = base.join("core/src/lib.rs");
    fs::write(&lib_rs, "//! Pure domain core\n")
        .map_err(|e| KickoffError::WriteFileFailed(lib_rs.display().to_string(), e))?;

    let vord_toml = base.join("vord.toml");
    if !vord_toml.exists() {
        let default_config = r#"# vord configuration for clean Rust project
[profile]
name = "recommended"

[rules]
"rust:disallow-unwrap-expect" = "major"
"rust:disallow-panic-macros" = "major"
"naming:rust-convention" = "minor"
"#;
        fs::write(&vord_toml, default_config)
            .map_err(|e| KickoffError::WriteFileFailed(vord_toml.display().to_string(), e))?;
    }

    println!("Successfully initialized clean Rust template at {:?}", base);
    Ok(())
}

fn kickoff_python_clean(base: &Path) -> Result<(), KickoffError> {
    let dirs = ["src/domain", "src/infrastructure", "src/api", "tests"];

    for d in &dirs {
        let p = base.join(d);
        fs::create_dir_all(&p)
            .map_err(|e| KickoffError::CreateDirFailed(p.display().to_string(), e))?;
        let init_file = p.join("__init__.py");
        fs::write(&init_file, "")
            .map_err(|e| KickoffError::WriteFileFailed(init_file.display().to_string(), e))?;
    }

    let vord_toml = base.join("vord.toml");
    if !vord_toml.exists() {
        let default_config = r#"# vord configuration for clean Python project
[profile]
name = "recommended"

[rules]
"python:missing-type-annotations" = "major"
"python:unclosed-open-file" = "major"
"python:modern-type-syntax" = "minor"
"#;
        fs::write(&vord_toml, default_config)
            .map_err(|e| KickoffError::WriteFileFailed(vord_toml.display().to_string(), e))?;
    }

    println!(
        "Successfully initialized clean Python template at {:?}",
        base
    );
    Ok(())
}

fn kickoff_typescript_clean(base: &Path) -> Result<(), KickoffError> {
    let dirs = [
        "src/domain",
        "src/infrastructure",
        "src/api",
        "src/types",
        "tests",
    ];

    for d in &dirs {
        let p = base.join(d);
        fs::create_dir_all(&p)
            .map_err(|e| KickoffError::CreateDirFailed(p.display().to_string(), e))?;
    }

    let vord_toml = base.join("vord.toml");
    if !vord_toml.exists() {
        let default_config = r#"# vord configuration for clean TypeScript project
[profile]
name = "recommended"

[rules]
"naming:boolean-prefix" = "minor"
"ai-agent:no-wildcard-reexports" = "major"
"#;
        fs::write(&vord_toml, default_config)
            .map_err(|e| KickoffError::WriteFileFailed(vord_toml.display().to_string(), e))?;
    }

    println!(
        "Successfully initialized clean TypeScript template at {:?}",
        base
    );
    Ok(())
}

fn kickoff_fullstack_hexagonal(base: &Path) -> Result<(), KickoffError> {
    let dirs = [
        "backend/src/domain/entities",
        "backend/src/domain/ports",
        "backend/src/infrastructure/adapters",
        "backend/src/infrastructure/web",
        "frontend/src/features",
        "frontend/src/shared",
        "spec",
    ];

    for d in &dirs {
        let p = base.join(d);
        fs::create_dir_all(&p)
            .map_err(|e| KickoffError::CreateDirFailed(p.display().to_string(), e))?;
    }

    let spec_yaml = base.join("spec/architecture.yaml");
    if !spec_yaml.exists() {
        let spec_content = r#"name: fullstack-hexagonal-app
version: 1.0.0
nodes:
  - name: user-domain
    type: domain
    contract: "ports/user_service.rs"
  - name: auth-adapter
    type: adapter
    depends_on:
      - user-domain
"#;
        fs::write(&spec_yaml, spec_content)
            .map_err(|e| KickoffError::WriteFileFailed(spec_yaml.display().to_string(), e))?;
    }

    let vord_toml = base.join("vord.toml");
    if !vord_toml.exists() {
        let default_config = r#"# vord configuration for Fullstack Hexagonal project
[profile]
name = "recommended"

[rules]
"architecture:hexagonal-layer-violation" = "blocking"
"architecture:graph-circular-dependency" = "blocking"
"rust:typeshare-dto-sync" = "major"
"#;
        fs::write(&vord_toml, default_config)
            .map_err(|e| KickoffError::WriteFileFailed(vord_toml.display().to_string(), e))?;
    }

    println!(
        "Successfully initialized Fullstack Hexagonal template at {:?}",
        base
    );
    Ok(())
}
