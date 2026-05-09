use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn limits_template_and_installer_scope_nofile_to_oxibelt_user() -> TestResult {
    let repo_root = repo_root()?;
    let template_path = repo_root.join("kernel-extension/templates/limits.d/90-oxibelt-edge.conf");
    let template = fs::read_to_string(&template_path)?;
    assert_oxibelt_scoped_nofile_limits(&template, &template_path)?;

    let staged_root = TempRoot::new("oxibelt-kernel-extension-security")?;
    run_script(
        &repo_root,
        &repo_root.join("kernel-extension/install.sh"),
        &[
            OsStr::new("--apply"),
            OsStr::new("--root"),
            staged_root.path.as_os_str(),
            OsStr::new("--kernel-release"),
            OsStr::new("7.0.3"),
        ],
    )?;
    run_script(
        &repo_root,
        &repo_root.join("kernel-extension/verify.sh"),
        &[
            OsStr::new("--root"),
            staged_root.path.as_os_str(),
            OsStr::new("--kernel-release"),
            OsStr::new("7.0.3"),
        ],
    )?;

    let installed_path = staged_root
        .path
        .join("etc/security/limits.d/90-oxibelt-edge.conf");
    let installed = fs::read_to_string(&installed_path)?;
    assert_oxibelt_scoped_nofile_limits(&installed, &installed_path)?;

    Ok(())
}

fn repo_root() -> TestResult<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "source crate directory has no repository parent".into())
}

fn assert_oxibelt_scoped_nofile_limits(contents: &str, source: &Path) -> TestResult {
    let mut has_soft_limit = false;
    let mut has_hard_limit = false;

    for (index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }

        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() >= 3 && fields[0] == "*" && fields[2] == "nofile" {
            return Err(format!(
                "{}:{} grants nofile limits to wildcard principal '*'",
                source.display(),
                index + 1
            )
            .into());
        }

        match fields.as_slice() {
            ["oxibelt", "soft", "nofile", "1048576"] => has_soft_limit = true,
            ["oxibelt", "hard", "nofile", "1048576"] => has_hard_limit = true,
            _ => {}
        }
    }

    if !has_soft_limit {
        return Err(format!(
            "{} is missing 'oxibelt soft nofile 1048576'",
            source.display()
        )
        .into());
    }
    if !has_hard_limit {
        return Err(format!(
            "{} is missing 'oxibelt hard nofile 1048576'",
            source.display()
        )
        .into());
    }

    Ok(())
}

fn run_script(repo_root: &Path, script: &Path, args: &[&OsStr]) -> TestResult {
    let output = Command::new("/bin/sh")
        .arg(script)
        .args(args)
        .current_dir(repo_root)
        .output()?;

    if output.status.success() {
        return Ok(());
    }

    Err(format!(
        "{} failed with status {}\nstdout:\n{}\nstderr:\n{}",
        script.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(prefix: &str) -> TestResult<Self> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
