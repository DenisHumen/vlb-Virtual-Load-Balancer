//! Self-update from GitHub Releases.
//!
//! `vlb update` asks the GitHub API for the newest release, downloads the
//! tarball built for this host's architecture, verifies it against the
//! published SHA-256, and swaps the running binary in place.
//!
//! # Safety properties
//!
//! Replacing the binary of a service that routes all of a site's traffic is
//! not something to do casually, so every step is defensive:
//!
//! * **Checksum before anything else.** The archive is verified against the
//!   `.sha256` asset before it is even opened as a tarball. A truncated
//!   download or a corrupted mirror can never reach the filesystem.
//! * **The new binary is proven runnable** (`vlb --version`) *before* the old
//!   one is replaced. A wrong-architecture or broken build is caught while
//!   the working binary is still in place.
//! * **The swap is atomic and reversible.** We write alongside the target
//!   (same filesystem, so `rename` is atomic), keep the previous binary as
//!   `.bak`, and restore it if the service fails to come back.
//! * **Downgrades require an explicit flag**, so a mistyped tag cannot walk
//!   a production gateway backwards.

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{info, warn};

use crate::canary::hex;
use crate::http::{self, HttpRequest, Scheme, Url};

/// Generous: release tarballs are a few MiB and the runner may be far away.
const NET_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ASSET_BYTES: usize = 64 * 1024 * 1024;
/// GitHub bounces asset downloads through a CDN; a couple of hops is normal.
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub tag: String,
    pub prerelease: bool,
    pub archive_url: String,
    pub checksum_url: Option<String>,
    pub asset_name: String,
}

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

/// The release-artifact target triple for the host we are running on.
///
/// Must match the `matrix.target` values in `.github/workflows/release.yml`,
/// which is what names the published assets.
///
/// Releases are statically linked against musl regardless of what this host
/// actually uses, so the triple is chosen by architecture alone. A glibc
/// build would carry the glibc version of whatever runner produced it —
/// currently 2.39 — and refuse to start on most machines in production.
pub fn host_target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-musl"),
        (os, arch) => bail!(
            "no published release artifact for {os}/{arch}. vlb ships Linux \
             x86_64 and aarch64 builds; on anything else, build from source \
             with `cargo build --release`."
        ),
    }
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Ask GitHub for the newest release and locate this host's artifact.
pub async fn check(repo: &str, allow_prerelease: bool) -> Result<ReleaseInfo> {
    let target = host_target()?;
    // `/releases` rather than `/releases/latest`: the latter hides
    // pre-releases entirely, and during the alpha every release is one.
    let url = format!("https://api.github.com/repos/{repo}/releases?per_page=20");
    let body = get_following_redirects(&url, 512 * 1024)
        .await
        .with_context(|| format!("failed to query the GitHub releases API for {repo}"))?;

    let releases: Vec<GhRelease> = serde_json::from_slice(&body).with_context(|| {
        format!(
            "GitHub returned something that is not a release list (first 200 bytes: {:?})",
            String::from_utf8_lossy(&body[..body.len().min(200)])
        )
    })?;

    let candidate = releases
        .into_iter()
        .filter(|r| !r.draft)
        .find(|r| allow_prerelease || !r.prerelease)
        .ok_or_else(|| {
            if allow_prerelease {
                anyhow!("repository {repo} has no published releases yet")
            } else {
                anyhow!(
                    "repository {repo} has no stable releases yet — only pre-releases. \
                     Set update.allow_prerelease = true (or pass --pre) to install one."
                )
            }
        })?;

    let want = format!("vlb-{}-{target}.tar.gz", candidate.tag_name);
    let archive = candidate
        .assets
        .iter()
        .find(|a| a.name == want)
        // Fall back to a suffix match so a change in tag formatting upstream
        // does not brick the updater.
        .or_else(|| {
            candidate
                .assets
                .iter()
                .find(|a| a.name.ends_with(&format!("{target}.tar.gz")))
        })
        .ok_or_else(|| {
            anyhow!(
                "release {} has no asset for {target}. Available: {}",
                candidate.tag_name,
                candidate
                    .assets
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    let checksum = candidate
        .assets
        .iter()
        .find(|a| a.name == format!("{}.sha256", archive.name))
        .map(|a| a.browser_download_url.clone());

    Ok(ReleaseInfo {
        tag: candidate.tag_name.clone(),
        prerelease: candidate.prerelease,
        archive_url: archive.browser_download_url.clone(),
        checksum_url: checksum,
        asset_name: archive.name.clone(),
    })
}

/// Everything `perform` needs beyond the release itself.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The config the new build must accept, and probe with.
    pub config_path: PathBuf,
    /// Where the daemon's control socket listens — polled after the restart
    /// to confirm the new build is actually serving.
    pub control_listen: String,
    pub service: String,
    pub restart_service: bool,
    /// Skip the canary reachability pre-flight.
    pub skip_preflight: bool,
}

/// What an update did.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub tag: String,
    pub path: PathBuf,
    pub restarted: bool,
    /// Provider carrying traffic after the restart, when the daemon could be
    /// asked; `adopted` means it was taken over from the routing table and
    /// is still being verified.
    pub active: Option<String>,
    pub active_adopted: bool,
    pub notes: Vec<String>,
}

impl Outcome {
    pub fn summary(&self) -> String {
        let mut s = format!("vlb {} installed at {}", self.tag, self.path.display());
        if self.restarted {
            match &self.active {
                Some(a) if self.active_adopted => s.push_str(&format!(
                    "; the service is back and carrying traffic via {a} (route adopted from the \
                     previous run, verification in progress)"
                )),
                Some(a) => s.push_str(&format!(
                    "; the service is back and carrying traffic via {a}"
                )),
                None => s.push_str("; the service is back"),
            }
        }
        for n in &self.notes {
            s.push_str("\nnote: ");
            s.push_str(n);
        }
        s
    }
}

/// Download, verify, prove, install and restart — with a way back.
///
/// The order is the point. Nothing on the box changes until the new build
/// has (1) been checksum-verified, (2) executed on this machine, (3) accepted
/// the config that is actually in use, and (4) — unless skipped — reached
/// the canary targets through at least one provider, since restarting into a
/// config whose canary cannot verify anything would leave the gateway with
/// automatic failover switched off. After the swap the service must come
/// back, or the previous binary is restored and restarted.
///
/// `progress` receives one line per step, for the CLI to print and the TUI
/// to show.
pub async fn perform(
    release: &ReleaseInfo,
    dest: &Path,
    plan: &Plan,
    progress: &mut (dyn FnMut(String) + Send),
) -> Result<Outcome> {
    let dir = dest
        .parent()
        .ok_or_else(|| anyhow!("cannot determine the directory of {}", dest.display()))?;
    // Say so before downloading anything, rather than after.
    if dest.exists() {
        let probe = dir.join(".vlb.update.probe");
        match tokio::fs::write(&probe, b"").await {
            Ok(()) => {
                let _ = tokio::fs::remove_file(&probe).await;
            }
            Err(e) => bail!(
                "{} is not writable ({e}) — run the update as root (sudo vlb update)",
                dir.display()
            ),
        }
    }

    progress(format!(
        "downloading {} ({})",
        release.asset_name, release.tag
    ));
    let binary = fetch_verified_binary(release).await?;
    progress("checksum verified, binary extracted".into());

    // Stage next to the destination so the final rename is atomic — a
    // cross-filesystem rename is not, and a half-written binary on a routing
    // gateway is a very bad outcome.
    let staged = dir.join(".vlb.update.new");
    let backup = dir.join("vlb.bak");
    tokio::fs::write(&staged, &binary)
        .await
        .with_context(|| format!("failed to write {}", staged.display()))?;
    set_executable(&staged).await?;

    // Everything from here until the rename must clean up the staged file on
    // failure, so a refused update leaves no trace behind.
    let discard = |staged: &Path| {
        let _ = std::fs::remove_file(staged);
    };

    // ── prove the new binary actually runs, before committing to it ─────
    let reported = verify_runnable(&staged)
        .await
        .inspect_err(|_| discard(&staged))?;
    progress(format!("new binary runs on this host ({reported})"));

    // ── the config in use must be accepted by the new build ─────────────
    match validate_config_with(&staged, &plan.config_path).await {
        Ok(()) => progress(format!(
            "existing config {} validates against {}",
            plan.config_path.display(),
            release.tag
        )),
        Err(e) => {
            discard(&staged);
            bail!(
                "the new build rejects the existing config — nothing was changed. \
                 Fix {} and re-run:\n{e:#}",
                plan.config_path.display()
            );
        }
    }

    // ── the canary must be reachable, or failover would be off ──────────
    if plan.skip_preflight {
        progress("canary pre-flight skipped (--skip-probe)".into());
    } else {
        progress(
            "pre-flight: checking the canary can reach its targets (this takes a moment)".into(),
        );
        match preflight_canary(&staged, &plan.config_path).await {
            Preflight::Met(via) => progress(format!("canary quorum met via {via}")),
            Preflight::NotApplicable => progress("canary is disabled in this config".into()),
            Preflight::NotMet(detail) => {
                discard(&staged);
                bail!(
                    "the content canary did not meet its quorum through any provider. \
                     Restarting now would mark every provider unhealthy and switch automatic \
                     failover off, while the currently installed binary keeps working.\n\
                     Nothing was changed. Either open egress to the canary targets, point \
                     [[canary.targets]] at endpoints you can reach, lower `quorum`, or re-run \
                     with --skip-probe if you know this is a false alarm.\n{detail}"
                );
            }
            Preflight::Unknown(why) => {
                progress(format!(
                    "could not run the canary pre-flight ({why}); continuing"
                ));
            }
        }
    }

    // ── commit ──────────────────────────────────────────────────────────
    let was_active = plan.restart_service && service_is_active(&plan.service).await;

    if dest.exists()
        && let Err(e) = tokio::fs::copy(dest, &backup).await
    {
        warn!(error = %e, "could not save a backup of the current binary");
    }
    tokio::fs::rename(&staged, dest).await.with_context(|| {
        format!(
            "failed to replace {} — is it on the same filesystem as {}?",
            dest.display(),
            dir.display()
        )
    })?;
    info!(path = %dest.display(), backup = %backup.display(), "binary replaced");
    progress(format!(
        "installed to {} (previous binary kept as {})",
        dest.display(),
        backup.display()
    ));

    let mut outcome = Outcome {
        tag: release.tag.clone(),
        path: dest.to_path_buf(),
        restarted: false,
        active: None,
        active_adopted: false,
        notes: Vec::new(),
    };

    if !plan.restart_service {
        outcome.notes.push(
            "update.restart_service = false — restart vlb yourself to use the new binary".into(),
        );
        return Ok(outcome);
    }
    if !was_active {
        outcome.notes.push(format!(
            "the `{}` service is not active, so nothing was restarted; the new binary is \
             used on the next start",
            plan.service
        ));
        return Ok(outcome);
    }

    // ── restart, and make sure it came back ─────────────────────────────
    progress(format!(
        "restarting {} (the default route stays in place; traffic keeps flowing)",
        plan.service
    ));
    if let Err(e) = restart_service(&plan.service).await {
        progress("restart failed — rolling back to the previous binary".into());
        let rb = rollback(dest, &backup, &plan.service).await;
        bail!(
            "`systemctl restart {}` failed: {e:#}. {}",
            plan.service,
            describe_rollback(rb)
        );
    }
    outcome.restarted = true;

    // Wait for the daemon to be serving again, not merely for systemd to
    // report the process started. The control socket answering means the
    // new build got through its own startup — sysctls, NAT, routing tables,
    // the adopted route — and is probing.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut answered = false;
    while std::time::Instant::now() < deadline {
        if !service_is_active(&plan.service).await {
            progress("the service stopped after the restart — rolling back".into());
            let rb = rollback(dest, &backup, &plan.service).await;
            bail!(
                "the `{}` service did not stay up on {} (see `journalctl -u {} -n 50`). {}",
                plan.service,
                release.tag,
                plan.service,
                describe_rollback(rb)
            );
        }
        if let Ok(crate::control::Response::Status { snapshot }) =
            crate::control::send(&plan.control_listen, &crate::control::Request::Status).await
        {
            answered = true;
            outcome.active = snapshot.active.clone();
            outcome.active_adopted = snapshot.active_adopted;
            if !snapshot.version.is_empty()
                && snapshot.version != release.tag.trim_start_matches('v')
            {
                outcome.notes.push(format!(
                    "the daemon that answered reports version {} — expected {}",
                    snapshot.version, release.tag
                ));
            }
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    if answered {
        progress(match &outcome.active {
            Some(a) => format!("the service is back; active provider: {a}"),
            None => "the service is back; no provider selected yet".into(),
        });
    } else {
        outcome.notes.push(format!(
            "the service is active but its control socket at {} did not answer within 30s; \
             check `journalctl -u {} -n 50`",
            plan.control_listen, plan.service
        ));
    }

    Ok(outcome)
}

/// Download the archive, verify it against the published checksum, and pull
/// the `vlb` binary out of it. Nothing touches the disk.
async fn fetch_verified_binary(release: &ReleaseInfo) -> Result<Vec<u8>> {
    info!(tag = %release.tag, asset = %release.asset_name, "downloading release");
    let archive = get_following_redirects(&release.archive_url, MAX_ASSET_BYTES)
        .await
        .context("failed to download the release archive")?;
    info!(bytes = archive.len(), "download complete");

    // ── verify before touching anything on disk ─────────────────────────
    match &release.checksum_url {
        Some(url) => {
            let raw = get_following_redirects(url, 4096)
                .await
                .context("failed to download the checksum file")?;
            let expected =
                parse_sha256sum_line(&String::from_utf8_lossy(&raw)).ok_or_else(|| {
                    anyhow!(
                        "could not parse the published checksum file: {:?}",
                        String::from_utf8_lossy(&raw[..raw.len().min(120)])
                    )
                })?;
            let actual = hex(&Sha256::digest(&archive));
            if actual != expected {
                bail!(
                    "checksum mismatch for {}: published {expected}, downloaded {actual}. \
                     Refusing to install — the download is corrupt or has been tampered with.",
                    release.asset_name
                );
            }
            info!(sha256 = %actual, "checksum verified");
        }
        None => bail!(
            "release {} publishes no .sha256 for {} — refusing to install an \
             unverified binary. Re-run the release workflow, or install manually.",
            release.tag,
            release.asset_name
        ),
    }

    // ── unpack ──────────────────────────────────────────────────────────
    let binary =
        extract_vlb_binary(&archive).context("failed to extract `vlb` from the archive")?;
    if binary.is_empty() {
        bail!("the extracted binary is empty");
    }
    Ok(binary)
}

/// Ask the *new* binary whether it accepts the config in use. A release that
/// tightened validation must be caught while the working binary is still in
/// place, not after the restart with the gateway down.
async fn validate_config_with(binary: &Path, config: &Path) -> Result<()> {
    let out = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(binary)
            .arg("--config")
            .arg(config)
            .arg("check")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| anyhow!("`check` did not finish within 30s"))?
    .context("could not run the new binary's `check`")?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let text = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };
    bail!(
        "{}",
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    )
}

enum Preflight {
    Met(String),
    NotMet(String),
    NotApplicable,
    /// The probe could not run or its output has no verdict line (an older
    /// build being installed for a rollback, say). Not evidence either way.
    Unknown(String),
}

/// Run the new binary's `probe` and read its canary verdict.
///
/// `probe` needs the running daemon's fwmark rules, which is why this runs
/// while the old daemon is still up. Read from the summary line the probe
/// prints for exactly this purpose, with a fallback for builds that predate
/// it.
async fn preflight_canary(binary: &Path, config: &Path) -> Preflight {
    let run = tokio::time::timeout(
        Duration::from_secs(240),
        tokio::process::Command::new(binary)
            .arg("--config")
            .arg(config)
            .arg("probe")
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let out = match run {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => return Preflight::Unknown(format!("could not run probe: {e}")),
        Err(_) => return Preflight::Unknown("probe did not finish within 240s".into()),
    };
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    classify_preflight(&text, out.status.success())
}

fn classify_preflight(text: &str, exited_ok: bool) -> Preflight {
    for line in text.lines() {
        let line = line.trim();
        if let Some(via) = line.strip_prefix("canary quorum: MET via ") {
            return Preflight::Met(via.trim().to_string());
        }
        if line.starts_with("canary quorum: NOT MET") {
            let detail: Vec<&str> = text
                .lines()
                .filter(|l| {
                    l.contains("TAMPERED") || l.contains("unreach") || l.contains("verdict")
                })
                .take(12)
                .collect();
            return Preflight::NotMet(detail.join("\n"));
        }
        if line.starts_with("canary quorum: not applicable") {
            return Preflight::NotApplicable;
        }
    }
    if !exited_ok {
        return Preflight::Unknown("probe exited non-zero".into());
    }
    // Older builds print only per-provider verdicts.
    if text
        .lines()
        .any(|l| l.contains("canary verdict:") && !l.contains("canary verdict: 0/"))
    {
        return Preflight::Met("(per-provider verdict)".into());
    }
    if text.contains("canary verdict:") {
        return Preflight::NotMet(String::new());
    }
    Preflight::Unknown("no canary verdict in the probe output".into())
}

/// Put the previous binary back and restart the service.
async fn rollback(dest: &Path, backup: &Path, service: &str) -> Result<()> {
    if !backup.exists() {
        bail!("no backup at {} to roll back to", backup.display());
    }
    let dir = dest
        .parent()
        .ok_or_else(|| anyhow!("cannot determine the directory of {}", dest.display()))?;
    // Same dance as the install: stage, then rename, so the swap is atomic.
    let staged = dir.join(".vlb.rollback.new");
    tokio::fs::copy(backup, &staged)
        .await
        .with_context(|| format!("failed to copy {} back", backup.display()))?;
    set_executable(&staged).await?;
    tokio::fs::rename(&staged, dest)
        .await
        .with_context(|| format!("failed to restore {}", dest.display()))?;
    restart_service(service).await?;
    warn!(path = %dest.display(), "rolled back to the previous binary");
    Ok(())
}

fn describe_rollback(rb: Result<()>) -> String {
    match rb {
        Ok(()) => "Rolled back to the previous binary and restarted it.".to_string(),
        Err(e) => format!(
            "ROLLBACK FAILED ({e:#}) — the previous binary is at vlb.bak next to the \
             installed one; restore it by hand and restart the service."
        ),
    }
}

/// Run `<path> --version` to prove the download is a working binary for this
/// machine before it replaces the one currently keeping the site online.
/// Returns what it reported.
async fn verify_runnable(path: &Path) -> Result<String> {
    let out = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::process::Command::new(path)
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| anyhow!("the downloaded binary did not respond to --version within 20s"))?
    .with_context(|| format!("could not execute the downloaded binary {}", path.display()))?;

    if !out.status.success() {
        bail!(
            "the downloaded binary exited with {} on --version: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let reported = String::from_utf8_lossy(&out.stdout).trim().to_string();
    info!(version = %reported, "downloaded binary verified as runnable");
    Ok(reported)
}

#[cfg(unix)]
async fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = tokio::fs::metadata(path).await?.permissions();
    perms.set_mode(0o755);
    tokio::fs::set_permissions(path, perms)
        .await
        .context("failed to mark the new binary executable")?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Restart the systemd unit so the new binary takes over.
pub async fn restart_service(unit: &str) -> Result<()> {
    let out = tokio::process::Command::new("systemctl")
        .args(["restart", unit])
        .kill_on_drop(true)
        .output()
        .await
        .context("failed to invoke systemctl")?;
    if !out.status.success() {
        bail!(
            "`systemctl restart {unit}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Is the unit currently active? Used to decide whether restarting is even
/// meaningful, and to report honestly when it is not.
pub async fn service_is_active(unit: &str) -> bool {
    tokio::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .kill_on_drop(true)
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Pull `vlb` out of a gzip-compressed tar archive.
fn extract_vlb_binary(archive: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;

    let decoder = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(decoder);
    for entry in tar.entries().context("archive is not a valid tar stream")? {
        let mut entry = entry.context("corrupt tar entry")?;
        let path = entry.path().context("tar entry has an unreadable path")?;
        let is_vlb = path
            .file_name()
            .map(|n| n == std::ffi::OsStr::new("vlb"))
            .unwrap_or(false);
        if !is_vlb {
            continue;
        }
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .context("failed to read the `vlb` entry out of the archive")?;
        return Ok(buf);
    }
    bail!("archive does not contain a file named `vlb`")
}

/// Parse a `sha256sum`-style line: `<64 hex>  <filename>`.
fn parse_sha256sum_line(text: &str) -> Option<String> {
    for line in text.lines() {
        let token = line.split_whitespace().next()?;
        if token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(token.to_ascii_lowercase());
        }
    }
    None
}

/// GET a URL, following redirects.
///
/// Unlike the canary — where a redirect is the *finding* and must never be
/// followed — the updater has to follow them, because GitHub always bounces
/// asset downloads to a CDN host.
///
/// Requests go out on the default route with no fwmark: an update should use
/// whichever uplink is currently active and healthy, which is precisely the
/// one the balancer has already selected.
async fn get_following_redirects(url: &str, max_body: usize) -> Result<Vec<u8>> {
    let mut current = Url::parse(url)?;
    for hop in 0..=MAX_REDIRECTS {
        let ip = match current.host_as_ip() {
            Some(ip) => ip,
            None => resolve_system(&current.host).await?,
        };
        let req = HttpRequest {
            url: current.clone(),
            connect_ip: ip,
            mark: None,
            timeout: NET_TIMEOUT,
            max_body,
            user_agent: format!("vlb/{} (self-update)", current_version()),
        };
        let resp = http::fetch(&req).await?;

        if resp.is_redirect() {
            if hop == MAX_REDIRECTS {
                bail!("too many redirects while fetching {url}");
            }
            let location = resp.header("location").ok_or_else(|| {
                anyhow!(
                    "{} returned {} with no Location header",
                    current,
                    resp.status
                )
            })?;
            current = resolve_location(&current, location)?;
            continue;
        }

        if resp.status == 403 || resp.status == 429 {
            bail!(
                "GitHub rate-limited the request ({}). Unauthenticated API calls are \
                 limited per IP — wait a few minutes and try again.",
                resp.status
            );
        }
        if resp.status == 404 {
            bail!("{current} returned 404 — check `update.repo` in the config");
        }
        if !(200..300).contains(&resp.status) {
            bail!("{current} returned HTTP {}", resp.status);
        }
        if resp.truncated {
            bail!(
                "response from {current} exceeded the {max_body}-byte limit and was \
                 truncated — refusing to use a partial download"
            );
        }
        return Ok(resp.body);
    }
    unreachable!("loop always returns or bails")
}

/// Resolve a `Location` value, which may be absolute or a site-relative path.
///
/// Refuses to downgrade an HTTPS request onto plain HTTP. This code path
/// downloads a binary that is then executed as root, so the transport must
/// stay authenticated for the whole redirect chain — otherwise anyone able
/// to inject a `Location: http://…` (or sitting on the network for the
/// following hop) gets to choose the bytes. The checksum is fetched over the
/// same chain, so it would not save us here.
fn resolve_location(base: &Url, location: &str) -> Result<Url> {
    let loc = location.trim();

    let target = if loc.starts_with("http://") || loc.starts_with("https://") {
        Url::parse(loc)?
    } else if loc.starts_with('/') {
        Url::parse(&format!(
            "{}://{}{}",
            base.scheme.as_str(),
            base.host_header(),
            loc
        ))?
    } else {
        bail!("cannot follow relative redirect target {loc:?} from {base}")
    };

    if base.scheme == Scheme::Https && target.scheme == Scheme::Http {
        bail!(
            "{base} redirected to {target}, downgrading HTTPS to plain HTTP. \
             Refusing to follow — the binary this fetches runs as root, so the \
             chain has to stay authenticated end to end."
        );
    }

    Ok(target)
}

/// Resolve through the system resolver, taking the first IPv4 answer.
async fn resolve_system(host: &str) -> Result<std::net::Ipv4Addr> {
    let addrs = tokio::net::lookup_host((host, 0))
        .await
        .with_context(|| format!("DNS lookup for {host} failed"))?;
    for a in addrs {
        if let std::net::IpAddr::V4(v4) = a.ip() {
            return Ok(v4);
        }
    }
    bail!("{host} has no IPv4 address")
}

// ─────────────────────────────────────────────────────────────────────────
// Version comparison
// ─────────────────────────────────────────────────────────────────────────

/// A semantic version, tolerant of a leading `v` and of pre-release suffixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// `alpha`, `rc.1`, … Empty for a final release.
    pub pre: String,
}

impl Version {
    pub fn parse(s: &str) -> Option<Version> {
        let s = s.trim().trim_start_matches('v').trim_start_matches('V');
        // Build metadata (`+abc`) never affects precedence, so drop it.
        let s = s.split('+').next()?;
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => (c, p.to_string()),
            None => (s, String::new()),
        };
        let mut parts = core.split('.');
        let major = parts.next()?.parse().ok()?;
        // Missing minor/patch default to 0 so a bare `v1` still parses.
        let minor = parts.next().unwrap_or("0").parse().ok()?;
        let patch = parts.next().unwrap_or("0").parse().ok()?;
        Some(Version {
            major,
            minor,
            patch,
            pre,
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            write!(f, "-{}", self.pre)?;
        }
        Ok(())
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                // SemVer §11: a pre-release sorts *before* its final release,
                // so 1.0.0-alpha < 1.0.0.
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => compare_prerelease(&self.pre, &other.pre),
            })
    }
}

/// Dot-separated identifiers, numeric ones compared as numbers.
fn compare_prerelease(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let mut ai = a.split('.');
    let mut bi = b.split('.');
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            // Fewer identifiers sorts lower: 1.0.0-alpha < 1.0.0-alpha.1.
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(nx), Ok(ny)) => nx.cmp(&ny),
                    // Numeric identifiers always sort below alphanumeric.
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

/// Is `candidate` strictly newer than `current`? Unparseable versions are
/// treated as "not newer", so a malformed tag can never trigger an install.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (Version::parse(candidate), Version::parse(current)) {
        (Some(c), Some(cur)) => c > cur,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing_tolerates_tag_shapes() {
        assert_eq!(
            Version::parse("v1.2.3"),
            Some(Version {
                major: 1,
                minor: 2,
                patch: 3,
                pre: String::new()
            })
        );
        assert_eq!(Version::parse("0.0.1-alpha").unwrap().pre, "alpha");
        // Bare and partial versions fill in zeros.
        assert_eq!(Version::parse("2").unwrap().to_string(), "2.0.0");
        assert_eq!(Version::parse("2.5").unwrap().to_string(), "2.5.0");
        // Build metadata is ignored for precedence.
        assert_eq!(Version::parse("1.2.3+build7").unwrap().to_string(), "1.2.3");
        assert_eq!(Version::parse("not-a-version"), None);
        assert_eq!(Version::parse(""), None);
    }

    #[test]
    fn newer_versions_are_detected() {
        assert!(is_newer("v0.1.0", "0.0.1-alpha"));
        assert!(is_newer("v1.0.0", "v0.9.9"));
        assert!(is_newer("v0.2.1", "v0.2.0"));
        assert!(!is_newer("v0.0.1-alpha", "v0.0.1-alpha"));
        assert!(!is_newer("v0.1.0", "v0.2.0"));
    }

    /// SemVer precedence: a pre-release is *older* than its final release.
    /// Getting this backwards would make the updater refuse to install the
    /// stable build that supersedes the alpha currently running.
    #[test]
    fn prerelease_sorts_before_its_release() {
        assert!(is_newer("1.0.0", "1.0.0-alpha"));
        assert!(!is_newer("1.0.0-alpha", "1.0.0"));
        assert!(is_newer("1.0.0-beta", "1.0.0-alpha"));
        assert!(is_newer("1.0.0-alpha.2", "1.0.0-alpha.1"));
        assert!(is_newer("1.0.0-alpha.1", "1.0.0-alpha"));
        assert!(is_newer("1.0.0-rc.1", "1.0.0-beta.11"));
    }

    #[test]
    fn malformed_tags_never_trigger_an_install() {
        // A garbage tag must not be read as "newer" — that would swap the
        // binary of a production gateway on the strength of a typo.
        assert!(!is_newer("latest", "0.0.1-alpha"));
        assert!(!is_newer("", "0.0.1-alpha"));
        assert!(!is_newer("v1.0.0", "garbage"));
    }

    #[test]
    fn current_version_parses() {
        // Guards against a Cargo.toml version that the updater cannot
        // compare — which would silently disable update checks.
        assert!(
            Version::parse(current_version()).is_some(),
            "Cargo.toml version {:?} is not parseable by the updater",
            current_version()
        );
    }

    #[test]
    fn checksum_line_parsing() {
        assert_eq!(
            parse_sha256sum_line(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  vlb.tar.gz\n"
            )
            .as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        // Uppercase digests are normalised.
        assert_eq!(
            parse_sha256sum_line(&format!("{}  x", "A".repeat(64))).as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert_eq!(parse_sha256sum_line("nope"), None);
        assert_eq!(parse_sha256sum_line(""), None);
        // Too short to be a digest.
        assert_eq!(parse_sha256sum_line("abc123  file"), None);
    }

    #[test]
    fn redirect_targets_resolve() {
        let base = Url::parse("https://github.com/o/r/releases/download/v1/x.tar.gz").unwrap();
        assert_eq!(
            resolve_location(&base, "https://objects.githubusercontent.com/a/b")
                .unwrap()
                .to_string(),
            "https://objects.githubusercontent.com/a/b"
        );
        // Site-relative redirects keep scheme and host.
        assert_eq!(
            resolve_location(&base, "/other/path").unwrap().to_string(),
            "https://github.com/other/path"
        );
        assert!(resolve_location(&base, "../relative").is_err());
    }

    /// The updater fetches a binary that is then executed as root, so the
    /// redirect chain must stay on HTTPS. A `Location: http://…` anywhere in
    /// it would hand the choice of bytes to whoever is on the network for the
    /// next hop — and the checksum travels the same chain, so it offers no
    /// protection against that.
    #[test]
    fn redirects_may_not_downgrade_https_to_http() {
        let secure = Url::parse("https://github.com/o/r/releases/download/v1/x.tar.gz").unwrap();

        let err = resolve_location(&secure, "http://evil.example/x.tar.gz")
            .unwrap_err()
            .to_string();
        assert!(err.contains("downgrading"), "{err}");

        // Site-relative redirects inherit the scheme, so they stay secure.
        assert_eq!(
            resolve_location(&secure, "/other").unwrap().scheme,
            Scheme::Https
        );

        // https -> https is of course fine, as is http -> https.
        assert!(resolve_location(&secure, "https://cdn.example/x").is_ok());
        let insecure = Url::parse("http://example.com/a").unwrap();
        assert!(resolve_location(&insecure, "https://example.com/a").is_ok());
    }

    /// The updater builds an asset name from [`host_target`], and the release
    /// workflow builds the same name from its `matrix.target`. If the two
    /// ever disagree, `vlb update` silently stops finding its own releases —
    /// a failure that only shows up in the field, months later, on the day
    /// somebody actually needs to upgrade. Pin them together here by reading
    /// the workflow.
    #[test]
    fn release_workflow_publishes_the_targets_the_updater_looks_for() {
        let workflow = include_str!("../../.github/workflows/release.yml");
        for target in ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"] {
            assert!(
                workflow.contains(target),
                "release.yml does not build {target}, but the updater asks for it"
            );
        }
        // And the reverse: no glibc target should reappear, since those
        // binaries inherit the runner's glibc version and will not start on
        // most production hosts.
        assert!(
            !workflow.contains("unknown-linux-gnu"),
            "release.yml builds a glibc target again — those artifacts require \
             the CI runner's glibc version and fail to start on older servers"
        );
    }

    #[test]
    fn host_target_is_known_or_explains_itself() {
        match host_target() {
            Ok(t) => assert!(t.contains("linux")),
            Err(e) => {
                // On a dev machine (e.g. Windows) this is the expected path;
                // the message must tell the user what to do instead.
                let msg = e.to_string();
                assert!(msg.contains("build from source"), "{msg}");
            }
        }
    }

    #[test]
    fn extract_rejects_an_archive_without_the_binary() {
        // Build a tiny gzip'd tar containing only a README.
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let data = b"hello";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "README", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar_buf).unwrap();
        let archive = gz.finish().unwrap();

        let err = extract_vlb_binary(&archive).unwrap_err().to_string();
        assert!(err.contains("does not contain"), "{err}");
    }

    #[test]
    fn extract_finds_the_binary() {
        let payload = b"\x7fELF-not-really-but-fine";
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "vlb", &payload[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar_buf).unwrap();
        let archive = gz.finish().unwrap();

        assert_eq!(extract_vlb_binary(&archive).unwrap(), payload);
    }

    #[test]
    fn extract_rejects_garbage() {
        assert!(extract_vlb_binary(b"not a gzip stream at all").is_err());
    }

    /// The pre-flight reads a summary line the probe prints for exactly this
    /// purpose, and must fall back sensibly for builds that predate it —
    /// which is what a rollback installs.
    #[test]
    fn preflight_verdicts_are_read_from_probe_output() {
        assert!(matches!(
            classify_preflight("...\ncanary quorum: MET via isp-main, isp-backup\n", true),
            Preflight::Met(v) if v == "isp-main, isp-backup"
        ));
        assert!(matches!(
            classify_preflight(
                "canary verdict: 0/3 ...\ncanary quorum: NOT MET via any provider",
                true
            ),
            Preflight::NotMet(_)
        ));
        assert!(matches!(
            classify_preflight("canary quorum: not applicable (canary disabled)", true),
            Preflight::NotApplicable
        ));
        // An older build: only per-provider verdict lines exist.
        assert!(matches!(
            classify_preflight("    canary verdict: 3/3 canary targets verified\n", true),
            Preflight::Met(_)
        ));
        assert!(matches!(
            classify_preflight("    canary verdict: 0/3 canary targets verified\n", true),
            Preflight::NotMet(_)
        ));
        // No verdict at all is not evidence either way.
        assert!(matches!(
            classify_preflight("== vlb probe ==\n", true),
            Preflight::Unknown(_)
        ));
        assert!(matches!(
            classify_preflight("", false),
            Preflight::Unknown(_)
        ));
    }

    #[test]
    fn outcome_summary_mentions_the_active_provider() {
        let o = Outcome {
            tag: "v9.9.9".into(),
            path: PathBuf::from("/usr/local/bin/vlb"),
            restarted: true,
            active: Some("isp-main".into()),
            active_adopted: true,
            notes: vec!["extra".into()],
        };
        let s = o.summary();
        assert!(s.contains("v9.9.9"), "{s}");
        assert!(s.contains("isp-main"), "{s}");
        assert!(s.contains("adopted"), "{s}");
        assert!(s.contains("note: extra"), "{s}");
    }

    #[test]
    fn release_json_is_parsed() {
        let json = r#"[
          {"tag_name":"v0.2.0","prerelease":false,"draft":true,"assets":[]},
          {"tag_name":"v0.1.0","prerelease":false,"draft":false,"assets":[
            {"name":"vlb-v0.1.0-x86_64-unknown-linux-gnu.tar.gz",
             "browser_download_url":"https://example.com/a.tar.gz"},
            {"name":"vlb-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256",
             "browser_download_url":"https://example.com/a.tar.gz.sha256"}
          ]}
        ]"#;
        let releases: Vec<GhRelease> = serde_json::from_str(json).unwrap();
        assert_eq!(releases.len(), 2);
        // Drafts must be skipped — they are not published artifacts.
        let first_published = releases.iter().find(|r| !r.draft).unwrap();
        assert_eq!(first_published.tag_name, "v0.1.0");
        assert_eq!(first_published.assets.len(), 2);
    }
}
