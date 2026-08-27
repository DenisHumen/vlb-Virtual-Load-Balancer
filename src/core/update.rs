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
use crate::http::{self, HttpRequest, Url};

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
pub fn host_target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu"),
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

/// Download, verify, and install `release`, replacing the running binary.
///
/// Returns the path that was replaced.
pub async fn install(release: &ReleaseInfo, dest: &Path) -> Result<PathBuf> {
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

    // Stage next to the destination so the final rename is atomic — a
    // cross-filesystem rename is not, and a half-written binary on a routing
    // gateway is a very bad outcome.
    let dir = dest
        .parent()
        .ok_or_else(|| anyhow!("cannot determine the directory of {}", dest.display()))?;
    let staged = dir.join(".vlb.update.new");
    let backup = dir.join("vlb.bak");

    tokio::fs::write(&staged, &binary)
        .await
        .with_context(|| format!("failed to write {}", staged.display()))?;
    set_executable(&staged).await?;

    // ── prove the new binary actually runs, before committing to it ─────
    verify_runnable(&staged).await.inspect_err(|_| {
        let _ = std::fs::remove_file(&staged);
    })?;

    // Keep the old binary recoverable.
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

    Ok(dest.to_path_buf())
}

/// Run `<path> --version` to prove the download is a working binary for this
/// machine before it replaces the one currently keeping the site online.
async fn verify_runnable(path: &Path) -> Result<()> {
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
    Ok(())
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
fn resolve_location(base: &Url, location: &str) -> Result<Url> {
    let loc = location.trim();
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return Url::parse(loc);
    }
    if loc.starts_with('/') {
        return Url::parse(&format!(
            "{}://{}{}",
            base.scheme.as_str(),
            base.host_header(),
            loc
        ));
    }
    bail!("cannot follow relative redirect target {loc:?} from {base}")
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
