#!/usr/bin/env python3
"""
azure_collect.py — Azure / Entra ID Token Collection and Tool Orchestration
Clearwater Security | 7 Vikings Security

Workflow:
  1. Login via az cli (browser, device-code, or service principal)
  2. Retrieve Graph tokens from both legacy (v1) and modern (v2) endpoints
  3. Feed legacy token to roadrecon (gather)
  4. Feed modern token to azurehound (list)
  5. Run EntraFalcon

Usage:
  python azure_collect.py --tenant TENANT_ID [options]

  # Browser auth (default)
  python azure_collect.py --tenant TENANT_ID

  # Device code
  python azure_collect.py --tenant TENANT_ID --auth device-code

  # Skip az login if already authenticated
  python azure_collect.py --tenant TENANT_ID --skip-login

  # Run only specific stages
  python azure_collect.py --tenant TENANT_ID --stages tokens roadrecon

  # Custom tool paths
  python azure_collect.py --tenant TENANT_ID \\
      --azurehound "C:/Tools/azurehound.exe" \\
      --entrafalcon "C:/Tools/EntraFalcon/run_EntraFalcon.ps1"
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

# ── ANSI colour support ───────────────────────────────────────────────────────
# Enabled on any TTY; on Windows requires Windows Terminal or ANSICON.
_USE_COLOUR = sys.stdout.isatty() and (
    platform.system() != "Windows"
    or os.environ.get("WT_SESSION")
    or os.environ.get("ANSICON")
    or os.environ.get("TERM_PROGRAM")
)

# Palette
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"

_RED    = "\033[38;5;196m"
_ORANGE = "\033[38;5;208m"
_YELLOW = "\033[38;5;220m"
_GREEN  = "\033[38;5;82m"
_CYAN   = "\033[38;5;51m"
_BLUE   = "\033[38;5;33m"
_PURPLE = "\033[38;5;135m"
_GREY   = "\033[38;5;244m"
_WHITE  = "\033[38;5;255m"

_BG_DARK = "\033[48;5;235m"

def _c(colour: str, text: str, bold: bool = False) -> str:
    if not _USE_COLOUR:
        return text
    b = _BOLD if bold else ""
    return f"{b}{colour}{text}{_RESET}"


# ── Output functions ──────────────────────────────────────────────────────────

_STAGE_WIDTH = 58

def print_startup_banner() -> None:
    art = r"""
   ___   ____  __  ____  ____  ____  ____  __    __    ____  ___  ____
  / _ | |_  / / / / __ \/ __/ / __/ / __/ / /   / /   / __/ / _/ /_  /
 / __ |_/_ < / /_/ /_/ / /__ / /__ / _/  / /__ / /__ / _/  / /_  / /_
/_/ |_/____//____|____/\___/ \___/ /_/   /____//____//___/ /___/ /___/
"""
    tagline = "Azure / Entra ID Collection & Tool Orchestration"
    credit  = "Clearwater Security  |  7 Vikings Security"
    if _USE_COLOUR:
        # Gradient: cyan → blue → purple across lines
        colours = [_CYAN, _BLUE, _BLUE, _PURPLE]
        lines   = art.splitlines()
        coloured = "\n".join(
            _c(colours[min(i, len(colours)-1)], line, bold=True)
            for i, line in enumerate(lines)
        )
        print(coloured)
        print(_c(_GREY,   f"  {tagline}"))
        print(_c(_GREY,   f"  {credit}"))
    else:
        print(art)
        print(f"  {tagline}")
        print(f"  {credit}")
    print()


def banner(title: str) -> None:
    """Section header — bold cyan rule with title."""
    bar = "─" * _STAGE_WIDTH
    print()
    print(_c(_CYAN, f"┌{bar}┐", bold=True))
    padding = _STAGE_WIDTH - len(title) - 2
    left    = padding // 2
    right   = padding - left
    print(_c(_CYAN, "│", bold=True) +
          _c(_WHITE, f"{' ' * left}{title}{' ' * right}", bold=True) +
          _c(_CYAN,  "│", bold=True))
    print(_c(_CYAN, f"└{bar}┘", bold=True))


def section(title: str) -> None:
    """Sub-section marker."""
    print()
    print(_c(_YELLOW, f"  ▸ {title}", bold=True))


def info(msg: str) -> None:
    print(_c(_GREEN, "  [+]", bold=True) + _c(_WHITE, f" {msg}"))


def warn(msg: str) -> None:
    print(_c(_ORANGE, "  [!]", bold=True) + _c(_YELLOW, f" {msg}"), file=sys.stderr)


def finding(msg: str) -> None:
    print(_c(_RED, "  [✗]", bold=True) + _c(_RED, f" {msg}"))


def step(msg: str) -> None:
    print(_c(_GREY, f"      $ {msg}"))


def status_row(label: str, value: str, colour: str = _WHITE) -> None:
    """Aligned key: value row for summaries."""
    print(f"  {_c(_GREY, f'{label:<18}')}  {_c(colour, value)}")


def divider() -> None:
    print(_c(_GREY, _DIM + "  " + "·" * (_STAGE_WIDTH - 2)))


# ── Helpers ───────────────────────────────────────────────────────────────────

def run(
    cmd,
    *,
    check: bool = True,
    capture: bool = False,
    timeout: int = 300,
    env: dict = None,
    shell_override: bool = False,
) -> subprocess.CompletedProcess:
    """Run a subprocess, streaming stdout/stderr unless capture=True."""
    merged_env = {**os.environ, **(env or {})}
    display = cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd)
    step(display)
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        timeout=timeout,
        env=merged_env,
        check=False,
        shell=shell_override,
    )
    if check and result.returncode != 0:
        err = result.stderr.strip() if capture else "(see above)"
        raise RuntimeError(
            f"Command failed (exit {result.returncode}): {display}\n{err}"
        )
    return result


def az(*args, **kwargs) -> subprocess.CompletedProcess:
    """Invoke az cli, resolving the binary across platforms.

    On Windows, az ships as az.cmd which cannot be launched as a direct
    executable by subprocess without shell=True. We resolve the full path
    via shutil.which (which honours PATHEXT and finds .cmd/.bat wrappers)
    and set shell=True automatically when the resolved path ends in .cmd/.bat.
    """
    import shutil
    az_resolved = shutil.which("az")
    if az_resolved is None:
        raise RuntimeError(
            "az cli not found in PATH. Install from: https://aka.ms/installazurecliwindows"
        )
    use_shell = platform.system() == "Windows" and az_resolved.lower().endswith((".cmd", ".bat"))
    # When shell=True on Windows we pass the command as a single string
    if use_shell:
        cmd_str = " ".join([f'"{az_resolved}"'] + [f'"{a}"' if " " in str(a) else str(a) for a in args])
        return run(cmd_str, shell_override=True, **kwargs)
    return run([az_resolved, *args], **kwargs)


def pwsh(*args, **kwargs) -> subprocess.CompletedProcess:
    """Invoke PowerShell Core (pwsh) or Windows PowerShell."""
    import shutil
    for binary in ("pwsh", "powershell"):
        resolved = shutil.which(binary)
        if resolved:
            return run([resolved, *args], **kwargs)
    raise RuntimeError("No PowerShell binary found (tried pwsh, powershell).")


def _which(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


def _require(binary: str, install_hint: str) -> None:
    if not _which(binary):
        raise RuntimeError(f"'{binary}' not found in PATH. {install_hint}")


def out_dir(base: Path, name: str) -> Path:
    d = base / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    info(f"Saved: {path}")


# ── Download infrastructure ───────────────────────────────────────────────────

GITHUB_API = "https://api.github.com"

def _github_latest_release(repo: str) -> dict:
    """Return the latest release metadata dict from the GitHub API."""
    url = f"{GITHUB_API}/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={"User-Agent": "azure-collect/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _download_file(url: str, dest: Path, label: str = "") -> Path:
    """Download url to dest, printing a progress bar."""
    label = label or dest.name
    info(f"Downloading  {_c(_CYAN, label)}")
    step(url)
    req = urllib.request.Request(url, headers={"User-Agent": "azure-collect/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        done  = 0
        chunk = 65536
        with open(dest, "wb") as f:
            while True:
                buf = resp.read(chunk)
                if not buf:
                    break
                f.write(buf)
                done += len(buf)
                if total and _USE_COLOUR:
                    pct   = done * 100 // total
                    filled = pct * 30 // 100
                    bar   = ("█" * filled) + ("░" * (30 - filled))
                    print(f"\r      {_c(_CYAN, bar)}  {_c(_WHITE, f'{pct:3d}%')}  "
                          f"{_c(_GREY, f'{done // 1024:,} / {total // 1024:,} KB')}",
                          end="", flush=True)
                elif total:
                    pct = done * 100 // total
                    print(f"\r      {pct:3d}%  {done // 1024:,} KB / {total // 1024:,} KB",
                          end="", flush=True)
    print()
    info(f"Saved  {_c(_CYAN, str(dest))}  {_c(_GREY, f'({done // 1024:,} KB)')}")
    return dest


def _platform_triplet() -> tuple[str, str, str]:
    """Return (os_name, arch, exe_suffix) for the current host."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_name = {"darwin": "darwin", "linux": "linux", "windows": "windows"}.get(system, system)
    arch    = {"x86_64": "amd64", "amd64": "amd64",
               "arm64": "arm64", "aarch64": "arm64"}.get(machine, machine)
    suffix  = ".exe" if system == "windows" else ""
    return os_name, arch, suffix


def _extract_zip(zip_path: Path, dest_dir: Path, member_suffix: str = "") -> list[Path]:
    """Extract a zip archive, returning paths of extracted files."""
    import zipfile
    extracted = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            if not member_suffix or name.endswith(member_suffix):
                zf.extract(name, dest_dir)
                extracted.append(dest_dir / name)
    return extracted


def _make_executable(path: Path) -> None:
    if platform.system() != "Windows":
        path.chmod(path.stat().st_mode | 0o111)


def _fetch_azurehound(tmp_dir: Path) -> Path:
    """
    Download the latest azurehound release binary for the current platform
    from BloodHoundAD/AzureHound, extract it, and return the path to the binary.
    """
    os_name, arch, suffix = _platform_triplet()
    section(f"Fetching azurehound  ({os_name}/{arch})")

    release = _github_latest_release("BloodHoundAD/AzureHound")
    tag     = release["tag_name"]
    info(f"Latest release: {tag}")

    # Asset naming convention (v2.x+): AzureHound_{tag}_{os}_{arch}.zip
    # e.g. AzureHound_v2.12.0_windows_amd64.zip
    asset_name = f"AzureHound_{tag}_{os_name}_{arch}.zip"
    asset = next(
        (a for a in release["assets"] if a["name"].lower() == asset_name.lower()),
        None,
    )
    if not asset:
        # Fallback: match by os/arch suffix in case tag format changes
        asset = next(
            (a for a in release["assets"]
             if a["name"].lower().endswith(f"_{os_name}_{arch}.zip")),
            None,
        )
    if not asset:
        available = [a["name"] for a in release["assets"]]
        raise RuntimeError(
            f"No azurehound asset matching '{asset_name}' in release {tag}.\n"
            f"Available: {available}"
        )

    zip_path = tmp_dir / asset_name
    _download_file(asset["browser_download_url"], zip_path, asset_name)

    extracted = _extract_zip(zip_path, tmp_dir, member_suffix=f"azurehound{suffix}")
    zip_path.unlink(missing_ok=True)

    binary = next((p for p in extracted if p.name == f"azurehound{suffix}"), None)
    if not binary or not binary.exists():
        # Some releases nest inside a subdirectory — do a recursive search
        binary = next(tmp_dir.rglob(f"azurehound{suffix}"), None)
    if not binary:
        raise RuntimeError(f"azurehound binary not found after extracting {asset_name}.")

    _make_executable(binary)
    info(f"azurehound ready: {binary}")
    return binary


def _fetch_entrafalcon(tmp_dir: Path) -> Path:
    """
    Download the full CompassSecurity/EntraFalcon repo as a zip archive and
    extract it, preserving the modules/ subdirectory that run_EntraFalcon.ps1
    depends on. Returns the path to run_EntraFalcon.ps1 inside the extract.
    """
    section("Fetching EntraFalcon (full repo)")

    repo_zip_url = "https://github.com/CompassSecurity/EntraFalcon/archive/refs/heads/main.zip"
    zip_path     = tmp_dir / "EntraFalcon-main.zip"

    # Try latest release zip first, fall back to main branch archive
    try:
        release = _github_latest_release("CompassSecurity/EntraFalcon")
        tag     = release["tag_name"]
        # GitHub auto-generates a source zip for every release at this URL
        release_zip_url = f"https://github.com/CompassSecurity/EntraFalcon/archive/refs/tags/{tag}.zip"
        info(f"Latest release: {tag} — downloading source archive...")
        _download_file(release_zip_url, zip_path, f"EntraFalcon-{tag}.zip")
    except Exception as e:
        warn(f"Release archive download failed ({e}) — falling back to main branch zip.")
        _download_file(repo_zip_url, zip_path, "EntraFalcon-main.zip")

    # Extract the zip — GitHub archives nest everything under EntraFalcon-{ref}/
    info("Extracting EntraFalcon archive...")
    _extract_zip(zip_path, tmp_dir)
    zip_path.unlink(missing_ok=True)

    # Find run_EntraFalcon.ps1 inside the extracted tree
    candidates = list(tmp_dir.rglob("run_EntraFalcon.ps1"))
    if not candidates:
        raise RuntimeError(
            "run_EntraFalcon.ps1 not found after extracting the archive. "
            "Repository structure may have changed."
        )

    # Pick the one closest to the repo root (shortest path depth)
    ef_script = min(candidates, key=lambda p: len(p.parts))
    info(f"EntraFalcon ready: {ef_script}")
    info(f"Modules directory: {ef_script.parent / 'modules'}")
    return ef_script


# ── Stage 1 — az cli login ────────────────────────────────────────────────────

def stage_login(args) -> None:
    banner("Stage 1 — az cli Login")

    if args.skip_login:
        info("--skip-login set — verifying existing session...")
        result = az("account", "show", capture=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(
                "No active az session found. Remove --skip-login and authenticate."
            )
        acct = json.loads(result.stdout)
        info(f"Existing session: {acct.get('user', {}).get('name')} "
             f"| Tenant: {acct.get('tenantId')}")
        return

    login_cmd = ["login", "--tenant", args.tenant, "--allow-no-subscriptions"]

    if args.auth == "device-code":
        login_cmd += ["--use-device-code"]
        info("Starting device-code flow — check terminal for the code...")
    elif args.auth == "browser":
        info("Launching browser for interactive sign-in...")
    elif args.auth == "sp":
        if not (args.client_id and args.client_secret):
            raise RuntimeError("Service principal auth requires --client-id and --client-secret.")
        login_cmd += [
            "--service-principal",
            "--username", args.client_id,
            "--password", args.client_secret,
        ]
        info("Authenticating as service principal...")

    az(*login_cmd)

    # Pin to the requested tenant so subsequent calls are unambiguous
    az("account", "set", "--subscription", args.tenant, check=False)
    info("Login complete.")


# ── Stage 2 — Token Retrieval ─────────────────────────────────────────────────

GRAPH_RESOURCE_MODERN = "https://graph.microsoft.com"
GRAPH_RESOURCE_LEGACY = "https://graph.windows.net"
ARM_RESOURCE          = "https://management.azure.com"

def _get_az_token(resource: str) -> dict:
    """Retrieve an access token for a resource via az cli."""
    result = az(
        "account", "get-access-token",
        "--resource", resource,
        "--output", "json",
        capture=True,
    )
    return json.loads(result.stdout)


def _decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without signature verification."""
    import base64
    payload = token.split(".")[1]
    # Re-pad to a multiple of 4
    payload += "=" * (4 - len(payload) % 4)
    decoded = base64.urlsafe_b64decode(payload)
    return json.loads(decoded)


def _token_expiry(token: str) -> str:
    try:
        exp = _decode_jwt_payload(token).get("exp", 0)
        return datetime.utcfromtimestamp(exp).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return "unknown"


def stage_tokens(args, output: Path) -> dict:
    """
    Retrieve tokens from both endpoint generations:
      - v1 (legacy): https://login.microsoftonline.com/{tenant}/oauth2/token
        Used by roadrecon, older MSOL tooling.
      - v2 (modern): https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
        Used by azurehound, EntraFalcon, Microsoft.Graph SDK.

    az cli internally uses MSAL and caches tokens in its token cache.
    We redeem them via `az account get-access-token` to avoid re-prompting.
    The raw JWT is then passed to each tool directly.
    """
    banner("Stage 2 — Token Retrieval")
    tokens = {}

    # ── Modern Graph token (v2 endpoint) ──────────────────────────────────────
    section("Modern Graph token  (v2 / graph.microsoft.com)")
    modern = _get_az_token(GRAPH_RESOURCE_MODERN)
    tokens["graph_modern"] = modern["accessToken"]
    info(f"Modern Graph token obtained — expires: {modern.get('expiresOn', _token_expiry(modern['accessToken']))}")

    # ── Legacy Graph token (v1 endpoint / graph.windows.net) ─────────────────
    # roadrecon's gatherer targets the legacy AAD Graph API (graph.windows.net).
    # az cli can redeem a v1 token for this resource directly.
    section("Legacy Graph token  (v1 / graph.windows.net)")
    legacy = _get_az_token(GRAPH_RESOURCE_LEGACY)
    tokens["graph_legacy"] = legacy["accessToken"]
    info(f"Legacy Graph token obtained — expires: {legacy.get('expiresOn', _token_expiry(legacy['accessToken']))}")

    # ── ARM token ─────────────────────────────────────────────────────────────
    section("ARM token  (management.azure.com)")
    try:
        arm = _get_az_token(ARM_RESOURCE)
        tokens["arm"] = arm["accessToken"]
        info(f"ARM token obtained — expires: {arm.get('expiresOn', _token_expiry(arm['accessToken']))}")
    except Exception as e:
        warn(f"ARM token retrieval failed (no subscriptions?): {e}")
        tokens["arm"] = None

    # ── Inspect token claims ──────────────────────────────────────────────────
    section("Token Claims")
    try:
        claims = _decode_jwt_payload(tokens["graph_modern"])
        upn    = claims.get("upn") or claims.get("unique_name") or claims.get("oid", "unknown")
        tid    = claims.get("tid", "unknown")
        scp    = claims.get("scp", claims.get("roles", ""))
        divider()
        status_row("Identity",  upn,  _WHITE)
        status_row("Tenant",    tid,  _CYAN)
        status_row("Scopes",    scp,  _GREY)
        divider()
        tokens["_meta"] = {"upn": upn, "tid": tid, "scp": scp}
    except Exception as e:
        warn(f"Could not decode token claims: {e}")

    # ── Persist tokens to disk (no ARM token — it's sensitive enough) ─────────
    token_out = output / "tokens"
    token_out.mkdir(exist_ok=True)
    save_json(token_out / "graph_modern_claims.json",
              _decode_jwt_payload(tokens["graph_modern"]) if tokens.get("graph_modern") else {})
    save_json(token_out / "graph_legacy_claims.json",
              _decode_jwt_payload(tokens["graph_legacy"]) if tokens.get("graph_legacy") else {})
    # Raw tokens saved to separate files for easy copy-paste into other tools
    (token_out / "graph_modern.token").write_text(tokens.get("graph_modern", ""), encoding="utf-8")
    (token_out / "graph_legacy.token").write_text(tokens.get("graph_legacy", ""), encoding="utf-8")
    info(f"Token files saved to: {token_out}")

    return tokens


# ── Stage 3 — roadrecon ───────────────────────────────────────────────────────

def stage_roadrecon(args, tokens: dict, output: Path) -> None:
    """
    Authenticate roadrecon using the legacy Graph token (graph.windows.net),
    then run the full gather. roadrecon's --access-token flag feeds directly
    into its SQLite database without requiring a separate auth flow.
    """
    banner("Stage 3 — roadrecon")
    _require("roadrecon", "Install via: pip install roadrecon")

    legacy_token = tokens.get("graph_legacy")
    if not legacy_token:
        warn("No legacy Graph token available — skipping roadrecon.")
        return

    rr_dir = out_dir(output, "roadrecon")
    db_path = rr_dir / "roadrecon.db"

    # ── Auth: inject legacy token directly ────────────────────────────────────
    section("roadrecon auth — legacy token (graph.windows.net)")
    run(
        ["roadrecon", "auth", "--access-token", legacy_token,
         "--tenant", args.tenant],
        timeout=30,
    )

    # ── Gather: full tenant enumeration ───────────────────────────────────────
    section("roadrecon gather")
    run(
        ["roadrecon", "gather",
         "--database", str(db_path),
         "--tenant", args.tenant],
        timeout=1800,  # 30 min ceiling for large tenants
    )

    info(f"roadrecon database saved to: {db_path}")

    # ── Export: generate HTML report ──────────────────────────────────────────
    section("roadrecon export — HTML report")
    html_path = rr_dir / "roadrecon.html"
    try:
        run(
            ["roadrecon", "dump",
             "--database", str(db_path),
             "--output-format", "html",
             "--output", str(html_path)],
            timeout=120,
        )
        info(f"HTML report saved to: {html_path}")
    except Exception as e:
        warn(f"roadrecon HTML export failed (non-fatal): {e}")


# ── Stage 4 — azurehound list ─────────────────────────────────────────────────

def stage_azurehound(args, tokens: dict, output: Path) -> None:
    """
    Run azurehound using the modern Graph token (graph.microsoft.com).
    If the binary is not found at the specified path or in PATH, it is
    downloaded from the latest BloodHoundAD/AzureHound GitHub release,
    executed, and then deleted.
    """
    banner("Stage 4 — azurehound list")

    modern_token = tokens.get("graph_modern")
    if not modern_token:
        warn("No modern Graph token available — skipping azurehound.")
        return

    import shutil
    ah_dir    = out_dir(output, "azurehound")
    tmp_dir   = output / "_tmp_azurehound"
    _ephemeral = False   # tracks whether we downloaded the binary

    # ── Resolve binary ────────────────────────────────────────────────────────
    ah_bin = shutil.which(args.azurehound) or (
        args.azurehound if Path(args.azurehound).exists() else None
    )

    if ah_bin is None and not args.no_auto_download:
        info("azurehound not found — downloading latest release...")
        try:
            tmp_dir.mkdir(parents=True, exist_ok=True)
            ah_bin     = str(_fetch_azurehound(tmp_dir))
            _ephemeral = True
        except Exception as e:
            warn(f"azurehound download failed: {e}")
            warn("Supply the binary via --azurehound or ensure it is in PATH.")
            return
    elif ah_bin is None:
        warn("azurehound not found and --no-auto-download is set — skipping.")
        return

    # ── Execute ───────────────────────────────────────────────────────────────
    try:
        arm_token = tokens.get("arm")

        cmd = [
            ah_bin, "list",
            "--jwt-access-token", modern_token,
            "--tenant", args.tenant,
            "--output", str(ah_dir / "azurehound.json"),
        ]
        if arm_token:
            cmd += ["--arm-jwt-access-token", arm_token]
            info("ARM token supplied — resource enumeration enabled.")
        else:
            warn("No ARM token — azurehound will enumerate Entra objects only.")

        section("azurehound list")
        run(cmd, timeout=3600)
        info(f"azurehound output saved to: {ah_dir}")

    finally:
        if _ephemeral and tmp_dir.exists():
            import shutil as _shutil
            _shutil.rmtree(tmp_dir, ignore_errors=True)
            info("Temporary azurehound binary deleted.")


# ── Stage 5 — EntraFalcon ─────────────────────────────────────────────────────

def stage_entrafalcon(args, tokens: dict, output: Path) -> None:
    """
    Run EntraFalcon by calling run_EntraFalcon.ps1 directly via pwsh -File.
    The full repo (including modules/) is downloaded when the script is not
    found locally, then deleted after execution.
    """
    banner("Stage 5 — EntraFalcon")

    ef_out  = output / "entrafalcon"
    tmp_dir = output / "_tmp_entrafalcon"
    _ephemeral = False

    # ── Resolve script path ───────────────────────────────────────────────────
    ef_path = Path(args.entrafalcon)

    if not ef_path.exists() and not args.no_auto_download:
        info("run_EntraFalcon.ps1 not found — downloading full repo from GitHub...")
        try:
            tmp_dir.mkdir(parents=True, exist_ok=True)
            ef_path    = _fetch_entrafalcon(tmp_dir)
            _ephemeral = True
        except Exception as e:
            warn(f"EntraFalcon download failed: {e}")
            warn("Supply the script via --entrafalcon or ensure the path is correct.")
            return
    elif not ef_path.exists():
        warn(f"EntraFalcon not found at '{ef_path}' and --no-auto-download is set — skipping.")
        return

    # ── Execute directly ──────────────────────────────────────────────────────
    # run_EntraFalcon.ps1 handles its own authentication — just invoke it with
    # pwsh -File so $PSScriptRoot resolves correctly and modules/ imports work.
    try:
        section("Running EntraFalcon...")
        pwsh(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", str(ef_path),
            timeout=600,
        )
        info(f"EntraFalcon output saved alongside script in: {ef_path.parent}")

    except Exception as e:
        warn(f"EntraFalcon execution failed: {e}")
    finally:
        if _ephemeral and tmp_dir.exists():
            import shutil as _shutil
            # Move any output EntraFalcon generated next to the script into
            # the main output directory before we wipe the temp tree.
            for item in ef_path.parent.iterdir():
                if item.name != ef_path.name and item.suffix not in (".ps1", ".psm1"):
                    dest = ef_out / item.name
                    ef_out.mkdir(parents=True, exist_ok=True)
                    _shutil.move(str(item), str(dest))
                    info(f"Moved EntraFalcon output: {dest}")
            _shutil.rmtree(tmp_dir, ignore_errors=True)
            info("Temporary EntraFalcon repo deleted.")


# ── Argument Parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="azure_collect.py",
        description="Azure / Entra ID token collection and tool orchestration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument("--tenant", required=True,
                   help="Entra ID tenant ID (GUID).")
    p.add_argument("--auth",
                   choices=["browser", "device-code", "sp"],
                   default="browser",
                   help="az cli auth method (default: browser).")
    p.add_argument("--skip-login", action="store_true",
                   help="Skip az login — reuse an existing authenticated session.")
    p.add_argument("--client-id",
                   help="Service principal client ID (--auth sp only).")
    p.add_argument("--client-secret",
                   help="Service principal client secret (--auth sp only).")
    p.add_argument("--output", default=None,
                   help="Output directory (default: ./azure_collect_YYYYMMDD-HHMMSS).")
    p.add_argument(
        "--stages",
        nargs="+",
        choices=["login", "tokens", "roadrecon", "azurehound", "entrafalcon"],
        default=["login", "tokens", "roadrecon", "azurehound", "entrafalcon"],
        help="Stages to run (default: all).",
    )

    tools = p.add_argument_group("Tool Paths")
    tools.add_argument("--azurehound",
                       default="azurehound",
                       help="Path to azurehound binary (default: azurehound in PATH).")
    tools.add_argument("--entrafalcon",
                       default=r"C:\Computer Files\Tools\EntraFalcon\run_EntraFalcon.ps1",
                       help="Path to run_EntraFalcon.ps1.")
    tools.add_argument("--no-auto-download", action="store_true",
                       help="Disable automatic tool download from GitHub. "
                            "Script will skip stages where tools are missing.")

    return p


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    print_startup_banner()

    # ── Output directory ──────────────────────────────────────────────────────
    ts     = datetime.now().strftime("%Y%m%d-%H%M%S")
    output = Path(args.output) if args.output else Path(f"azure_collect_{ts}")
    output.mkdir(parents=True, exist_ok=True)

    divider()
    status_row("Tenant",    args.tenant,       _CYAN)
    status_row("Auth",      args.auth,         _WHITE)
    status_row("Stages",    " · ".join(args.stages), _WHITE)
    status_row("Output",    str(output.resolve()), _GREY)
    divider()

    stages = set(args.stages)
    tokens: dict = {}
    start  = time.time()

    try:
        if "login" in stages:
            stage_login(args)

        if "tokens" in stages:
            tokens = stage_tokens(args, output)
        elif any(s in stages for s in ("roadrecon", "azurehound", "entrafalcon")):
            warn("'tokens' stage skipped — attempting silent token retrieval...")
            try:
                tokens = stage_tokens(args, output)
            except Exception as e:
                warn(f"Silent token retrieval failed: {e}. Downstream stages may error.")

        if "roadrecon"   in stages: stage_roadrecon(args, tokens, output)
        if "azurehound"  in stages: stage_azurehound(args, tokens, output)
        if "entrafalcon" in stages: stage_entrafalcon(args, tokens, output)

    except KeyboardInterrupt:
        warn("\nInterrupted.")
        sys.exit(130)
    except RuntimeError as e:
        finding(f"Fatal: {e}")
        sys.exit(1)

    # ── Final summary ─────────────────────────────────────────────────────────
    elapsed = time.time() - start
    mins, secs = divmod(int(elapsed), 60)

    banner("Collection Complete")
    print()
    status_row("Runtime",   f"{mins}m {secs:02d}s",         _WHITE)
    status_row("Output",    str(output.resolve()),           _CYAN)
    print()

    rows = [
        ("tokens/",      "Raw JWTs + decoded claims",            "roadrecon", "azurehound", "entrafalcon"),
        ("roadrecon/",   "roadrecon.db  +  HTML graph report",   "roadrecon"),
        ("azurehound/",  "BloodHound-ready JSON for import",     "azurehound"),
        ("entrafalcon/", "HTML report  +  findings summary",     "entrafalcon"),
    ]
    print(_c(_GREY, "  Output layout"))
    for path, desc, *stage_req in rows:
        ran = any(s in stages for s in stage_req)
        col = _WHITE if ran else _GREY
        dim = "" if ran else _DIM
        print(f"  {_c(_CYAN if ran else _GREY, f'{path:<18}')}"
              f"  {_c(col, dim + desc)}")

    print()
    print(_c(_GREY, "  Next steps"))

    next_steps = []
    if "azurehound"  in stages: next_steps.append(("BloodHound CE",  "Import azurehound/azurehound.json"))
    if "roadrecon"   in stages: next_steps.append(("roadrecon UI",   "Run: roadrecon roadui"))
    if "entrafalcon" in stages: next_steps.append(("EntraFalcon",    "Review entrafalcon/ HTML report"))

    for tool, hint in next_steps:
        print(f"  {_c(_PURPLE, f'  {tool:<16}')}{_c(_GREY, hint)}")
    print()


if __name__ == "__main__":
    main()
