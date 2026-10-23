#!/bin/bash
# emsign-check.sh - audit a developer Mac's TLS trust configuration after the
# October 2026 eMudhra/emSign intermediate CA key compromise.
#
# Audits first (read-only). If anything FAILs and a person is at the terminal,
# it asks whether to remediate, then confirms each fix before applying it.
# Compatible with stock macOS bash 3.2.
#
# Usage:  ./emsign-check.sh [--deep] [--audit-only] [--yes] [--ea] [--no-color]
#   --deep        also search $HOME and /Applications for vendored PEM bundles (slower)
#   --audit-only  never prompt or change anything
#   --yes         apply every available fix without prompting (still no sudo)
#   --ea          print one <result> line only (Jamf extension attribute style, exits 0)
#   --no-color    plain output
#
# Env: BLOCKED_CERTS_FILE=/path/to/blocked.certs  use a pre-downloaded Oracle file
#      BLOCKED_CERTS_URL=https://internal/...      fetch from an internal mirror instead
#      BLOCKED_CERTS_SHA256=<hex>                  refuse any file that doesn't match
#      (ops.java returns 403 to scripted clients, so a vetted internal mirror plus
#       a pinned hash is the fleet-friendly setup)
#
# Fixes offered (same as the developer guide):
#   Node     nvm install of the fixed release per major, optional removal of old versions
#   Homebrew brew upgrade of node, go, ca-certificates
#   Java     backup cacerts, delete the emSign ECC Root CA - G3 alias, merge Oracle's
#            blocked.certs (https://ops.java/emudhra); IDE-bundled JDKs are reported
#            as WARN and never edited
#   Python   pip install -U certifi in each flagged interpreter/virtualenv
#
# Exit codes (without --ea): 0 clean, 1 warnings only, 2 exposure found
# (after remediation, the exit code of the verification re-run)
#
# When run as root (MDM), it re-runs itself as the logged-in console user and
# loads that user's login shell environment, so nvm/sdkman/pyenv installs,
# ~/.npmrc, ~/.gradle etc. are the ones inspected.
#
# Limitation: bundles are checked for the emSign roots. Three of the
# compromised intermediates were also cross-signed by Sectigo's
# "AAA Certificate Services" root, which is legitimately in every bundle.
# Those cross-signs were revoked, so only clients that check revocation (or
# carry a key-based block, like patched Go) are protected on that path.

set -u

DEEP=0; EA=0; COLOR=1; CLEANUP=""; MDM=0; AUDIT_ONLY=0; YES=0
BLOCKED_CERTS_URL="${BLOCKED_CERTS_URL:-https://ops.java/unix/blocked.certs}"
for a in "$@"; do
  case "$a" in
    --deep) DEEP=1 ;;
    --audit-only) AUDIT_ONLY=1 ;;
    --yes) YES=1 ;;
    --ea) EA=1; COLOR=0 ;;
    --no-color) COLOR=0 ;;
    --cleanup=*) CLEANUP="${a#--cleanup=}"; MDM=1 ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
  esac
done
[ -t 1 ] || COLOR=0

# ---- root/MDM: re-exec as console user -------------------------------------
if [ "$(id -u)" -eq 0 ]; then
  cu=$(stat -f%Su /dev/console 2>/dev/null)
  if [ -n "$cu" ] && [ "$cu" != "root" ] && [ "$cu" != "loginwindow" ]; then
    tmp=$(mktemp /tmp/emsign-check.XXXXXX) || exit 3
    cp "$0" "$tmp" && chmod 755 "$tmp"
    args=""
    [ $DEEP -eq 1 ] && args="$args --deep"
    [ $EA -eq 1 ] && args="$args --ea"
    [ $COLOR -eq 0 ] && args="$args --no-color"
    args="$args --audit-only"   # MDM runs report only
    # shellcheck disable=SC2086
    exec sudo -u "$cu" -H /bin/bash "$tmp" $args "--cleanup=$tmp"
  fi
fi
[ -n "$CLEANUP" ] && trap 'rm -f "$CLEANUP"' EXIT

# Pull the user's real login environment when launched by MDM.
if [ $MDM -eq 1 ]; then
  ush=$(dscl . -read "/Users/$(id -un)" UserShell 2>/dev/null | awk '{print $2}')
  envdump=$("${ush:-/bin/zsh}" -ilc 'env' </dev/null 2>/dev/null)
  for v in PATH JAVA_HOME JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS NODE_OPTIONS \
           NODE_EXTRA_CA_CERTS NODE_TLS_REJECT_UNAUTHORIZED SSL_CERT_FILE \
           SSL_CERT_DIR REQUESTS_CA_BUNDLE CURL_CA_BUNDLE GIT_SSL_CAINFO \
           GIT_SSL_NO_VERIFY NVM_DIR SDKMAN_DIR PYENV_ROOT; do
    line=$(printf '%s\n' "$envdump" | grep "^$v=" | head -1)
    # shellcheck disable=SC2163  # exports "NAME=value" deliberately
    [ -n "$line" ] && export "$line"
  done
fi

# ---- output helpers ---------------------------------------------------------
PASS=0; WARN=0; FAIL=0; FINDINGS=""; SEEN=""
# remediation queue (filled during the audit)
NODE_FIX=(); JDK_FIX=(); CERTIFI_FIX=(); BREW_PKGS=""; MANUAL=()
queue_brew() { case " $BREW_PKGS " in *" $1 "*) ;; *) BREW_PKGS="${BREW_PKGS:+$BREW_PKGS }$1" ;; esac; }
if [ $COLOR -eq 1 ]; then
  R=$'\033[31m'; Y=$'\033[33m'; G=$'\033[32m'; B=$'\033[1m'; N=$'\033[0m'
else R=""; Y=""; G=""; B=""; N=""; fi
say()  { [ $EA -eq 1 ] || printf '%s\n' "$*"; }
hdr()  { say ""; say "${B}== $* ==${N}"; }
ok()   { PASS=$((PASS+1)); say "  ${G}PASS${N}  $*"; }
warn() { WARN=$((WARN+1)); say "  ${Y}WARN${N}  $*"; FINDINGS="${FINDINGS}WARN: $*; "; }
fail() { FAIL=$((FAIL+1)); say "  ${R}FAIL${N}  $*"; FINDINGS="${FINDINGS}FAIL: $*; "; }
info() { say "  INFO  $*"; }

rp() {
  if command -v realpath >/dev/null 2>&1; then realpath "$1" 2>/dev/null || echo "$1"
  else echo "$1"; fi
}
# seen KEY -> true if already processed, otherwise records it
seen() { case "|$SEEN|" in *"|$1|"*) return 0 ;; esac; SEEN="$SEEN|$1"; return 1; }
shopt -s nullglob

# Only emSign ECC Root CA - G3 (and its "Root TLS/CS CA - G3" sub-CAs, if a
# bundle carries them) is on the compromised path. G1, C1 and ECC C3 are not.
AFFECTED_RE='emSign (ECC Root CA|Root TLS CA|Root CS CA) - G3'
# classify <subject lines on stdin> -> prints "affected other names"
classify() {
  local lines aff oth names
  lines=$(grep -io 'emsign[^,/]*' | sed 's/[[:space:]]*$//' | sort -u)
  aff=$(printf '%s\n' "$lines" | grep -Eci "$AFFECTED_RE")
  oth=$(printf '%s\n' "$lines" | grep -ci emsign); oth=$((oth-aff))
  names=$(printf '%s\n' "$lines" | grep -v '^$' | paste -sd ';' -)
  printf '%s %s %s\n' "$aff" "$oth" "$names"
}

# ---- PEM bundle check -------------------------------------------------------
# check_bundle FILE LABEL [warn]  -> emSign present = FAIL (or WARN if 3rd arg)
# Sets LAST_BUNDLE_CLEAN=1 when the bundle parsed and had no emSign certs.
LAST_BUNDLE_CLEAN=0; LAST_BUNDLE_AFFECTED=0
check_bundle() {
  local f="$1" label="$2" sev="${3:-fail}" out total hits
  LAST_BUNDLE_CLEAN=0; LAST_BUNDLE_AFFECTED=0
  if [ ! -r "$f" ]; then warn "$label: not readable: $f"; return; fi
  f=$(rp "$f")
  if seen "pem:$f"; then info "$label: $f (already checked above)"; return; fi
  out=$(openssl crl2pkcs7 -nocrl -certfile "$f" 2>/dev/null \
        | openssl pkcs7 -print_certs -noout 2>/dev/null)
  total=$(printf '%s\n' "$out" | grep -c '^subject=')
  set -- $(printf '%s\n' "$out" | grep -i '^subject=.*emsign' | sed 's/^subject=//' | classify)
  local aff="${1:-0}" oth="${2:-0}" names="${3:-}"
  if [ "$total" -eq 0 ]; then
    warn "$label: could not parse certificates in $f"
  elif [ "$aff" -gt 0 ]; then
    LAST_BUNDLE_AFFECTED=1
    case "$f" in /opt/homebrew/*|/usr/local/*) queue_brew ca-certificates ;; esac
    if [ "$sev" = "warn" ]; then warn "$label: $f trusts emSign ECC Root CA - G3 (affected) [$total certs]"
    else fail "$label: $f trusts emSign ECC Root CA - G3 (affected) [$total certs]"; fi
  else
    LAST_BUNDLE_CLEAN=1
    if [ "$oth" -gt 0 ]; then ok "$label: $f ($total certs; unaffected emSign roots only)"
    else ok "$label: $f ($total certs, no emSign)"; fi
  fi
}

check_cert_dir() {
  local d="$1" label="$2" hits=0 c
  [ -d "$d" ] || { warn "$label: not a directory: $d"; return; }
  for c in "$d"/*; do
    [ -f "$c" ] || continue
    openssl x509 -in "$c" -noout -subject 2>/dev/null | grep -qi emsign && hits=$((hits+1))
  done
  if [ $hits -gt 0 ]; then fail "$label: $d contains $hits emSign cert(s)"
  else ok "$label: $d (no emSign)"; fi
}

# g3_aliases: keytool -list -v output on stdin -> every alias whose certificate
# is on the affected G3 path, ';'-separated. Vendors ship duplicates under
# different names (e.g. Corretto: "emsigneccrootca-g3" + "emsigneccrootcag3 [jdk]").
# G1 / G2 / C1 / C3 never match AFFECTED_RE, so they are never selected.
g3_aliases() {
  awk -v re="$AFFECTED_RE" '
    /^Alias name: / { a = substr($0, 13) }
    /^Owner:/ && tolower($0) ~ tolower(re) && a != "" { print a; a = "" }
  ' | sort -u | paste -sd';' -
}

# check_keystore KEYTOOL STORE PASSWORD LABEL [JDK_HOME]
check_keystore() {
  local kt="$1" ks="$2" pw="$3" label="$4" jh="${5:-}" out total hits
  LAST_KS_ALIAS=""
  [ -r "$ks" ] || { warn "$label: keystore not readable: $ks"; return; }
  ks=$(rp "$ks")
  if seen "ks:$ks"; then info "$label: $ks (already checked above)"; return; fi
  if [ -n "$pw" ]; then out=$("$kt" -list -v -keystore "$ks" -storepass "$pw" 2>/dev/null </dev/null)
  else out=$("$kt" -list -v -keystore "$ks" 2>/dev/null </dev/null); fi
  total=$(printf '%s\n' "$out" | grep -c '^Owner:')
  set -- $(printf '%s\n' "$out" | grep -i '^Owner:.*emsign' | classify)
  local aff="${1:-0}" alias
  if [ "$total" -eq 0 ]; then warn "$label: could not read $ks (password?)"
  elif [ "$aff" -gt 0 ]; then
    alias=$(printf '%s\n' "$out" | g3_aliases)
    case "$jh" in
      /Applications/*.app/*)
        warn "$label: IDE-bundled runtime trusts emSign ECC Root CA - G3; not edited (signed app). Set the IDE's Gradle JVM to a fixed JDK and update the IDE when its vendor ships a new runtime"
        return ;;
    esac
    disp=${alias//;/, }
    fail "$label: $ks trusts emSign ECC Root CA - G3 (alias: ${disp:-?}) [$total certs]"
    if [ -n "$jh" ]; then LAST_KS_ALIAS="$alias"
    elif [ -n "$alias" ]; then MANUAL+=("Remove alias(es) ${alias//;/, } from custom trust store $ks (keytool -delete)"); fi
  else ok "$label: $ks ($total certs, affected root absent)"; fi
}

# ver_ge A B -> true if version A >= B (dotted numeric)
ver_ge() {
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$2" ]
}

say "${B}eMudhra/emSign trust audit${N} - $(hostname -s) - user $(id -un) - $(date '+%Y-%m-%d %H:%M')"

# ---- macOS system trust -----------------------------------------------------
hdr "macOS system trust"
info "macOS $(sw_vers -productVersion 2>/dev/null)"
n=$(security find-certificate -a -c "emSign ECC Root CA - G3" \
      /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null | grep -c '"labl"')
info "Apple root store has emSign ECC Root CA - G3: $([ "$n" -gt 0 ] && echo yes || echo no). Apple blocks the 8 intermediates via revocation"
info "(since Oct 19) for Safari, Chrome and Security-framework apps; NOT for node --use-system-ca or OpenSSL tools."
override=0
for dom in "" "-d"; do
  if security dump-trust-settings $dom 2>/dev/null | grep -qi emsign; then
    fail "custom trust setting on an emSign cert (security dump-trust-settings $dom)"; override=1
  fi
done
[ $override -eq 0 ] && ok "no user/admin trust overrides for emSign certs"
check_bundle /etc/ssl/cert.pem "LibreSSL/system curl bundle (OS-managed)" warn

# ---- environment ------------------------------------------------------------
hdr "TLS environment variables"
SSL_CERT_FILE_CLEAN=0
for v in SSL_CERT_FILE NODE_EXTRA_CA_CERTS REQUESTS_CA_BUNDLE CURL_CA_BUNDLE GIT_SSL_CAINFO; do
  val=$(printenv "$v")
  if [ -n "$val" ]; then
    check_bundle "$val" "\$$v"
    [ "$v" = "SSL_CERT_FILE" ] && SSL_CERT_FILE_CLEAN=$LAST_BUNDLE_CLEAN
  fi
done
[ -n "${SSL_CERT_DIR:-}" ] && check_cert_dir "$SSL_CERT_DIR" "\$SSL_CERT_DIR"
[ "${NODE_TLS_REJECT_UNAUTHORIZED:-}" = "0" ] && fail "NODE_TLS_REJECT_UNAUTHORIZED=0 disables Node TLS verification"
[ -n "${GIT_SSL_NO_VERIFY:-}" ] && fail "GIT_SSL_NO_VERIFY is set (Git TLS verification off)"
[ -n "${NODE_OPTIONS:-}" ] && info "NODE_OPTIONS=$NODE_OPTIONS"
for rc in ~/.zshrc ~/.zprofile ~/.zshenv ~/.bash_profile ~/.bashrc ~/.profile; do
  [ -f "$rc" ] && grep -Eq 'NODE_TLS_REJECT_UNAUTHORIZED=["'\'']?0' "$rc" \
    && fail "$rc sets NODE_TLS_REJECT_UNAUTHORIZED=0"
done

# ---- Node.js ----------------------------------------------------------------
hdr "Node.js"
NODE_JS='const {X509Certificate}=require("crypto");const r=require("tls").rootCertificates;let n=0;for(const p of r){try{if(/emSign ECC Root CA - G3/i.test(new X509Certificate(p).subject))n++}catch(e){}}console.log(n+" "+r.length)'
node_mitigated=0
case "${NODE_OPTIONS:-}" in
  *--use-openssl-ca*) [ "$SSL_CERT_FILE_CLEAN" -eq 1 ] && node_mitigated=1 ;;
esac
found=0
for nb in "$(command -v node 2>/dev/null)" "${NVM_DIR:-$HOME/.nvm}"/versions/node/*/bin/node \
          ~/.volta/tools/image/node/*/bin/node ~/.fnm/node-versions/*/installation/bin/node \
          ~/.asdf/installs/nodejs/*/bin/node /opt/homebrew/bin/node /opt/homebrew/opt/node@*/bin/node \
          /usr/local/bin/node /usr/local/opt/node@*/bin/node; do
  [ -n "$nb" ] && [ -x "$nb" ] || continue
  r=$(rp "$nb"); seen "node:$r" && continue
  found=1
  # NODE_OPTIONS can hold flags older nodes reject (e.g. --use-system-ca < 22.15)
  ver=$(env -u NODE_OPTIONS "$nb" --version 2>/dev/null)
  [ -z "$ver" ] && ver=$(printf '%s' "$nb" | grep -o 'v[0-9][0-9]*\.[0-9][0-9.]*' | head -1)
  v=${ver#v}
  if [ -n "${NODE_OPTIONS:-}" ] && ! "$nb" --version >/dev/null 2>&1; then
    warn "node $ver ($nb): fails to start with current NODE_OPTIONS ($NODE_OPTIONS)"
  fi
  res=$(env -u NODE_OPTIONS "$nb" -e "$NODE_JS" 2>/dev/null); hits=${res%% *}
  # Fixed releases (21 Oct 2026) block the 8 intermediates in code; a remaining
  # emSign root in the bundle is then harmless, so the version decides.
  case "${v%%.*}" in
    22) need=22.23.4 ;; 24) need=24.22.1 ;; 26) need=26.12.1 ;;
    *) if ver_ge "$v" 27; then need=""; else need="EOL"; fi ;;
  esac
  if [ -z "$need" ] || { [ "$need" != "EOL" ] && ver_ge "$v" "$need"; }; then
    ok "node $ver ($nb): includes the eMudhra intermediate block"
  elif [ $node_mitigated -eq 1 ]; then
    warn "node $ver ($nb): unpatched, mitigated by --use-openssl-ca + clean SSL_CERT_FILE; upgrade anyway"
  elif [ "$need" = "EOL" ]; then
    fail "node $ver ($nb): end-of-life line, no fix; move to 22.23.4 / 24.22.1 / 26.12.1+"
    NODE_FIX+=("$nb|$v|24")
  else
    fail "node $ver ($nb): unpatched; upgrade to >= $need"
    NODE_FIX+=("$nb|$v|${v%%.*}")
  fi
done
[ $found -eq 0 ] && info "no node installs found"

if command -v npm >/dev/null 2>&1; then
  info "npm $(npm --version 2>/dev/null), registry $(npm config get registry 2>/dev/null)"
  caf=$(npm config get cafile 2>/dev/null)
  case "$caf" in ""|null|undefined) ok "npm: no custom cafile" ;; *) check_bundle "$caf" "npm cafile" ;; esac
  [ "$(npm config get strict-ssl 2>/dev/null)" = "false" ] && fail "npm strict-ssl=false (TLS verification off)"
fi
if command -v yarn >/dev/null 2>&1; then
  info "yarn $(yarn --version 2>/dev/null) (Yarn 1 uses the active node's TLS store, so it is fixed by the node upgrade)"
  caf=$(yarn config get cafile 2>/dev/null)
  case "$caf" in ""|null|undefined) ok "yarn: no custom cafile" ;; *) check_bundle "$caf" "yarn cafile" ;; esac
  [ "$(yarn config get strict-ssl 2>/dev/null)" = "false" ] && fail "yarn strict-ssl=false (TLS verification off)"
fi

# ---- Java -------------------------------------------------------------------
hdr "Java"
jhomes=$(/usr/libexec/java_home -V 2>&1 | grep '/' | sed 's/.* \(\/.*\)$/\1/')
found=0; anykt=""
# shellcheck disable=SC2086
for jh in ${JAVA_HOME:-} $jhomes ~/.sdkman/candidates/java/* ~/.asdf/installs/java/* \
          ~/Library/Java/JavaVirtualMachines/*/Contents/Home \
          /opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home \
          /usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home \
          /Applications/IntelliJ*.app/Contents/jbr/Contents/Home \
          /Applications/Android\ Studio*.app/Contents/jbr/Contents/Home; do
  [ -x "$jh/bin/keytool" ] || continue
  case "$jh" in */current) continue ;; esac
  r=$(rp "$jh"); seen "jdk:$r" && continue
  found=1; anykt="$jh/bin/keytool"
  jv=$("$jh/bin/java" -version 2>&1 | grep -v "^Picked up" | head -1)
  ks="$jh/lib/security/cacerts"; [ -f "$ks" ] || ks="$jh/jre/lib/security/cacerts"
  check_keystore "$jh/bin/keytool" "$ks" changeit "JDK [$jv] $jh" "$jh"
  bc="$jh/lib/security/blocked.certs"
  case "$jh" in /Applications/*.app/*) continue ;; esac
  needbc=0
  if [ -f "$bc.emudhra-installed" ]; then
    ok "JDK $jh: Oracle blocked.certs installed by this script ($(cat "$bc.emudhra-installed" 2>/dev/null))"
  else
    needbc=1
    warn "JDK $jh: Oracle's updated blocked.certs not installed (https://ops.java/emudhra; blocks the Sectigo cross-signed copies)"
  fi
  if [ -n "$LAST_KS_ALIAS" ] || [ $needbc -eq 1 ]; then JDK_FIX+=("$jh|$ks|$LAST_KS_ALIAS|$needbc"); fi
done
[ $found -eq 0 ] && info "no JDKs found"

for o in "${JAVA_TOOL_OPTIONS:-}" "${JDK_JAVA_OPTIONS:-}"; do
  ts=$(printf '%s' "$o" | grep -o 'javax.net.ssl.trustStore=[^ ]*' | cut -d= -f2)
  pw=$(printf '%s' "$o" | grep -o 'javax.net.ssl.trustStorePassword=[^ ]*' | cut -d= -f2)
  [ -n "$ts" ] && [ -n "$anykt" ] && check_keystore "$anykt" "$ts" "$pw" "JVM options trustStore"
done
gp=~/.gradle/gradle.properties
if [ -f "$gp" ]; then
  ts=$(grep -E '^systemProp.javax.net.ssl.trustStore=' "$gp" | cut -d= -f2-)
  pw=$(grep -E '^systemProp.javax.net.ssl.trustStorePassword=' "$gp" | cut -d= -f2-)
  tt=$(grep -E '^systemProp.javax.net.ssl.trustStoreType=' "$gp" | cut -d= -f2-)
  if [ "$tt" = "KeychainStore" ]; then info "Gradle uses the macOS keychain trust (KeychainStore)"
  elif [ -n "$ts" ] && [ -n "$anykt" ]; then check_keystore "$anykt" "$ts" "$pw" "Gradle trustStore"
  else ok "Gradle: no custom trustStore in $gp"; fi
fi

# ---- Python -----------------------------------------------------------------
hdr "Python"
PY_JS='import ssl,sys
p=ssl.get_default_verify_paths()
print("cafile|"+(p.openssl_cafile or ""))
try:
    import certifi; print("certifi|"+certifi.__version__+"|"+certifi.where())
except Exception: pass'
pys="$(command -v python3 2>/dev/null)"
xcode-select -p >/dev/null 2>&1 || pys=$(printf '%s' "$pys" | grep -v '^/usr/bin/python3$')
found=0
for py in $pys /opt/homebrew/bin/python3* /usr/local/bin/python3* \
          /Library/Frameworks/Python.framework/Versions/*/bin/python3 \
          ~/.pyenv/versions/*/bin/python3 ~/.asdf/installs/python/*/bin/python3; do
  case "$py" in *-config) continue ;; esac
  [ -x "$py" ] || continue
  r=$(rp "$py"); seen "py:$r" && continue
  found=1
  pv=$("$py" -V 2>&1)
  out=$("$py" -c "$PY_JS" 2>/dev/null)
  caf=$(printf '%s\n' "$out" | grep '^cafile|' | cut -d'|' -f2)
  [ -n "$caf" ] && [ -f "$caf" ] && check_bundle "$caf" "$pv ssl default"
  cline=$(printf '%s\n' "$out" | grep '^certifi|')
  if [ -n "$cline" ]; then
    cv=$(echo "$cline" | cut -d'|' -f2); cw=$(echo "$cline" | cut -d'|' -f3)
    info "$pv ($py): certifi $cv (fixed in 2026.10.19)"
    check_bundle "$cw" "$pv certifi"
    [ "$LAST_BUNDLE_AFFECTED" -eq 1 ] && CERTIFI_FIX+=("$py")
  fi
done
[ $found -eq 0 ] && info "no python3 installs found"
info "virtualenvs and pipx tools carry their own certifi; use --deep to find them"

# ---- Go ---------------------------------------------------------------------
hdr "Go"
found=0
for g in "$(command -v go 2>/dev/null)" /usr/local/go/bin/go /opt/homebrew/bin/go ~/sdk/go*/bin/go; do
  [ -n "$g" ] && [ -x "$g" ] || continue
  r=$(rp "$g"); seen "go:$r" && continue
  found=1
  gv=$("$g" env GOVERSION 2>/dev/null); v=${gv#go}; v=${v%%[!0-9.]*}
  mm=$(echo "$v" | cut -d. -f1,2)
  case "$mm" in
    1.26) need=1.26.10 ;; 1.27) need=1.27.3 ;;
    *) if ver_ge "$v" 1.28; then need=""; else need="1.26.10"; fi ;;
  esac
  if [ -z "$need" ] || ver_ge "$v" "$need"; then ok "$gv ($g): includes the key-based block"
  else
    fail "$gv ($g): binaries built with it lack the block (CVE-2026-111943); upgrade to >= $need and rebuild"
    case "$r" in /opt/homebrew/*|/usr/local/Cellar/*) queue_brew go ;;
      *) MANUAL+=("Upgrade Go at $g to >= $need (https://go.dev/dl), then rebuild your Go tools") ;; esac
  fi
done
[ $found -eq 0 ] && info "go not installed"

# ---- curl / OpenSSL / Homebrew bundles ---------------------------------------
hdr "Homebrew / OpenSSL bundles"
found=0
for f in /opt/homebrew/etc/ca-certificates/cert.pem /opt/homebrew/etc/openssl@3/cert.pem \
         /opt/homebrew/etc/openssl@1.1/cert.pem /usr/local/etc/ca-certificates/cert.pem \
         /usr/local/etc/openssl@3/cert.pem /usr/local/etc/openssl@1.1/cert.pem; do
  [ -e "$f" ] || continue
  found=1; check_bundle "$f" "Homebrew bundle"
done
[ $found -eq 0 ] && info "no Homebrew CA bundles found"
[ $found -eq 1 ] && info "fix for Homebrew bundles: brew upgrade ca-certificates"

# ---- Git --------------------------------------------------------------------
hdr "Git"
# /usr/bin/git is a stub that pops an install dialog when the Command Line Tools are missing
if command -v git >/dev/null 2>&1 && { xcode-select -p >/dev/null 2>&1 || [ "$(command -v git)" != /usr/bin/git ]; }; then
  ci=$(git config --get http.sslCAInfo 2>/dev/null)
  [ -n "$ci" ] && check_bundle "$ci" "git http.sslCAInfo"
  [ "$(git config --get http.sslVerify 2>/dev/null)" = "false" ] && fail "git http.sslVerify=false"
  git config --get-regexp '^http\..*\.sslverify$' 2>/dev/null | grep -qi ' false$' \
    && warn "git has per-URL sslVerify=false entries (git config --get-regexp sslverify)"
  [ -z "$ci" ] && ok "git: default trust (Apple keychain/system)"
fi

# ---- other runtimes ----------------------------------------------------------
hdr "Other runtimes"
rb=$(command -v ruby 2>/dev/null)
if [ -n "$rb" ]; then
  cf=$("$rb" -ropenssl -e 'print OpenSSL::X509::DEFAULT_CERT_FILE' 2>/dev/null)
  [ -n "$cf" ] && [ -f "$cf" ] && check_bundle "$cf" "ruby $("$rb" -e 'print RUBY_VERSION' 2>/dev/null)"
fi
command -v cargo >/dev/null 2>&1 && info "Rust: per project, webpki-roots must be >= 1.0.10 (check Cargo.lock)"
command -v composer >/dev/null 2>&1 && info "PHP Composer: composer/ca-bundle fix pending upstream"
command -v docker >/dev/null 2>&1 && info "Docker: images carry their own CA bundles; rebuild on patched bases"

# ---- deep scan ----------------------------------------------------------------
if [ $DEEP -eq 1 ]; then
  hdr "Deep scan: vendored PEM bundles in \$HOME and /Applications"
  while IFS= read -r f; do
    check_bundle "$f" "vendored"
  done < <(find "$HOME" /Applications \( -path "$HOME/Library/Caches" -o -path "$HOME/.Trash" \) -prune -o \
             -type f \( -name 'cacert.pem' -o -name 'ca-bundle.crt' -o -name 'ca-bundle.pem' \
             -o -name 'ca-certificates.crt' \) -print 2>/dev/null)
fi

# ---- summary -------------------------------------------------------------------
if [ $FAIL -gt 0 ]; then st="EXPOSED"; rc=2
elif [ $WARN -gt 0 ]; then st="WARN"; rc=1
else st="CLEAN"; rc=0; fi

if [ $EA -eq 1 ]; then
  echo "<result>$st ($FAIL fail, $WARN warn) ${FINDINGS% }</result>"
  exit 0
fi
say ""
say "${B}Result: $st${N}  pass=$PASS warn=$WARN fail=$FAIL"

[ $FAIL -eq 0 ] && [ ${#JDK_FIX[@]} -eq 0 ] && exit $rc
[ $AUDIT_ONLY -eq 1 ] && exit $rc
if [ $YES -eq 0 ] && ! [ -t 0 ]; then exit $rc; fi   # nobody to ask

# =============================================================================
# Remediation
# =============================================================================
FIXED=0; SKIPPED=0; ERRORS=0
ask() {   # ask "question" -> 0 for yes
  local r
  [ $YES -eq 1 ] && { say "  $1 [auto-yes]"; return 0; }
  printf '  %s [y/N] ' "$1"; read -r r </dev/tty || return 1
  case "$r" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}
done_()  { FIXED=$((FIXED+1));   say "  ${G}FIXED${N} $*"; }
skip_()  { SKIPPED=$((SKIPPED+1)); say "  SKIP  $*"; }
err_()   { ERRORS=$((ERRORS+1));  say "  ${R}ERROR${N} $*"; }

say ""
say "${B}Remediation available${N}"
[ ${#NODE_FIX[@]} -gt 0 ]    && say "  - Node: ${#NODE_FIX[@]} unpatched install(s)"
[ -n "$BREW_PKGS" ]          && say "  - Homebrew: brew upgrade $BREW_PKGS"
[ ${#JDK_FIX[@]} -gt 0 ]     && say "  - Java: ${#JDK_FIX[@]} JDK(s) (cacerts root removal and/or Oracle blocked.certs)"
[ ${#CERTIFI_FIX[@]} -gt 0 ] && say "  - Python: certifi in ${#CERTIFI_FIX[@]} interpreter(s)"
[ ${#MANUAL[@]} -gt 0 ]      && say "  - ${#MANUAL[@]} manual step(s), listed at the end"
say ""
if ! ask "Proceed to remediation? Each fix is confirmed separately."; then
  say "  No changes made."; exit $rc
fi

# ---- Node -------------------------------------------------------------------
if [ ${#NODE_FIX[@]} -gt 0 ]; then
  hdr "Fix: Node.js"
  NVM_SH="${NVM_DIR:-$HOME/.nvm}/nvm.sh"
  nvm_ok=0
  # shellcheck disable=SC1090
  [ -s "$NVM_SH" ] && . "$NVM_SH" >/dev/null 2>&1 && command -v nvm >/dev/null 2>&1 && nvm_ok=1
  majors=""; old_nvm=()
  for e in "${NODE_FIX[@]}"; do
    nb=${e%%|*}; rest=${e#*|}; v=${rest%%|*}; mj=${rest##*|}
    case "$nb" in
      "${NVM_DIR:-$HOME/.nvm}"/*)
        case " $majors " in *" $mj "*) ;; *) majors="${majors:+$majors }$mj" ;; esac
        old_nvm+=("$v") ;;
      /opt/homebrew/*|/usr/local/*)
        f=$(rp "$nb"); case "$f" in *node@*) p=$(echo "$f" | grep -o 'node@[0-9]*') ;; *) p=node ;; esac
        queue_brew "$p" ;;
      *) MANUAL+=("Upgrade node $v at $nb (Volta: volta install node@$mj; fnm/asdf: install $mj latest)") ;;
    esac
  done
  if [ -n "$majors" ]; then
    if [ $nvm_ok -eq 0 ]; then
      err_ "nvm installs found but $NVM_SH could not be loaded; run: nvm install <major> for: $majors"
    else
      def=$(nvm version default 2>/dev/null); def=${def#v}
      for mj in $majors; do
        if ask "nvm install $mj (latest $mj.x, carries global packages over)?"; then
          if nvm install "$mj" --reinstall-packages-from="$mj" >/dev/null 2>&1 || nvm install "$mj" >/dev/null 2>&1; then
            done_ "node $(nvm version "$mj") installed"
            if [ "${def%%.*}" = "$mj" ]; then nvm alias default "$mj" >/dev/null && done_ "nvm default -> $mj"; fi
          else err_ "nvm install $mj failed (network/proxy?)"; fi
        else skip_ "node $mj"; fi
      done
      # default on an end-of-life line -> offer 24
      case "${def%%.*}" in
        22|24|26) ;;
        *) case " ${old_nvm[*]} " in *" $def "*)
             if ask "Your default node $def is end-of-life. Set nvm default to 24?"; then
               nvm alias default 24 >/dev/null && done_ "nvm default -> 24"
             fi ;;
           esac ;;
      esac
      if ask "Uninstall the old flagged versions (${old_nvm[*]})?"; then
        nvm use default >/dev/null 2>&1
        for v in "${old_nvm[@]}"; do
          if nvm uninstall "$v" >/dev/null 2>&1; then done_ "removed node $v"
          else err_ "could not remove node $v (in use?)"; fi
        done
      else skip_ "old node versions kept; they stay vulnerable"; fi
    fi
  fi
fi

# ---- Homebrew -----------------------------------------------------------------
if [ -n "$BREW_PKGS" ]; then
  hdr "Fix: Homebrew"
  if command -v brew >/dev/null 2>&1; then
    if ask "brew update && brew upgrade $BREW_PKGS?"; then
      # shellcheck disable=SC2086
      if brew update >/dev/null 2>&1 && brew upgrade $BREW_PKGS; then done_ "brew upgrade $BREW_PKGS"
      else err_ "brew upgrade failed; re-run it manually to see why"; fi
      case " $BREW_PKGS " in *" go "*) MANUAL+=("Rebuild Go binaries you built or 'go install'ed with the old toolchain") ;; esac
    else skip_ "Homebrew packages"; fi
  else err_ "brew not on PATH"; fi
fi

# ---- Java -------------------------------------------------------------------
if [ ${#JDK_FIX[@]} -gt 0 ]; then
  hdr "Fix: Java"
  bcnew=""
  bc_failed=0
  # fetch_url URL OUT -> 0 on success, FETCH_ERR set on failure.
  # A browser on macOS uses the keychain and the system/PAC proxy; /usr/bin/curl
  # uses neither. Retry with admin-installed keychain roots (TLS inspection CAs)
  # and the system proxy from scutil when the plain attempt fails.
  fetch_url() {
    local url="$1" out="$2" rc e bundle="" px="" opts=""
    e=$(curl -fsSL --max-time 30 -o "$out" "$url" 2>&1); rc=$?
    [ $rc -eq 0 ] && return 0
    FETCH_ERR="curl exit $rc: ${e:-no detail}"
    if [ $rc -eq 22 ] && printf '%s' "$e" | grep -q ' 403'; then
      FETCH_ERR="$FETCH_ERR | the server rejects scripted downloads; host a vetted copy internally (BLOCKED_CERTS_URL) or use a browser download (BLOCKED_CERTS_FILE)"
      return 1
    fi
    if [ "$(uname)" = Darwin ]; then
      if [ $rc -eq 60 ] || [ $rc -eq 35 ] || [ $rc -eq 77 ]; then
        bundle=$(mktemp "${TMPDIR:-/tmp}/kc-roots.XXXXXX")
        { cat /etc/ssl/cert.pem 2>/dev/null
          security find-certificate -a -p /Library/Keychains/System.keychain 2>/dev/null
        } > "$bundle"
        opts="--cacert $bundle"
      fi
      if [ -z "${https_proxy:-}${HTTPS_PROXY:-}" ]; then
        px=$(scutil --proxy 2>/dev/null | awk '/HTTPSEnable : 1/{on=1} /HTTPSProxy :/{h=$3} /HTTPSPort :/{p=$3} END{if(on&&h)print h":"p}')
        [ -n "$px" ] && opts="$opts --proxy http://$px"
      fi
      if [ -n "$opts" ]; then
        e=$(curl -fsSL --max-time 30 $opts -o "$out" "$url" 2>&1); rc=$?
        [ -n "$bundle" ] && rm -f "$bundle"
        [ $rc -eq 0 ] && { say "        (downloaded using${px:+ system proxy $px}${bundle:+ keychain-installed CAs})"; return 0; }
        FETCH_ERR="$FETCH_ERR | retry with${px:+ system proxy}${bundle:+ keychain CAs}: curl exit $rc: ${e:-no detail}"
      fi
      if scutil --proxy 2>/dev/null | grep -q 'ProxyAutoConfigEnable : 1'; then
        FETCH_ERR="$FETCH_ERR | note: this Mac uses a PAC proxy file, which curl cannot read; set https_proxy"
      fi
    fi
    return 1
  }
  get_blocked() {   # fetch + sanity check Oracle's blocked.certs once per run
    [ -n "$bcnew" ] && return 0
    [ $bc_failed -eq 1 ] && return 1
    local src="${BLOCKED_CERTS_FILE:-}" p
    bcnew=$(mktemp "${TMPDIR:-/tmp}/blocked.certs.XXXXXX") || return 1
    if [ -n "$src" ]; then
      cp "$src" "$bcnew" 2>/dev/null || { err_ "cannot read BLOCKED_CERTS_FILE=$src"; src=""; }
    fi
    if [ -z "$src" ]; then
      if fetch_url "$BLOCKED_CERTS_URL" "$bcnew"; then
        src="$BLOCKED_CERTS_URL"
      else
        err_ "download failed: $BLOCKED_CERTS_URL"
        say "        $FETCH_ERR"
        say "        Download it in a browser from https://ops.java/emudhra (non-Windows file)."
        if [ $YES -eq 0 ]; then
          printf '  Path to the downloaded blocked.certs (Enter to skip): '
          read -r p </dev/tty || p=""
          p=${p/#\~/$HOME}; p=${p%\"}; p=${p#\"}
          [ -n "$p" ] && cp "$p" "$bcnew" 2>/dev/null && src="$p"
        fi
      fi
    fi
    if [ -z "$src" ]; then rm -f "$bcnew"; bcnew=""; bc_failed=1; return 1; fi
    if [ -n "${BLOCKED_CERTS_SHA256:-}" ]; then
      local got
      got=$(shasum -a 256 "$bcnew" 2>/dev/null || sha256sum "$bcnew"); got=${got%% *}
      if [ "$got" != "$BLOCKED_CERTS_SHA256" ]; then
        err_ "$src: SHA-256 $got does not match BLOCKED_CERTS_SHA256; not installing"
        rm -f "$bcnew"; bcnew=""; bc_failed=1; return 1
      fi
    fi
    if ! head -1 "$bcnew" | grep -q '^Algorithm='; then
      err_ "$src does not look like a blocked.certs file (no Algorithm= header); not installing"
      rm -f "$bcnew"; bcnew=""; bc_failed=1; return 1
    fi
    BC_SRC="$src"
    return 0
  }
  stamp=$(date +%Y%m%d%H%M%S)
  jdk_changed=0
  for e in "${JDK_FIX[@]}"; do
    IFS='|' read -r jh ks alias needbc <<EOF
$e
EOF
    say ""; say "  JDK: $jh"
    SUDO=""
    if [ ! -w "$ks" ] || [ ! -w "$(dirname "$ks")" ]; then
      if [ $YES -eq 1 ]; then skip_ "$ks needs admin rights; re-run interactively"; continue; fi
      ask "$ks is not writable by you. Use sudo?" || { skip_ "$jh"; continue; }
      SUDO="sudo"
    fi
    if [ -z "$alias" ]; then :
    else
      n_al=$(printf '%s' "$alias" | awk -F';' '{print NF}')
      if ask "Back up cacerts and delete $n_al emSign ECC Root CA - G3 alias(es): ${alias//;/, }?"; then
        if $SUDO cp -p "$ks" "$ks.bak-$stamp"; then
          # read -a: no pathname expansion ("[jdk]" is a glob and nullglob is on)
          IFS=';' read -r -a al_list <<< "$alias"
          for al in "${al_list[@]}"; do
            if $SUDO "$jh/bin/keytool" -delete -keystore "$ks" -storepass changeit -alias "$al" >/dev/null 2>&1; then
              done_ "removed '$al'"; jdk_changed=1
            else err_ "keytool could not delete '$al' from $ks"; fi
          done
          left=$("$jh/bin/keytool" -list -v -keystore "$ks" -storepass changeit 2>/dev/null </dev/null | g3_aliases)
          if [ -n "$left" ]; then err_ "G3 alias(es) still present in $ks: ${left//;/, }"
          else say "        backup: $ks.bak-$stamp; no G3 aliases remain"; fi
        else err_ "could not back up $ks; nothing deleted"; fi
      else skip_ "cacerts root removal"; fi
    fi

    bc="$jh/lib/security/blocked.certs"
    [ "$needbc" = "1" ] || continue
    if ask "Install Oracle's updated blocked.certs (merged with existing entries)?" && get_blocked; then
      merged=$(mktemp "${TMPDIR:-/tmp}/blocked.merged.XXXXXX")
      hdrline=$(head -1 "$bcnew")
      if [ -f "$bc" ] && [ "$(head -1 "$bc")" != "$hdrline" ]; then
        err_ "existing $bc uses a different algorithm header; install manually"; rm -f "$merged"; continue
      fi
      { echo "$hdrline"
        { tail -n +2 "$bcnew"; [ -f "$bc" ] && tail -n +2 "$bc"; } | grep -v '^[[:space:]]*$' | sort -u
      } > "$merged"
      if { [ ! -f "$bc" ] || $SUDO cp -p "$bc" "$bc.bak-$stamp"; } && $SUDO cp "$merged" "$bc" && $SUDO chmod 644 "$bc"; then
        done_ "blocked.certs installed ($(($(wc -l < "$merged")-1)) entries)"; jdk_changed=1
        echo "$(date '+%Y-%m-%d') from $BC_SRC" | $SUDO tee "$bc.emudhra-installed" >/dev/null
      else err_ "could not write $bc"; fi
      rm -f "$merged"
    else skip_ "blocked.certs"; fi
  done
  [ -n "$bcnew" ] && rm -f "$bcnew"
  if [ $jdk_changed -eq 1 ]; then
    if command -v gradle >/dev/null 2>&1; then gradle --stop >/dev/null 2>&1 && done_ "stopped Gradle daemons"
    else MANUAL+=("Run ./gradlew --stop in your projects so Gradle daemons pick up the new trust store"); fi
    MANUAL+=("brew upgrade / new JDK installs restore the old cacerts: re-run this script after each until a fixed JDK ships")
  fi
fi

# ---- Python -----------------------------------------------------------------
if [ ${#CERTIFI_FIX[@]} -gt 0 ]; then
  hdr "Fix: Python certifi"
  for py in "${CERTIFI_FIX[@]}"; do
    if ask "$py -m pip install -U certifi?"; then
      if "$py" -m pip install -q -U certifi 2>/dev/null; then
        done_ "certifi $("$py" -c 'import certifi;print(certifi.__version__)' 2>/dev/null) in $py"
      else
        err_ "pip failed for $py (externally managed? use its venv or: pipx upgrade-all)"
      fi
    else skip_ "$py"; fi
  done
fi

# ---- wrap-up ------------------------------------------------------------------
say ""
say "${B}Remediation: fixed=$FIXED skipped=$SKIPPED errors=$ERRORS${N}"
if [ ${#MANUAL[@]} -gt 0 ]; then
  say "Manual steps:"
  for m in "${MANUAL[@]}"; do say "  - $m"; done
fi
say ""
say "${B}Verification run${N}"
args="--audit-only"; [ $DEEP -eq 1 ] && args="$args --deep"; [ $COLOR -eq 0 ] && args="$args --no-color"
# shellcheck disable=SC2086
exec /bin/bash "$0" $args
