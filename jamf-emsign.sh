#!/bin/bash
# jamf-emsign.sh - audit (and optionally remediate) macOS TLS trust after the
# October 2026 eMudhra/emSign intermediate CA key compromise. One script for
# developers (run as yourself) and for Jamf (run as root). Stock bash 3.2.
#
# How certificates are judged (folded in from the v2.0 review build):
#   - by public key, against the disclosure site's identities: 4 anchor roots
#     (emSign ECC/TLS/CS G3, AAA Certificate Services) and the 8 compromised
#     intermediate keys. Names alone only ever trigger a review.
#   - strictly: one malformed or non-certificate block = no verdict for the file.
#   - once: each file is judged once per pass (real path + content hash).
#   - Java by blocked.certs: fixed when it blocks all 16 compromised certificates.
#   - runtimes are probed from / with stdin closed, a time limit, and the
#     variables that load extra code removed (NODE_OPTIONS, JAVA_TOOL_OPTIONS,
#     GOTOOLCHAIN downloads...). Every finding carries the fix; each run ends
#     with a plain summary: STATUS, Fix now, Waiting on a vendor, Review.
#
# ============================================================================
# FLEET MODE (Jamf policy, runs as root)
# ============================================================================
# Jamf script parameters:
#   $4  Mode                 audit | remediate          (default: audit)
#   $5  blocked.certs URL    optional: newer Oracle list to use instead of the
#                            embedded one (only when Oracle publishes an update)
#   $6  blocked.certs SHA256 required with $5
#   $7  Verbose logging      1 | 0                      (default: 1)
#   $8  Fail policy if exposed  yes | no                (default: yes)
#   $9  Run jamf recon after    yes | no                (default: no)
#   $10 Users to scan        all | console              (default: all)
#   $11 Also remove the emSign ECC Root CA - G3 alias from unpatched JDK cacerts
#                            yes | no                   (default: no; the blocklist
#                            is the fix, root removal is extra and destructive)
#
# How it runs:
#   - A system pass (root) checks macOS trust, /etc/ssl/cert.pem and root-owned
#     runtimes (e.g. JDKs in /Library/Java, pkg-installed Node/Go).
#   - Then one pass per local user (UID >= 501 with a home folder), run AS that
#     user with a clean environment, checks what that user owns: nvm/Homebrew/
#     SDKMAN JDKs, Node, Python, Go, Homebrew bundles, ~/.npmrc, Git config.
#   - Owner rule: a binary is only ever executed by the account that owns it.
#     Root never runs user-writable binaries.
#   - Java is judged by lib/security/blocked.certs: a JDK is fixed when it holds
#     every fingerprint in Oracle's list (embedded below, no download needed).
#     Patched vendor JDKs keep the emSign root in cacerts; that is expected.
#   - remediate fixes Java only, unattended: merges Oracle's list into the
#     blocklist each unpatched JDK reads (lib/security/blocked.certs, or
#     jre/lib/security/blacklisted.certs on Java 8), with a backup, and verifies
#     the result. With $11 = yes it also deletes the emSign G3 root alias(es).
#     AAA Certificate Services is never removed: it anchors unrelated Sectigo
#     chains, and the blocklist already rejects the cross-signed intermediates.
#     Node, Homebrew, pip and uv changes need the developer (network installs,
#     side effects such as extra brew upgrades), so they are reported as actions.
#   - IDE-bundled runtimes (IntelliJ, Android Studio) are never edited.
#
# Result states (per machine; also the dev-mode result):
#   PROTECTED       every inspected runtime rejects the compromised chains
#   EXPOSED         something accepts them and a fix is available
#   UNVERIFIED      something could not be proven (unreadable/malformed data,
#                   timeouts, errors, incomplete user pass)
#   VENDOR_PENDING  only exposures with no fix yet (macOS /etc/ssl/cert.pem,
#                   signed IDE runtimes)
#   Advisories (WARN) never change the state.
#
# Outputs:
#   - stdout (Jamf policy log) and /var/log/emsign-check.log (rotated at 5 MB)
#   - /Library/Application Support/emsign-check/status.plist
#   - exit 0 = PROTECTED or VENDOR_PENDING; 1 = EXPOSED or UNVERIFIED (when $8 = yes);
#     2 = bad parameters or the script could not run
#
# Extension attribute (reads the status file; no rescan at recon):
#   #!/bin/bash
#   f="/Library/Application Support/emsign-check/status.plist"
#   [ -f "$f" ] || { echo "<result>Not run</result>"; exit 0; }
#   r=$(/usr/libexec/PlistBuddy -c "Print :Result" "$f" 2>/dev/null)
#   d=$(/usr/libexec/PlistBuddy -c "Print :LastRun" "$f" 2>/dev/null)
#   echo "<result>$r ($d)</result>"
#
# Local test as root, same code path as Jamf:
#   sudo ./jamf-emsign.sh / "$(hostname)" "$USER" audit
#   sudo ./jamf-emsign.sh / "$(hostname)" "$USER" remediate "" "" 1 no no console
#   or flags:  sudo ./jamf-emsign.sh --mode=audit --verbose --users=console
#
# ============================================================================
# DEVELOPER MODE (run as yourself, not root)
# ============================================================================
#   ./jamf-emsign.sh [--deep] [--audit-only] [--yes] [--verbose] [--ea] [--no-color]
#   Audits, then (at a terminal) asks before each fix: Node (nvm), Homebrew,
#   Java, pip, certifi, uv. --yes approves non-destructive fixes only; removing
#   Node versions or cacerts roots needs an interactive answer or
#   --allow-destructive. --remove-roots offers the emSign G3 root removal.
#   Exit 0 PROTECTED, 1 VENDOR_PENDING, 2 EXPOSED, 3 UNVERIFIED.
#   Optional override of the embedded Oracle list (newer file from Oracle):
#   BLOCKED_CERTS_FILE or BLOCKED_CERTS_URL, plus BLOCKED_CERTS_SHA256
#
# Limitation: three compromised intermediates were also cross-signed by
# Sectigo's AAA Certificate Services root, which stays in every bundle. Only
# revocation checking or a key-based block (patched Go/Node, blocked.certs)
# covers that path.

set -u
shopt -s nullglob
VERSION="3.0.0"
ORG_DIR="/Library/Application Support/emsign-check"
STATUS_PLIST="$ORG_DIR/status.plist"
LOGFILE="${EMSIGN_LOGFILE:-/var/log/emsign-check.log}"
# Fleet passes use only system tool directories. /opt/homebrew and /usr/local
# are owned by a user, so root must never resolve openssl, curl, shasum etc.
# there. Runtimes in those places are found by explicit path and executed only
# by the account that owns them.
SYS_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
# Certificates are identified by public key (see "Certificate identity" below).
ME=$(id -un)
START_EPOCH=$(date +%s)

# ---- Oracle blocked.certs (embedded) ------------------------------------------
# Oracle's eMudhra blocklist from https://ops.java/emudhra (non-Windows file),
# downloaded in a browser and verified by the team: 86 SHA-256 fingerprints,
# including the eMudhra intermediates and their Sectigo cross-signs. Patched
# vendor JDKs (Oracle/OpenJDK x.0.2, Corretto 21.0.13.0.10, Zulu respins) ship
# these entries in lib/security/blocked.certs and keep the emSign root in
# cacerts, so the blocklist (not the root) decides whether a JDK is fixed.
EMBED_SHA=2596bb6dda83c66d96c5a252d7b2ae1f24cc1ae3f1890223b4f3591a8d52bf10
embedded_blocklist() {
cat <<'ORACLE_BLOCKED_CERTS'
Algorithm=SHA-256
0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19
03DB9E5E79FE6117177F81C11595AF598CB176AF766290DBCEB2C318B32E39A2
08C396C006A21055D00826A5781A5CCFCE2C8D053AB3C197637A4A7A5BB9A650
10E7E5BFDB55CFB78D0C21366654046182087A1960C079682513795665AA0C6B
14E6D2764A4B06701C6CBC376A253775F79C782FBCB6C0EE6F99DE4BA1024ADD
169A0523C5E071AA4E298286DBD4EE0E40C8C06ABB6B0C077D132F001FA19240
1C5E6985ACC09221DBD1A4B7BBC6D3A8C3F8540D19F20763A9537FDD42B4FFE7
1F6BF8A3F2399AF7FD04516C2719C566CBAD51F412738F66D0457E1E6BDE6F2D
21182E577E5106B669322ABE6086FFF6B101E8C83FD2D01DC32D854961AAC832
2A464E4113141352C7962FBD1706ED4B88533EF24D7BBA6CCC5D797FD202F1C4
31C8FD37DB9B56E708B03D1F01848B068C6DA66F36FB5D82C008C6040FA3E133
33C1BCDC6DA52DF950B3B14121127DA1955F7F31F828497A7608986EB2DDCC09
37E866582D43C35D7C17D47794B974F291B3047B868DC123382477F7A08AEFA8
3946901F46B0071E90D78279E82FABABCA177231A704BE72C5B0E8918566EA66
3B88E4B77FC53C45CA216700E39FC0EA7621A0A40FCB268215082E35D2BD5829
3C5456D4219BA2372273867FAC9A07104600391E96C7FDCDE3B4420C0F1F69BF
3E11CF90719F6FB44D94EAC9A156B89BEBE7B8598F28EC58913F2BFCAF91D0C0
423279423B9FC8CB06F1BB7C3B247522B948D5F18939F378ECC901126DE40BFB
42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493
432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3
450F1B421BB05C8609854884559C323319619E8B06B001EA2DCBB74A23AA3BE2
45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE
4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1
4CBBF8256BC9888A8007B2F386940A2E394378B0D903CBB3863C5A6394B889CE
4DED6F955374E40B8558A611A9719B2AB69AA6852AC50966EDC4B07DE4D4277C
4FEE0163686ECBD65DB968E7494F55D84B25486D438E9DE558D629D28CD4D176
50E71B08B9AC407B93D50EE90100CB6B6B41C956DC7AA86C5BAA38AE713CFD6A
535D04DFCE027C70BD5F8A9E0AD4F218E9AFDCF5BBCF9B6DE0D81E148E2E3172
558EC6CA13DA9B800FEDC9ACC3C18CA98BB19768F1309B60B5BB89793B3481CB
568FAF38D9F155F624838E2181B1CEB4D8459305EE652B0F810C97C3611BFE19
579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512
585CFE6B7436CBD4E732763A2137D7F49599BA9B1790E688FCEC799C58EB84A6
59CC5FD35A737B84682EDA26AD23F5ADE8AA847D5BEB3B38AB6CD62347925A66
5D8FC3ECDDB4DDB243AEE5C306BCFDE670ADF2D66B193DD3AA2D6B2FB91869BE
5E83124D68D24E8E177E306DF643D5EA99C5A94D6FC34B072F7544A1CABB7C7B
5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699
62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72
71CB00749B9130FB2707A2664BFF958D0FCC8E161D9674C7450BA0FC2BEAF9D3
7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489
75D8853BE99C87678E6C7BF9F684B31454D81DEB1C7F37B9FBC026A268337536
76A45A496031E4DD2D7ED23E8F6FF97DBDEA980BAAC8B0BA94D7EDB551348645
7BA62FEC54E9D040556FCA70A6A88F03761C178FA1F7CB8390A73076849F55A2
84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD
8A1BD21661C60015065212CC98B1ABB50DFD14C872A208E66BAE890F25C448AF
8F580C6E34CEE7EE57B93BA9C0AC5FAEDD7BF3085F5EE9C6C0175A2555B111D0
8FED925362F62FFF90DD835BE6ADC32B02DEC8DF5E82D83E512F1C977D066E82
912A48745BFF2F14D1798B27858613DE1C0EB03C2BDE630AFD0DDD5251E1EBE1
98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B
9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4
9E7617035CFF537C837E078A7CDC7FD9EB77BCE7DDF3DC6DBD5C50AAFC1F1FA7
9ED8F9B0E8E42A1656B8E1DD18F42BA42DC06FE52686173BA2FC70E756F207DC
9FADCE80D62A959F9930D748488C1E22E821F4E1E4A43584B848C2FC11E04D77
A0ED2032C5249EE1A653F1F88005D9E779E385DF533B5C521137CEE5176CD7FC
A104B1314DF8E02F7DE27DDC287D0961D6E6824AD4DAFC3D11064F24C1B653D5
A4328E058C867AF9CA8D468C388B72C250CE84BDB6BAF7F8C47C9A0B1CB35EEC
A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8
A4B72DBD37256324B557B9176F8CBA4310DDFFBCC4609977E2463F3504A716C8
A61FE79B019062DD3C6420BC20EAF64702CC1063C546A084DD0A0BCB915A14A9
A686FEE577C88AB664D0787ECDFFF035F4806F3DE418DC9E4D516324FFF02083
A90132CEA1D4F7185E4F688EFFD16F6AC14DFD78356A807599A5DABBEEF3333E
AB7292F82267333031F512379FDBADA949DFA49D3C046CC8FA7F34117C342986
B7121039CAF13E03E52507F42DB56FA802FF119DA7591ABA8A2E842133DB7C9C
B75104427B6A5BE55033AF50DC0FE3102181BE130E761D487A4E8178C93317DD
B8686723E415534BC0DBD16326F9486F85B0B0799BF6639334E61DAAE67F36CD
C0D1F42B9F4BF7ACC045B7BB5D4805E10737F67B6310CE505248D543D0D5FE07
C5F1531C6331659C75A6411A088A65DAD7518FD91F57B64537A651B6DCD76AE0
C65CBC98295549BA940494A6214B9706E7115E64F3FE269412C5B48AEACB2222
C93F7B1EEF27CFD0F227DFE3F057D63833533890B7230B1821A424BD40848E33
CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F
CD740652E552D93EE64D7C9D1CC25228E466895889CEE25A11C962AB09906978
D0156949F1381943442C6974E9B5B49EF441BB799EF20477B90A89C3F33620CE
D151962D954970501C60079258EBCFA38502E0A9F03CD640322B08C0A3117FE5
D24566BF315F4E597D6E381C87119FB4198F5E9E2607F5F4AB362EF7E2E7672F
D3A936E1A7775A45217C8296A1F22AC5631DCDEC45594099E78EEEBBEDCBA967
D6CEAE5D9E047FAF7D797858D229AC991AD44316D1E2A37A21926D763153593A
D8A50FA0068E9558E6C3BEE18CDB03B7EECBC3C56C1B2336B98AEE11644994B8
DF21016B00FC54F9FE3BC8B039911BB216E9162FAD2FD14D990AB96E951B49BE
E0E740E4B0F8B3548181FF75B5372FAF4C70B99EC995D694ED0FB91B03FF8D21
E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838
EC30C9C3065A06BB07DC5B1C6B497F370C1CA65C0F30C08E042BA6BCECC78F2C
EF34030C01B13BF42B534072DCC3C75B13C009DC9241119ADA39E2C15E2AFD2E
F5B6F88F75D391A4B1EB336F9E201239FB6B1377DB8CFA7B84736216E5AFFFD7
FBB12938ABD86C125796EDF4162D291028890A7D6C0C1CCA75FD4B95EBFA7A1A
FC02FD48DB92D4DCE6F11679D38354CF750CFC7F584A520EB90BDE80E241F2BD
FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F
FDEDB5BDFCB67411513A61AEE5CB5B5D7C52AF06028EFC996CC1B05B1D6CEA2B
ORACLE_BLOCKED_CERTS
}

# The 16 compromised certificates (8 intermediate keys, each issued by emSign and
# cross-signed by Sectigo), by certificate SHA-256, from the disclosure site's
# impacted-intermediates.json. A JDK is fixed when its blocklist has all 16,
# whatever else its vendor's list contains (patched Corretto, Zulu, Oracle 8u511).
EMUDHRA_COUNT=16
emudhra_fingerprints() {
cat <<'EMUDHRA_FPS'
42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493
45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE
98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B
5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699
E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838
579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512
0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19
62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72
CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F
7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489
432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3
FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F
9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4
A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8
4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1
84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD
EMUDHRA_FPS
}

# ---- options -----------------------------------------------------------------
ROLE=""             # fleet (root orchestrator) | userpass | dev
MODE=""             # audit | remediate | interactive
VERBOSE=0; DEEP=0; EA=0; COLOR=1; YES=0
FAIL_ON_EXPOSED=1; RUN_RECON=0; USER_SCOPE=all; PASS_LABEL=""; BC_FAILED_PRESET=0
REMOVE_ROOTS=0; ALLOW_DESTRUCTIVE=0
BLOCKED_CERTS_URL="${BLOCKED_CERTS_URL:-}"
BLOCKED_CERTS_SHA256="${BLOCKED_CERTS_SHA256:-}"
BLOCKED_CERTS_FILE="${BLOCKED_CERTS_FILE:-}"

yesno() { case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in 1|y|yes|true|on) echo 1 ;; *) echo 0 ;; esac; }

if [ "$(id -u)" -eq 0 ] && [ $# -ge 3 ] && [ "${1#-}" = "$1" ]; then
  # Jamf positional parameters ($1-$3 are mount point, computer, user)
  ROLE=fleet
  MODE="${4:-audit}"
  [ -n "${5:-}" ] && BLOCKED_CERTS_URL="$5"
  [ -n "${6:-}" ] && BLOCKED_CERTS_SHA256="$6"
  if [ -n "${7:-}" ]; then VERBOSE=$(yesno "$7"); else VERBOSE=1; fi
  [ -n "${8:-}" ] && FAIL_ON_EXPOSED=$(yesno "$8")
  [ -n "${9:-}" ] && RUN_RECON=$(yesno "$9")
  [ -n "${10:-}" ] && USER_SCOPE="${10}"
  [ -n "${11:-}" ] && REMOVE_ROOTS=$(yesno "${11}")
else
  for a in "$@"; do
    case "$a" in
      --fleet) ROLE=fleet ;;
      --user-pass) ROLE=userpass ;;
      --label=*) PASS_LABEL="${a#--label=}" ;;
      --mode=*) MODE="${a#--mode=}" ;;
      --audit-only) MODE=audit ;;
      --yes) YES=1 ;;
      --deep) DEEP=1 ;;
      --ea) EA=1; COLOR=0 ;;
      --no-color) COLOR=0 ;;
      --verbose) VERBOSE=1 ;;
      --quiet) VERBOSE=0 ;;
      --blocked-url=*) BLOCKED_CERTS_URL="${a#--blocked-url=}" ;;
      --blocked-sha256=*) BLOCKED_CERTS_SHA256="${a#--blocked-sha256=}" ;;
      --blocked-file=*) BLOCKED_CERTS_FILE="${a#--blocked-file=}" ;;
      --blocked-label=*) BLOCKED_CERTS_LABEL="${a#--blocked-label=}" ;;
      --blocked-unavailable) BC_FAILED_PRESET=1 ;;
      --fail-on-exposed=*) FAIL_ON_EXPOSED=$(yesno "${a#*=}") ;;
      --recon) RUN_RECON=1 ;;
      --remove-roots) REMOVE_ROOTS=1 ;;
      --allow-destructive) ALLOW_DESTRUCTIVE=1 ;;
      --users=*) USER_SCOPE="${a#--users=}" ;;
      -h|--help) sed -n '2,100p' "$0" | sed -n '/^#/p' | sed 's/^# \{0,1\}//'; exit 0 ;;
      *) echo "unknown option: $a (see --help)" >&2; exit 2 ;;
    esac
  done
  if [ -z "$ROLE" ]; then
    if [ "$(id -u)" -eq 0 ]; then ROLE=fleet; [ -z "$MODE" ] && VERBOSE=1; else ROLE=dev; fi
  fi
fi
[ -z "$MODE" ] && { [ "$ROLE" = dev ] && MODE=interactive || MODE=audit; }
[ -t 1 ] || COLOR=0
[ "$ROLE" = dev ] || COLOR=0
[ -z "$PASS_LABEL" ] && { [ "$ROLE" = fleet ] && PASS_LABEL="system" || PASS_LABEL="$ME"; }
# Fleet passes only look at files owned by the account running the pass.
OWNER_FILTER=0; [ "$ROLE" = dev ] || OWNER_FILTER=1

# ---- output -----------------------------------------------------------------
if [ $COLOR -eq 1 ]; then
  R=$'\033[31m'; Y=$'\033[33m'; G=$'\033[32m'; B=$'\033[1m'; N=$'\033[0m'
else R=""; Y=""; G=""; B=""; N=""; fi
ts() { date '+%Y-%m-%d %H:%M:%S'; }
line() {   # line LEVEL text
  [ $EA -eq 1 ] && return 0
  if [ "$ROLE" = dev ]; then printf '%s\n' "$2"
  else printf '%s [%s] %-5s %s\n' "$(ts)" "$PASS_LABEL" "$1" "$2"; fi
}
say()  { line INFO "$*"; }
dbg()  { [ $VERBOSE -eq 1 ] || return 0; if [ "$ROLE" = dev ]; then line DEBUG "  DEBUG $*"; else line DEBUG "$*"; fi; }
hdr()  { if [ "$ROLE" = dev ]; then say ""; say "${B}== $* ==${N}"; else line INFO "----- $* -----"; fi; }
info() { if [ "$ROLE" = dev ]; then say "  INFO  $*"; else line INFO "$*"; fi; }
ok()   { PASS=$((PASS+1)); if [ "$ROLE" = dev ]; then say "  ${G}PASS${N}  $*"; else line PASS "$*"; fi; }
warn() { WARN=$((WARN+1)); RESULTS+=("WARN|$*")
         if [ "$ROLE" = dev ]; then say "  ${Y}WARN${N}  $*"; else line WARN "$*"; fi; }
# fail/pend/unv MESSAGE [FIX]: the fix text feeds the end-of-run summary.
US=$'\x1f'
fail() { FAIL=$((FAIL+1)); RESULTS+=("FAIL|$1${2:+$US$2}")
         if [ "$ROLE" = dev ]; then say "  ${R}FAIL${N}  $1"; else line FAIL "$1"; fi; }
# Exposed, but no fix exists yet (OS-managed bundle, signed IDE runtime).
pend() { PEND=$((PEND+1)); RESULTS+=("PENDING|$1${2:+$US$2}")
         if [ "$ROLE" = dev ]; then say "  ${Y}PEND${N}  $1"; else line PEND "$1"; fi; }
# Could not prove either way (unreadable, unparsable, timed out).
unv()  { UNV=$((UNV+1)); RESULTS+=("UNVERIFIED|$1${2:+$US$2}")
         if [ "$ROLE" = dev ]; then say "  ${Y}UNVER${N} $1"; else line UNVER "$1"; fi; }
done_() { FIXED=$((FIXED+1)); if [ "$ROLE" = dev ]; then say "  ${G}FIXED${N} $*"; else line FIXED "$*"; fi; }
skip_() { SKIPPED=$((SKIPPED+1)); if [ "$ROLE" = dev ]; then say "  SKIP  $*"; else line SKIP "$*"; fi; }
err_()  { ERRORS=$((ERRORS+1)); RESULTS+=("ERROR|$*")
          if [ "$ROLE" = dev ]; then say "  ${R}ERROR${N} $*"; else line ERROR "$*"; fi; }
action() { ACTIONS+=("$*"); if [ "$ROLE" = dev ]; then say "  ACTION $*"; else line ACTN "$*"; fi; }
# restate: an action that repeats a finding's fix (kept for the status file only)
restate() { ACTIONS+=("~$*"); dbg "action recorded: $*"; }

# ---- helpers ----------------------------------------------------------------
PERL=$(command -v perl 2>/dev/null || true)
export PERL_BADLANG=0   # the timeout wrapper must not print locale warnings into captured output
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0 COREPACK_ENABLE_NETWORK=0 npm_config_update_notifier=false NO_UPDATE_NOTIFIER=1
run_t() {   # run_t SECONDS cmd... -> runs cmd with a timeout (exit 142 on timeout)
  local t=$1; shift
  if [ -n "$PERL" ]; then "$PERL" -e 'alarm shift @ARGV; exec @ARGV or exit 127' "$t" "$@"
  else "$@"; fi
}
rp() {
  if command -v realpath >/dev/null 2>&1; then realpath "$1" 2>/dev/null || echo "$1"
  else echo "$1"; fi
}
# BSD stat (macOS) rejects -c; GNU stat accepts -f but means "filesystem", so try -c first.
owner_of() { stat -c %U "$1" 2>/dev/null || stat -f %Su "$1" 2>/dev/null; }
# mine PATH -> true if this pass may execute/inspect it (always true in dev mode)
mine() {
  [ $OWNER_FILTER -eq 0 ] && return 0
  local o; o=$(owner_of "$(rp "$1")")
  [ "$o" = "$ME" ] && return 0
  dbg "skip $1: owned by ${o:-unknown}, checked in that account's pass"
  return 1
}
# pm_tool CMD... -> run npm/yarn so it can never stall the audit. Corepack shims
# ask "Do you want to continue? [Y/n]" before downloading a project-pinned
# package manager (e.g. "packageManager": "npm@10.9.x"); with stderr discarded
# the prompt is invisible and the run hangs. Run from / (no project pin), stdin
# from /dev/null, no Corepack prompt or download, no update check, 20 s limit.
# Settings themselves are read from ~/.npmrc / ~/.yarnrc, never from npm.
pm_tool() {
  ( cd / || exit 1
    export COREPACK_ENABLE_DOWNLOAD_PROMPT=0 COREPACK_ENABLE_NETWORK=0 \
           npm_config_update_notifier=false NO_UPDATE_NOTIFIER=1
    run_t 20 "$@" ) </dev/null 2>/dev/null
}
seen() { case "|$SEEN|" in *"|$1|"*) return 0 ;; esac; SEEN="$SEEN|$1"; return 1; }
ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$2" ]; }
sha256_of() { local h; h=$(shasum -a 256 "$1" 2>/dev/null || sha256sum "$1" 2>/dev/null); echo "${h%% *}"; }
is_user_pass() { [ "$ROLE" = userpass ] || [ "$ROLE" = dev ]; }
is_system_pass() { [ "$ROLE" = fleet ] || [ "$ROLE" = dev ]; }
timed() {   # timed LABEL cmd... -> runs a section and logs its duration at DEBUG
  local l=$1 t0 t1; shift; t0=$(date +%s); "$@"; t1=$(date +%s); dbg "$l took $((t1-t0))s"
}

# =============================================================================
# Certificate identity
# =============================================================================
# Identities from the disclosure site's roots.json and impacted-intermediates.json
# (SPKI = SHA-256 of the DER public key). Certificates are classified by key, so
# a renamed or re-encoded copy is still recognized; names are only a fallback
# that triggers a review, never a verdict or a deletion.
#   ANCHOR       a root the compromised intermediates chain to
#   COMPROMISED  one of the 8 compromised intermediate keys (either issuer)
#   SUSPECT      affected-looking name with an unrecognized key -> review
ANCHOR_KEYS="8D417DB2DD8BF5E3084D1E3F196D583849D81BDD4C00C70B9D39369E96B8C782 C619E4780ED8E0ABEDA24AD732567DE4383A7EA941338F6D1A7D1B49AC792FE9 0A6C2B2CA5B364207954171987AC9D2178561569D8205457E77CA90C32EDE282 BD153ED7B0434F6886B17BCE8BBE84ED340C7132D702A8F4FA318F756ECBD6F3"
# emSign ECC Root CA - G3, emSign Root TLS CA - G3, emSign Root CS CA - G3.
# Only these may ever be removed from a JDK store; AAA Certificate Services never.
EMSIGN_ROOT_KEYS="8D417DB2DD8BF5E3084D1E3F196D583849D81BDD4C00C70B9D39369E96B8C782 C619E4780ED8E0ABEDA24AD732567DE4383A7EA941338F6D1A7D1B49AC792FE9 0A6C2B2CA5B364207954171987AC9D2178561569D8205457E77CA90C32EDE282"
COMPROMISED_KEYS="EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105 43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41 49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F 63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8 5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0 EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6 92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30"
SUSPECT_RE='CN *= *(emSign (ECC Root CA|Root TLS CA|Root CS CA) - G3|AAA Certificate Services|EM (DV|OV|EV) (TLS|CS) CA - G3[BC])'
if [ -x /usr/bin/openssl ]; then OPENSSL=/usr/bin/openssl; else OPENSSL=$(command -v openssl 2>/dev/null || echo openssl); fi

key_class() {   # key_class SPKI SUBJECT
  case " $ANCHOR_KEYS " in *" $1 "*) echo ANCHOR; return ;; esac
  case " $COMPROMISED_KEYS " in *" $1 "*) echo COMPROMISED; return ;; esac
  if printf '%s\n' "$2" | grep -Eiq "$SUSPECT_RE"; then echo SUSPECT; else echo OTHER; fi
}

# cert_row PEMFILE -> "fingerprint<TAB>spki<TAB>class<TAB>subject"; non-zero if unusable
cert_row() {
  local c="$1" out fp key sj
  out=$("$OPENSSL" x509 -in "$c" -noout -subject -nameopt RFC2253 -fingerprint -sha256 -pubkey 2>/dev/null) || return 1
  fp=$(printf '%s\n' "$out" | awk -F= 'tolower($0) ~ /fingerprint=/ { gsub(":", "", $2); print toupper($2) }')
  sj=$(printf '%s\n' "$out" | sed -n 's/^subject= *//p' | head -1 | tr '\t' ' ')
  key=$(printf '%s\n' "$out" | sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' \
        | "$OPENSSL" pkey -pubin -outform DER 2>/dev/null | "$OPENSSL" dgst -sha256 2>/dev/null)
  key=${key##* }; key=$(printf '%s' "$key" | tr '[:lower:]' '[:upper:]')
  [ ${#fp} -eq 64 ] && [ ${#key} -eq 64 ] || return 1
  printf '%s\t%s\t%s\t%s\n' "$fp" "$key" "$(key_class "$key" "$sj")" "$sj"
}

# split_pem FILE DIR -> one file per certificate in DIR. Strict: any non-certificate
# block, nesting, or a truncated block fails the whole file (no partial verdicts).
split_pem() {
  local f="$1" d="$2"
  if grep -aq -- '-----BEGIN' "$f"; then
    EMSIGN_SPLIT_DIR="$d" awk '
      BEGIN { inside = 0; n = 0; bad = 0; dir = ENVIRON["EMSIGN_SPLIT_DIR"] }
      { sub(/\r$/, "") }
      /-----BEGIN / { if ($0 != "-----BEGIN CERTIFICATE-----" || inside) { bad = 1; exit 41 }
                      inside = 1; n++; out = sprintf("%s/%06d.pem", dir, n) }
      inside { print $0 > out }
      /-----END /   { if ($0 != "-----END CERTIFICATE-----" || !inside) { bad = 1; exit 42 }
                      inside = 0; close(out) }
      END { if (bad || inside || n == 0) exit 43 }' "$f" || return 1
  else
    "$OPENSSL" x509 -inform DER -in "$f" -out "$d/000001.pem" 2>/dev/null || return 1
  fi
}

# Fast path: one Perl process per file (core modules only: MIME::Base64,
# Digest::SHA). Same strict rules as split_pem; computes the certificate and
# SPKI SHA-256 from the DER itself and classifies by key. Exit != 0 = no verdict.
PERL_SCAN='use strict; use warnings; use MIME::Base64; use Digest::SHA qw(sha256_hex);
my %anchor = map { $_ => 1 } split / /, $ENV{EMS_ANCHOR};
my %comp   = map { $_ => 1 } split / /, $ENV{EMS_COMP};
my $sus    = qr/$ENV{EMS_SUSPECT}/i;
my $f = shift; open(my $fh, "<:raw", $f) or exit 2; local $/; my $data = <$fh>; close $fh;
exit 3 unless defined $data && length $data;
my @ders;
if ($data =~ /-----BEGIN/) {
  my ($in, $b64) = (0, "");
  for my $l (split /\n/, $data) {
    $l =~ s/\r$//;
    if ($l =~ /-----BEGIN /) { exit 41 if $l ne "-----BEGIN CERTIFICATE-----" || $in; $in = 1; $b64 = ""; next }
    if ($l =~ /-----END /)   { exit 42 if $l ne "-----END CERTIFICATE-----" || !$in; $in = 0;
                               exit 44 if $b64 =~ m{[^A-Za-z0-9+/=\s]} || $b64 !~ /\S/;
                               push @ders, decode_base64($b64); next }
    $b64 .= $l if $in;
  }
  exit 43 if $in || !@ders;
} else { @ders = ($data) }
sub tlv { my ($s, $o) = @_; return () if $o + 2 > length $s;
  my $t = ord substr($s, $o, 1); my $l = ord substr($s, $o + 1, 1); my $h = 2;
  if ($l & 0x80) { my $n = $l & 0x7f; return () if $n < 1 || $n > 4 || $o + 2 + $n > length $s;
    $l = 0; $l = ($l << 8) | ord substr($s, $o + 1 + $_, 1) for 1 .. $n; $h = 2 + $n }
  return () if $o + $h + $l > length $s; return ($t, $h, $l) }
for my $d (@ders) {
  my ($t, $h, $l) = tlv($d, 0); exit 45 unless defined $t && $t == 0x30 && $h + $l == length $d;
  my ($tt, $th, $tl) = tlv($d, $h); exit 46 unless defined $tt && $tt == 0x30;
  my ($p, $end, @k) = ($h + $th, $h + $th + $tl);
  while ($p < $end) { my ($kt, $kh, $kl) = tlv($d, $p); exit 47 unless defined $kt; push @k, [$kt, $p, $kh + $kl]; $p += $kh + $kl }
  shift @k if @k && $k[0][0] == 0xA0;
  exit 48 unless @k >= 6 && $k[4][0] == 0x30 && $k[5][0] == 0x30;
  my $subj = substr($d, $k[4][1], $k[4][2]); my $cn = "";
  my $i = index($subj, "\x06\x03\x55\x04\x03");
  if ($i >= 0) { my ($st, $sh, $sl) = tlv($subj, $i + 5); $cn = substr($subj, $i + 5 + $sh, $sl) if defined $st }
  $cn =~ s/[\t\r\n]/ /g;
  my $fp = uc sha256_hex($d); my $key = uc sha256_hex(substr($d, $k[5][1], $k[5][2]));
  my $cls = $anchor{$key} ? "ANCHOR" : $comp{$key} ? "COMPROMISED" : ("CN=$cn" =~ $sus ? "SUSPECT" : "OTHER");
  print "$fp\t$key\t$cls\tCN=$cn\n";
}'
perl_scan() { EMS_ANCHOR="$ANCHOR_KEYS" EMS_COMP="$COMPROMISED_KEYS" EMS_SUSPECT="$SUSPECT_RE" "$PERL" -e "$PERL_SCAN" "$1" 2>/dev/null; }

# scan_pem FILE -> cert_row for every certificate; non-zero if any part is unusable
scan_pem() {
  local f="$1" d c n=0 rc=0
  if [ -n "$PERL" ]; then perl_scan "$f"; return; fi
  d=$(mktemp -d "${TMPDIR:-/tmp}/emsign-scan.XXXXXX") || return 1
  if split_pem "$f" "$d"; then
    for c in "$d"/*.pem; do
      if cert_row "$c"; then n=$((n+1)); else rc=1; break; fi
    done
  else rc=1; fi
  rm -rf "$d"
  [ $rc -eq 0 ] && [ $n -gt 0 ]
}

# Short list of the affected certificates in scan rows: "CN (ANCHOR); CN (COMPROMISED)"
affected_names() {
  awk -F'\t' '$3 == "ANCHOR" || $3 == "COMPROMISED" || $3 == "SUSPECT" {
      cn = $4; if (match(cn, /CN=[^,]*/)) cn = substr(cn, RSTART + 3, RLENGTH - 3)
      print cn " (" tolower($3) ")" }' | sort -u | paste -sd';' - | sed 's/;/; /g'
}

# =============================================================================
# Bundle, directory and keystore checks
# =============================================================================
LAST_BUNDLE_CLEAN=0; LAST_BUNDLE_AFFECTED=0
# check_bundle FILE LABEL [fail|pend|note] [FIX]
#   fail: exposure with a fix; pend: exposure waiting on a vendor; note: affected
#   material that cannot be used against this client (reported, not counted).
# Each file is judged once per pass: the cache key is the real path, and a file
# with identical contents at another path is reported as a note, not recounted.
check_bundle() {
  local f="$1" label="$2" sev="${3:-fail}" fix="${4:-}" canon h hit rows rc total hits sus names
  LAST_BUNDLE_CLEAN=0; LAST_BUNDLE_AFFECTED=0
  if [ ! -f "$f" ] || [ ! -r "$f" ]; then
    unv "$label: not a readable file: $f" "Fix the path or permissions, or remove the setting that points to it"; return
  fi
  canon=$(rp "$f"); h=$(sha256_of "$canon")
  hit=$(printf '%s\n' "$BUNDLE_CACHE" | awk -F'\t' -v p="$canon" -v h="$h" '$1 == p || ($2 == h && h != "") { print $1 "\t" $3 "\t" $4; exit }')
  if [ -n "$hit" ]; then
    LAST_BUNDLE_AFFECTED=$(printf '%s' "$hit" | cut -f2); LAST_BUNDLE_CLEAN=$(printf '%s' "$hit" | cut -f3)
    if [ "$(printf '%s' "$hit" | cut -f1)" = "$canon" ]; then dbg "$label: $canon already judged (affected=$LAST_BUNDLE_AFFECTED)"
    else info "$label: $canon has the same contents as $(printf '%s' "$hit" | cut -f1); judged once"; fi
    return
  fi
  rows=$(scan_pem "$canon"); rc=$?
  total=$(printf '%s\n' "$rows" | grep -c .)
  hits=$(printf '%s\n' "$rows" | awk -F'\t' '$3 == "ANCHOR" || $3 == "COMPROMISED"' | grep -c .)
  sus=$(printf '%s\n' "$rows" | awk -F'\t' '$3 == "SUSPECT"' | grep -c .)
  names=$(printf '%s\n' "$rows" | affected_names)
  dbg "$label: $canon sha256=${h:0:12}… rc=$rc certs=$total affected=$hits suspect=$sus ${names:+[$names]}"
  if [ $rc -ne 0 ]; then
    unv "$label: $canon could not be fully parsed (malformed, truncated or non-certificate block); no verdict" \
        "Replace the file from the package that owns it, then re-run"
  elif [ "$hits" -gt 0 ]; then
    LAST_BUNDLE_AFFECTED=1
    case "$canon" in /opt/homebrew/*|/usr/local/*) queue_brew ca-certificates ;; esac
    case "$sev" in
      pend) pend "$label: $canon trusts $names" "${fix:-Install the vendor update when it ships}" ;;
      note) info "$label: $canon contains $names; not counted (${fix:-the client using it blocks the compromised keys})" ;;
      *)    fail "$label: $canon trusts $names ($total certs)" "${fix:-Update the package that owns this file}" ;;
    esac
  elif [ "$sus" -gt 0 ]; then
    unv "$label: $canon has affected-looking names with unrecognized keys: $names" \
        "Compare those certificates' fingerprints with the disclosure site before trusting this file"
  else
    LAST_BUNDLE_CLEAN=1
    ok "$label: $canon ($total certs, no affected keys)"
  fi
  BUNDLE_CACHE="$BUNDLE_CACHE"$'\n'"$canon"$'\t'"$h"$'\t'"$LAST_BUNDLE_AFFECTED"$'\t'"$LAST_BUNDLE_CLEAN"
}

# check_cert_dir DIR LABEL -> same verdict for an OpenSSL hashed CA directory
check_cert_dir() {
  local d="$1" label="$2" c n=0 bad=0 rows all="" hits sus names
  if [ ! -d "$d" ] || [ ! -r "$d" ] || [ ! -x "$d" ]; then
    unv "$label: directory not readable: $d" "Fix the path or permissions"; return
  fi
  for c in "$d"/*; do
    [ -f "$c" ] || continue
    case "${c##*/}" in *.r[0-9]*) continue ;; esac   # CRLs, not certificates
    n=$((n+1))
    if rows=$(scan_pem "$c"); then all="$all"$'\n'"$rows"; else bad=$((bad+1)); fi
  done
  hits=$(printf '%s\n' "$all" | awk -F'\t' '$3 == "ANCHOR" || $3 == "COMPROMISED"' | grep -c .)
  sus=$(printf '%s\n' "$all" | awk -F'\t' '$3 == "SUSPECT"' | grep -c .)
  names=$(printf '%s\n' "$all" | affected_names)
  dbg "$label: $d -> files=$n unparsable=$bad affected=$hits suspect=$sus"
  if [ "$hits" -gt 0 ]; then fail "$label: $d trusts $names" "Remove those files from the directory (or update its owning package) and re-hash it"
  elif [ $bad -gt 0 ]; then unv "$label: $bad of $n files in $d could not be parsed; no verdict" "Regenerate the directory with its owning package"
  elif [ $n -eq 0 ]; then unv "$label: $d has no certificate files" "Point the setting at the directory actually in use"
  elif [ "$sus" -gt 0 ]; then unv "$label: $d has affected-looking names with unrecognized keys: $names" "Compare their fingerprints with the disclosure site"
  else ok "$label: $d ($n certs, no affected keys)"; fi
}

# ks_scan KEYTOOL STORE PASSWORD -> "alias<TAB>entrytype<TAB>cert_row..." per certificate.
# keytool on some JDKs (24) ends lines with CRLF; carriage returns are stripped.
ks_scan() {
  local kt ks="$2" pw="$3" d c a t row rc
  kt=$(rp "$1"); case "$kt" in /*) ;; *) kt="$PWD/$kt" ;; esac   # probes run from /
  ks=$(rp "$ks"); case "$ks" in /*) ;; *) ks="$PWD/$ks" ;; esac
  d=$(mktemp -d "${TMPDIR:-/tmp}/emsign-ks.XXXXXX") || return 1
  if [ -n "$pw" ]; then
    probe_java 60 "$kt" -list -rfc -keystore "$ks" -storepass "$pw" > "$d/list" 2>/dev/null
  else
    probe_java 60 "$kt" -list -rfc -keystore "$ks" > "$d/list" 2>/dev/null </dev/null
  fi
  rc=$?
  printf '@@RC\t%s\n' "$rc"     # first line: keytool exit code (callers run us in a subshell)
  EMSIGN_SPLIT_DIR="$d" awk '
    BEGIN { dir = ENVIRON["EMSIGN_SPLIT_DIR"] }
    { sub(/\r$/, "") }
    /^Alias name: / { a = substr($0, 13); t = "" }
    /^Entry type: / { t = substr($0, 13) }
    /^-----BEGIN CERTIFICATE-----$/ { n++; out = sprintf("%s/%06d.pem", dir, n); print n "\t" t "\t" a > (dir "/map") }
    out != "" { print $0 > out }
    /^-----END CERTIFICATE-----$/ { close(out); out = "" }' "$d/list"
  if [ -f "$d/map" ]; then
    if [ -n "$PERL" ]; then
      cat "$d"/0*.pem > "$d/all.pem"
      if perl_scan "$d/all.pem" > "$d/rows" && [ "$(grep -c . "$d/rows")" -eq "$(grep -c . "$d/map")" ]; then
        paste "$d/map" "$d/rows" | awk -F'\t' -v OFS='\t' '{ print $3, $2, $4, $5, $6, $7 }'
      else
        awk -F'\t' '{ print $3 "\t" $2 "\t-\t-\tUNPARSABLE\t-" }' "$d/map"
      fi
    else
      while IFS="$(printf '\t')" read -r c t a; do
        row=$(cert_row "$d/$(printf '%06d' "$c").pem") || row=$'-\t-\tUNPARSABLE\t-'
        printf '%s\t%s\t%s\n' "$a" "$t" "$row"
      done < "$d/map"
    fi
  fi
  rm -rf "$d"
}

# check_keystore KEYTOOL STORE PASSWORD LABEL [JDK_HOME]
# For a JDK, cacerts contents are not the verdict (blocked.certs is): patched
# vendor JDKs keep the roots. LAST_KS_ALIAS lists emSign root aliases by key, for
# the opt-in root removal. A custom store is only as safe as the JVMs using it.
check_keystore() {
  local kt="$1" ks="$2" pw="$3" label="$4" jh="${5:-}" rows total roots comp anchors
  LAST_KS_ALIAS=""
  [ -r "$ks" ] || { unv "$label: keystore not readable: $ks" "Fix permissions or the configured path"; return; }
  ks=$(rp "$ks")
  if seen "ks:$ks"; then dbg "$label: $ks already checked"; return; fi
  rows=$(ks_scan "$kt" "$ks" "$pw")
  KS_RC=$(printf '%s\n' "$rows" | awk -F'\t' '$1 == "@@RC" { print $2; exit }')
  rows=$(printf '%s\n' "$rows" | grep -v '^@@RC')
  total=$(printf '%s\n' "$rows" | grep -c .)
  roots=$(printf '%s\n' "$rows" | awk -F'\t' -v k=" $EMSIGN_ROOT_KEYS " '$2 == "trustedCertEntry" && index(k, " " $4 " ") { print $1 }' | sort -u | paste -sd';' -)
  anchors=$(printf '%s\n' "$rows" | awk -F'\t' '$2 == "trustedCertEntry" && $5 == "ANCHOR" { print $1 }' | sort -u | paste -sd';' -)
  comp=$(printf '%s\n' "$rows" | awk -F'\t' '$5 == "COMPROMISED" { print $1 }' | sort -u | paste -sd';' -)
  dbg "$label: keytool rc=$KS_RC certs=$total emsign_roots=${roots:-none} anchors=${anchors:-none} compromised=${comp:-none}"
  if [ "$total" -eq 0 ]; then unv "$label: could not read $ks (keytool rc=$KS_RC)" "Check the store password or format"; return; fi
  if printf '%s\n' "$rows" | grep -q $'\tUNPARSABLE\t'; then
    unv "$label: some entries in $ks could not be parsed" "Inspect the store with keytool -list -v"
  fi
  if [ -n "$jh" ]; then
    if [ -n "$roots" ]; then
      if [ "${JDK_BL_OK:-0}" -eq 1 ]; then
        info "$label: emSign root(s) still in cacerts (${roots//;/, }); expected on patched JDKs, blocked.certs stops the compromised chains"
      else
        info "$label: emSign root(s) in cacerts (${roots//;/, }); the blocked.certs merge is the fix$([ $REMOVE_ROOTS -eq 1 ] && echo '; root removal enabled' || echo ' (root removal is opt-in: --remove-roots / $11)')"
        LAST_KS_ALIAS="$roots"
      fi
    else ok "$label: $ks ($total certs, no emSign root)"; fi
    return
  fi
  if [ -n "$comp" ]; then
    fail "$label: custom trust store $ks contains compromised intermediate(s) as trusted entries (${comp//;/, })" \
         "Delete those aliases with keytool -delete; they are never needed"
  elif [ -n "$anchors" ]; then
    warn "$label: custom trust store $ks contains affected root(s) (${anchors//;/, }); safe only on JVMs whose blocked.certs is complete"
    MANUAL+=("Custom trust store $ks: confirm every JVM using it is patched, or remove alias(es) ${anchors//;/, }")
  else ok "$label: $ks ($total certs, no affected keys)"; fi
}

# ks_emsign_roots KEYTOOL STORE -> emSign root aliases (by key) still present
ks_emsign_roots() {
  ks_scan "$1" "$2" changeit | awk -F'\t' -v k=" $EMSIGN_ROOT_KEYS " '$2 == "trustedCertEntry" && index(k, " " $4 " ") { print $1 }' | sort -u | paste -sd';' -
}

queue_brew() { case " $BREW_PKGS " in *" $1 "*) ;; *) BREW_PKGS="${BREW_PKGS:+$BREW_PKGS }$1" ;; esac; }

# probe* run an installed runtime from / with stdin closed, a time limit, and the
# environment variables that would make it load extra code or settings removed.
probe()      { local t=$1; shift; ( cd / && run_t "$t" "$@" ) </dev/null; }
probe_java() { local t=$1; shift; probe "$t" env -u JAVA_TOOL_OPTIONS -u JDK_JAVA_OPTIONS -u _JAVA_OPTIONS "$@"; }
probe_node() { local t=$1; shift; probe "$t" env -u NODE_OPTIONS -u NODE_PATH "$@"; }
probe_go()   { local t=$1; shift; probe "$t" env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOENV=off GOFLAGS= "$@"; }
probe_ruby() { local t=$1; shift; probe "$t" env -u RUBYOPT -u RUBYLIB "$@"; }

# props_value FILE KEY -> last active value of KEY in a .properties file (comments ignored)
props_value() {
  [ -f "$1" ] || return 0
  awk -v k="$2" '
    { sub(/\r$/, "") }
    /^[[:space:]]*[#!]/ { next }
    { line = $0; sub(/^[[:space:]]+/, "", line)
      if (index(line, k) == 1) { rest = substr(line, length(k) + 1)
        if (rest ~ /^[[:space:]]*[=:]/) { sub(/^[[:space:]]*[=:][[:space:]]*/, "", rest); v = rest } } }
    END { if (v != "") print v }' "$1"
}

# =============================================================================
# Audit sections
# =============================================================================
NOT_COVERED=()
audit_macos() {
  hdr "macOS system trust"
  info "macOS $(sw_vers -productVersion 2>/dev/null || echo '?') ($(uname -m))"
  local n dom found=0
  n=$(security find-certificate -a -c "emSign ECC Root CA - G3" \
        /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null | grep -c '"labl"')
  info "Apple root store has emSign ECC Root CA - G3: $([ "$n" -gt 0 ] && echo yes || echo no). Apple blocks the 8 intermediates via revocation for Security-framework apps (Safari, Chrome, Go on macOS); NOT for node --use-system-ca or OpenSSL tools"
  NOT_COVERED+=("Apple Security-framework revocation is not tested; keep macOS updated")
  for dom in "-d" "-s"; do
    if security dump-trust-settings $dom 2>/dev/null | grep -Eqi "emsign|AAA Certificate Services|EM (DV|OV|EV) (TLS|CS) CA - G3"; then
      unv "trust setting on an emSign/AAA certificate (security dump-trust-settings $dom)" \
          "Open Keychain Access and check whether it is marked Always Trust; a text match cannot tell Always from Never Trust"; found=1
    fi
  done
  [ $found -eq 0 ] && ok "no admin/system trust settings for affected certificates"
  check_bundle /etc/ssl/cert.pem "macOS /etc/ssl/cert.pem (used by /usr/bin/curl, system Ruby, LibreSSL tools; OS-managed)" pend \
    "Install the macOS update that refreshes it; until then prefer Homebrew curl over /usr/bin/curl"
}

audit_env() {
  hdr "TLS environment"
  local v val rc
  if security dump-trust-settings 2>/dev/null | grep -Eqi "emsign|AAA Certificate Services|EM (DV|OV|EV) (TLS|CS) CA - G3"; then
    unv "user trust setting on an emSign/AAA certificate (security dump-trust-settings)" \
        "Open Keychain Access and check whether it is marked Always Trust"
  fi
  if [ "$ROLE" = dev ]; then
    for v in SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE GIT_SSL_CAINFO PIP_CERT; do
      val=$(printenv "$v")
      [ -n "$val" ] && check_bundle "$val" "\$$v" fail "Point \$$v at an updated bundle (or unset it) in your shell profile"
    done
    [ -n "${SSL_CERT_DIR:-}" ] && check_cert_dir "$SSL_CERT_DIR" "\$SSL_CERT_DIR"
    [ "${NODE_TLS_REJECT_UNAUTHORIZED:-}" = "0" ] && fail "NODE_TLS_REJECT_UNAUTHORIZED=0 disables Node TLS verification" "Remove it from your shell profile and project .env files"
    case "${GIT_SSL_NO_VERIFY:-}" in ""|0|false|FALSE|no|off) ;; *) fail "GIT_SSL_NO_VERIFY is set (Git TLS verification off)" "Unset it in your shell profile" ;; esac
    [ -n "${PIP_TRUSTED_HOST:-}" ] && fail "PIP_TRUSTED_HOST is set (pip skips certificate checks for those hosts)" "Unset it; configure the index's CA instead"
    [ -n "${NODE_OPTIONS:-}" ] && info "NODE_OPTIONS=$NODE_OPTIONS"
  else
    dbg "user pass runs with a clean environment; checking shell startup files instead of live variables"
  fi
  for rc in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile"; do
    [ -f "$rc" ] || continue
    dbg "scanning $rc"
    if awk '/^[[:space:]]*#/ { next } /NODE_TLS_REJECT_UNAUTHORIZED[[:space:]]*=[[:space:]]*["\047]?0([[:space:]"\047;]|$)/ { f = 1 } END { exit !f }' "$rc"; then
      fail "$rc sets NODE_TLS_REJECT_UNAUTHORIZED=0" "Delete that line from $rc"
    fi
    if awk '/^[[:space:]]*#/ { next } /GIT_SSL_NO_VERIFY[[:space:]]*=[[:space:]]*["\047]?(1|true|yes)/ { f = 1 } END { exit !f }' "$rc"; then
      fail "$rc sets GIT_SSL_NO_VERIFY (Git TLS verification off)" "Delete that line from $rc"
    fi
  done
}

audit_node() {
  hdr "Node.js"
  local nb r ver v need found=0 caf f strict extra
  for nb in "$(command -v node 2>/dev/null)" "${NVM_DIR:-$HOME/.nvm}"/versions/node/*/bin/node \
            "$HOME"/.volta/tools/image/node/*/bin/node "$HOME"/.fnm/node-versions/*/installation/bin/node \
            "$HOME"/.asdf/installs/nodejs/*/bin/node /opt/homebrew/bin/node /opt/homebrew/opt/node@*/bin/node \
            /usr/local/bin/node /usr/local/opt/node@*/bin/node; do
    [ -n "$nb" ] && [ -x "$nb" ] || continue
    r=$(rp "$nb"); seen "node:$r" && continue
    mine "$nb" || continue
    found=1
    ver=$(probe_node 20 "$nb" --version 2>/dev/null)
    [ -z "$ver" ] && ver=$(printf '%s' "$nb" | grep -o 'v[0-9][0-9]*\.[0-9][0-9.]*' | head -1)
    v=${ver#v}
    dbg "node candidate $nb -> $r version=${ver:-unknown}"
    if [ "$ROLE" = dev ] && [ -n "${NODE_OPTIONS:-}" ] && ! ( cd / && run_t 20 "$nb" --version ) >/dev/null 2>&1 </dev/null; then
      warn "node $ver ($nb): fails to start with your NODE_OPTIONS ($NODE_OPTIONS)"
    fi
    case "${v%%.*}" in
      22) need=22.23.4 ;; 24) need=24.22.1 ;; 26) need=26.12.1 ;;
      *) if [ -n "$v" ] && ver_ge "$v" 27; then need=""; else need="EOL"; fi ;;
    esac
    if [ -z "$need" ] || { [ "$need" != "EOL" ] && ver_ge "$v" "$need"; }; then
      ok "node $ver ($nb): patched release (blocks the compromised keys in code, whatever CA file it loads)"
    elif [ "$need" = "EOL" ]; then
      fail "node ${ver:-unknown} ($nb): end-of-life release line, no fix" "Install Node 24 (nvm install 24) and move projects to it; remove this version"
      NODE_FIX+=("$nb|$v|24")
    else
      fail "node $ver ($nb): unpatched" "Upgrade to $need or later: nvm install ${v%%.*} (or brew upgrade / nodejs.org installer)"
      NODE_FIX+=("$nb|$v|${v%%.*}")
    fi
  done
  [ $found -eq 0 ] && info "no node installs found"

  is_user_pass || return 0
  # NODE_EXTRA_CA_CERTS only matters to an unpatched Node: patched releases reject
  # the compromised keys even when an extra CA file adds AAA or emSign roots.
  extra="${NODE_EXTRA_CA_CERTS:-}"
  if [ "$ROLE" = dev ] && [ -n "$extra" ]; then
    if [ ${#NODE_FIX[@]} -eq 0 ]; then check_bundle "$extra" "\$NODE_EXTRA_CA_CERTS" note "every Node found is patched"
    else check_bundle "$extra" "\$NODE_EXTRA_CA_CERTS" fail "Upgrade Node (above); or remove the affected roots from this file"; fi
  fi
  if [ "$ROLE" = dev ] && command -v npm >/dev/null 2>&1; then
    v=$(pm_tool npm --version)
    info "npm ${v:-version unavailable (Corepack shim without a cached npm, or timed out)}"
    caf="${npm_config_cafile:-${NPM_CONFIG_CAFILE:-}}"; caf=${caf/#\~/$HOME}
    [ -n "$caf" ] && check_bundle "$caf" "npm cafile (environment)"
    case "${npm_config_strict_ssl:-${NPM_CONFIG_STRICT_SSL:-}}" in false) fail "npm strict-ssl=false in the environment (TLS verification off)" "Unset npm_config_strict_ssl" ;; esac
  fi
  # Package-manager settings come from the files; npm/Yarn are never run for them.
  for f in "$HOME/.npmrc" "$HOME/.yarnrc"; do
    [ -f "$f" ] || continue
    dbg "reading $f"
    strict=$(grep -Ei '^[[:space:]]*"?strict-ssl"?[[:space:]=]' "$f" | tail -1 | sed -E 's/^[^=[:space:]]+[[:space:]=]+"?//; s/"?[[:space:]]*$//')
    [ "$strict" = false ] && fail "$f sets strict-ssl false (TLS verification off)" "Delete the strict-ssl line from $f"
    caf=$(grep -Ei '^[[:space:]]*"?cafile"?[[:space:]=]' "$f" | tail -1 | sed -E 's/^[^=[:space:]]+[[:space:]=]+"?//; s/"?[[:space:]]*$//')
    caf=${caf/#\~/$HOME}
    [ -n "$caf" ] && check_bundle "$caf" "$(basename "$f") cafile" fail "Point cafile in $f at an updated bundle, or remove it"
  done
  f="$HOME/.yarnrc.yml"   # Yarn 2+ (berry)
  if [ -f "$f" ]; then
    dbg "reading $f"
    grep -Eqi '^[[:space:]]*enableStrictSsl:[[:space:]]*false' "$f" && fail "$f sets enableStrictSsl: false (TLS verification off)" "Delete that line from $f"
    caf=$(grep -Ei '^[[:space:]]*(httpsCaFilePath|caFilePath):' "$f" | tail -1 | sed -E 's/^[^:]+:[[:space:]]*//; s/^["\x27]//; s/["\x27][[:space:]]*$//')
    caf=${caf/#\~/$HOME}
    [ -n "$caf" ] && check_bundle "$caf" ".yarnrc.yml CA file" fail "Point it at an updated bundle, or remove it"
  fi
}

audit_java() {
  hdr "Java"
  local jhomes jh r jv ks bc needbc miss found=0 anykt="" o ts pw tt gp gjh ide
  gp="$HOME/.gradle/gradle.properties"
  gjh=""; is_user_pass && gjh=$(props_value "$gp" org.gradle.java.home)
  [ -n "$gjh" ] && dbg "Gradle org.gradle.java.home=$gjh"
  jhomes=$(/usr/libexec/java_home -V 2>&1 | grep '/' | sed 's/.* \(\/.*\)$/\1/')
  dbg "java_home reports: $(printf '%s' "$jhomes" | tr '\n' ' ')"
  # shellcheck disable=SC2086
  for jh in ${JAVA_HOME:-} "$gjh" $jhomes "$HOME"/.sdkman/candidates/java/* "$HOME"/.asdf/installs/java/* \
            "$HOME"/Library/Java/JavaVirtualMachines/*/Contents/Home \
            /Library/Java/JavaVirtualMachines/*/Contents/Home \
            /opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home \
            /usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home \
            /Applications/IntelliJ*.app/Contents/jbr/Contents/Home \
            /Applications/Android\ Studio*.app/Contents/jbr/Contents/Home \
            "$HOME"/Applications/IntelliJ*.app/Contents/jbr/Contents/Home \
            "$HOME"/Applications/Android\ Studio*.app/Contents/jbr/Contents/Home; do
    [ -n "$jh" ] && [ -x "$jh/bin/keytool" ] || continue
    case "$jh" in */current) continue ;; esac
    r=$(rp "$jh"); seen "jdk:$r" && continue
    mine "$jh/bin/keytool" || continue
    found=1; anykt="$jh/bin/keytool"
    jv=$(probe_java 30 "$jh/bin/java" -version 2>&1 | grep -v "^Picked up" | head -1 | tr -d '\r')
    dbg "JDK $jh -> $r [$jv] owner=$(owner_of "$r/bin/keytool")"
    ks="$jh/lib/security/cacerts"; [ -f "$ks" ] || ks="$jh/jre/lib/security/cacerts"
    bc=$(jdk_blocklist_path "$jh")
    ide=0; case "$jh" in /Applications/*.app/*|"$HOME"/Applications/*.app/*) ide=1 ;; esac
    JDK_BL_OK=0; needbc=0
    miss=$(bl_missing "$bc")
    dbg "JDK $jh: $bc -> ${miss} of $EMUDHRA_COUNT compromised certificates not blocked"
    if [ "$miss" = "BADFORMAT" ]; then
      unv "JDK [$jv] $jh: $(basename "$bc") is not in the standard SHA-256 format; no verdict" "Compare it with the JDK vendor's file, or reinstall the JDK"
    elif [ "$miss" -eq 0 ]; then
      JDK_BL_OK=1
      ok "JDK [$jv] $jh: $(basename "$bc") blocks all $EMUDHRA_COUNT compromised certificates (both issuers)"
    elif [ $ide -eq 1 ]; then
      pend "JDK [$jv] $jh: IDE-bundled runtime does not block $miss of $EMUDHRA_COUNT compromised certificates; not edited (signed app)" \
           "Set the IDE's Gradle JVM to a fixed JDK; update the IDE when its vendor ships a new runtime"
    else
      needbc=1
      fail "JDK [$jv] $jh: $(basename "$bc") does not block $miss of $EMUDHRA_COUNT compromised certificates" \
           "Install a fixed JDK (Oracle/OpenJDK 8u511, 11.0.33.0.2, 17.0.21.0.2, 21.0.13.0.2, 25.0.5.0.2, 27.0.1.0.2; Corretto 21.0.13.0.10), or let this script merge Oracle's blocklist"
    fi
    if [ $ide -eq 1 ] && [ $JDK_BL_OK -eq 0 ]; then
      dbg "IDE runtime $jh already reported; skipping cacerts detail"; continue
    fi
    check_keystore "$jh/bin/keytool" "$ks" changeit "JDK [$jv] $jh" "$jh"
    [ $ide -eq 1 ] && continue
    [ $REMOVE_ROOTS -eq 1 ] || LAST_KS_ALIAS=""
    if [ -n "$LAST_KS_ALIAS" ] || [ $needbc -eq 1 ]; then JDK_FIX+=("$jh|$ks|$LAST_KS_ALIAS|$needbc|$bc"); fi
  done
  [ $found -eq 0 ] && info "no JDKs found"
  if [ -n "$gjh" ] && [ ! -x "$gjh/bin/keytool" ]; then
    unv "Gradle org.gradle.java.home points to $gjh, which is not a JDK" "Fix org.gradle.java.home in $gp"
  fi

  is_user_pass || return 0
  for o in "${JAVA_TOOL_OPTIONS:-}" "${JDK_JAVA_OPTIONS:-}"; do
    ts=$(printf '%s' "$o" | grep -o 'javax.net.ssl.trustStore=[^ ]*' | cut -d= -f2)
    pw=$(printf '%s' "$o" | grep -o 'javax.net.ssl.trustStorePassword=[^ ]*' | cut -d= -f2)
    [ -n "$ts" ] && [ -n "$anykt" ] && check_keystore "$anykt" "$ts" "$pw" "JVM options trustStore"
  done
  if [ -f "$gp" ]; then
    ts=$(props_value "$gp" systemProp.javax.net.ssl.trustStore)
    pw=$(props_value "$gp" systemProp.javax.net.ssl.trustStorePassword)
    tt=$(props_value "$gp" systemProp.javax.net.ssl.trustStoreType)
    if [ "$tt" = "KeychainStore" ]; then info "Gradle uses the macOS keychain trust (KeychainStore)"
    elif [ -n "$ts" ] && [ -n "$anykt" ]; then check_keystore "$anykt" "${ts/#\~/$HOME}" "$pw" "Gradle trustStore"
    else ok "Gradle: no active custom trustStore in $gp"; fi
  fi
}

PY_JS='import ssl,sys
p=ssl.get_default_verify_paths()
print("cafile|"+(p.openssl_cafile or ""))
try:
    import certifi; print("certifi|"+certifi.__version__+"|"+certifi.where())
except Exception: pass
try:
    import pip
    from pip._vendor import certifi as pc
    print("pip|"+pip.__version__+"|"+pc.where())
except Exception: pass'
audit_python() {
  hdr "Python"
  local pys py r pv out caf cline cv cw pline pipv pipw found=0
  pys="$(command -v python3 2>/dev/null)"
  # /usr/bin/python3 is a stub that pops an install dialog without the Command Line Tools
  xcode-select -p >/dev/null 2>&1 || pys=$(printf '%s' "$pys" | grep -v '^/usr/bin/python3$')
  for py in $pys /opt/homebrew/bin/python3* /usr/local/bin/python3* \
            /Library/Frameworks/Python.framework/Versions/*/bin/python3 \
            "$HOME"/.pyenv/versions/*/bin/python3 "$HOME"/.asdf/installs/python/*/bin/python3; do
    case "$py" in *-config) continue ;; esac
    [ -x "$py" ] || continue
    r=$(rp "$py"); seen "py:$r" && continue
    mine "$py" || continue
    found=1
    pv=$(probe 20 "$py" -I -V 2>&1)
    out=$(probe 30 "$py" -I -c "$PY_JS" 2>/dev/null)
    dbg "python $py -> $r [$pv]: $(printf '%s' "$out" | tr '\n' ' ')"
    caf=$(printf '%s\n' "$out" | grep '^cafile|' | cut -d'|' -f2)
    [ -n "$caf" ] && [ -f "$caf" ] && check_bundle "$caf" "$pv ssl default"
    cline=$(printf '%s\n' "$out" | grep '^certifi|')
    if [ -n "$cline" ]; then
      cv=$(echo "$cline" | cut -d'|' -f2); cw=$(echo "$cline" | cut -d'|' -f3)
      info "$pv ($py): certifi $cv (fixed in 2026.10.19)"
      check_bundle "$cw" "$pv certifi $cv" fail "$py -m pip install -U certifi (2026.10.19 or later)"
      [ "$LAST_BUNDLE_AFFECTED" -eq 1 ] && CERTIFI_FIX+=("$py")
    fi
    # pip always adds its vendored certifi to the system store; only pip 26.2.2+ is clean.
    pline=$(printf '%s\n' "$out" | grep '^pip|')
    if [ -n "$pline" ]; then
      pipv=$(echo "$pline" | cut -d'|' -f2); pipw=$(echo "$pline" | cut -d'|' -f3)
      check_bundle "$pipw" "$pv pip $pipv vendored certifi" fail "$py -m pip install -U pip (26.2.2 or later; Homebrew Python: brew upgrade python)"
      [ "$LAST_BUNDLE_AFFECTED" -eq 1 ] && PIP_FIX+=("$py|$pipv")
    else
      dbg "$pv: no pip, or pip without a vendored certifi (distro-patched)"
    fi
  done
  [ $found -eq 0 ] && info "no python3 installs found"
  [ "$ROLE" = dev ] && [ $DEEP -eq 0 ] && NOT_COVERED+=("virtualenvs and pipx tools carry their own pip/certifi; run with --deep to scan them")
  return 0
}

audit_uv() {
  hdr "uv"
  local u r v found=0
  for u in "$(command -v uv 2>/dev/null)" "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv" /opt/homebrew/bin/uv /usr/local/bin/uv; do
    [ -n "$u" ] && [ -x "$u" ] || continue
    r=$(rp "$u"); seen "uv:$r" && continue
    mine "$u" || continue
    found=1
    v=$(probe 10 "$u" --version 2>/dev/null | awk '{print $2}')
    dbg "uv $u -> $r version=${v:-unknown}"
    if [ -n "$v" ] && ver_ge "$v" 0.13.4; then ok "uv $v ($u): embedded roots updated"
    else
      fail "uv ${v:-unknown} ($u): embedded roots trust the compromised CAs" "uv self update (0.13.4 or later; Homebrew: brew upgrade uv)"
      case "$r" in /opt/homebrew/*|/usr/local/Cellar/*) queue_brew uv ;; *) UV_FIX+=("$u|${v:-unknown}") ;; esac
    fi
  done
  [ $found -eq 0 ] && dbg "uv not installed (or owned by another account)"
  return 0
}

audit_go() {
  hdr "Go"
  local g r gv v mm need found=0
  for g in "$(command -v go 2>/dev/null)" /usr/local/go/bin/go /opt/homebrew/bin/go "$HOME"/sdk/go*/bin/go; do
    [ -n "$g" ] && [ -x "$g" ] || continue
    r=$(rp "$g"); seen "go:$r" && continue
    mine "$g" || continue
    found=1
    gv=$(probe_go 20 "$g" env GOVERSION 2>/dev/null); v=${gv#go}; v=${v%%[!0-9.]*}
    dbg "go $g -> $r version=$gv"
    mm=$(echo "$v" | cut -d. -f1,2)
    case "$mm" in
      1.26) need=1.26.10 ;; 1.27) need=1.27.3 ;;
      *) if [ -n "$v" ] && ver_ge "$v" 1.28; then need=""; else need="1.26.10"; fi ;;
    esac
    if [ -z "$need" ] || ver_ge "$v" "$need"; then ok "$gv ($g): includes the key-based block"
    else
      fail "$gv ($g): toolchain lacks the key block (CVE-2026-111943)" "Upgrade Go to $need or later, then rebuild binaries you ship to Linux/containers"
      case "$r" in /opt/homebrew/*|/usr/local/Cellar/*) queue_brew go ;; esac
    fi
  done
  [ $found -eq 0 ] && info "go not installed (or owned by another account)"
  is_user_pass && audit_go_bins
  return 0
}

# Compiled Go programs keep the Go version they were built with. On macOS the
# default x509 verification goes through Apple's trust evaluation (which Apple
# has patched), so an old build here matters when it is shipped to Linux or
# containers, or carries its own root pool. Reported as advisories.
audit_go_bins() {
  local f v mm need tool="" g n=0 old=0
  for g in /opt/homebrew/bin/go /usr/local/go/bin/go "$HOME"/sdk/go*/bin/go; do
    [ -x "$g" ] && mine "$g" && { tool="$g"; break; }
  done
  for f in "$HOME"/go/bin/*; do
    [ -f "$f" ] && [ -x "$f" ] || continue
    mine "$f" || continue
    # `go version FILE` reads build metadata; the binary itself is never executed.
    if [ -n "$tool" ]; then v=$(probe_go 15 "$tool" version "$f" 2>/dev/null | awk '{print $2}')
    else v=$(LC_ALL=C grep -a -o -m1 'go1\.[0-9][0-9]*\.[0-9][0-9]*' "$f" 2>/dev/null | head -1); fi
    case "$v" in go1.*) ;; *) dbg "go binary $f: build version unknown"; continue ;; esac
    n=$((n+1)); v=${v#go}; mm=$(echo "$v" | cut -d. -f1,2)
    case "$mm" in 1.26) need=1.26.10 ;; 1.27) need=1.27.3 ;; *) if ver_ge "$v" 1.28; then need=""; else need=1.26.10; fi ;; esac
    if [ -n "$need" ] && ! ver_ge "$v" "$need"; then
      old=$((old+1))
      warn "Go binary $f built with go$v: rebuild with Go >= $need if it ships to Linux/containers or uses its own root pool"
    fi
  done
  dbg "go binaries in $HOME/go/bin: $n inspected, $old built before the fix (reader: ${tool:-string scan})"
}

audit_bundles() {
  hdr "Homebrew / OpenSSL bundles"
  local f found=0
  for f in /opt/homebrew/etc/ca-certificates/cert.pem /opt/homebrew/etc/openssl@3/cert.pem \
           /opt/homebrew/etc/openssl@1.1/cert.pem /usr/local/etc/ca-certificates/cert.pem \
           /usr/local/etc/openssl@3/cert.pem /usr/local/etc/openssl@1.1/cert.pem; do
    [ -e "$f" ] || continue
    mine "$f" || continue
    found=1; check_bundle "$f" "Homebrew bundle" fail "brew update && brew upgrade ca-certificates (as the Homebrew owner)"
  done
  [ $found -eq 0 ] && info "no Homebrew CA bundles found (or owned by another account)"
  return 0
}

audit_git() {
  hdr "Git"
  local ci g
  g=$(command -v git 2>/dev/null)
  # /usr/bin/git is a stub that pops an install dialog when the Command Line Tools are missing
  if [ -z "$g" ] || { [ "$g" = /usr/bin/git ] && ! xcode-select -p >/dev/null 2>&1; }; then
    dbg "git unavailable (no Command Line Tools); skipping"; return 0
  fi
  ci=$( (cd / && git config --global --get http.sslCAInfo) 2>/dev/null </dev/null)
  [ -n "$ci" ] && check_bundle "${ci/#\~/$HOME}" "git http.sslCAInfo" fail "Point http.sslCAInfo at an updated bundle, or unset it (git config --global --unset http.sslCAInfo)"
  [ "$( (cd / && git config --global --get http.sslVerify) 2>/dev/null </dev/null)" = "false" ] && \
    fail "git http.sslVerify=false (global)" "git config --global --unset http.sslVerify"
  (cd / && git config --global --get-regexp '^http\..*\.sslverify$') 2>/dev/null </dev/null | grep -qi ' false$' \
    && warn "git has per-URL sslVerify=false entries (git config --global --get-regexp sslverify)"
  [ -z "$ci" ] && ok "git: default trust (Apple keychain/system)"
  return 0
}

audit_other() {
  hdr "Other runtimes"
  local rb cf
  rb=$(command -v ruby 2>/dev/null)
  if [ -n "$rb" ] && mine "$rb"; then
    cf=$(probe_ruby 20 "$rb" -ropenssl -e 'print OpenSSL::X509::DEFAULT_CERT_FILE' 2>/dev/null)
    [ -n "$cf" ] && [ -f "$cf" ] && check_bundle "$cf" "ruby $(probe_ruby 10 "$rb" -e 'print RUBY_VERSION' 2>/dev/null)"
  fi
  [ "$ROLE" = dev ] || return 0
  command -v cargo >/dev/null 2>&1 && NOT_COVERED+=("Rust projects: webpki-roots must be >= 1.0.10 and rustls-webpki >= 0.103.16 (check each Cargo.lock)")
  command -v composer >/dev/null 2>&1 && NOT_COVERED+=("PHP projects: composer/ca-bundle >= 1.4.16 (1.4.x) or >= 1.6.0 (check each composer.lock)")
  command -v docker >/dev/null 2>&1 && NOT_COVERED+=("Docker images carry their own CA bundles; rebuild on patched base images (Docker Desktop itself: 4.96.2 or later)")
  { command -v bun || command -v deno; } >/dev/null 2>&1 && NOT_COVERED+=("Bun (>= 1.4.4) and Deno (>= 2.9.8) ship their own root stores; check their versions")
  return 0
}

audit_deep() {
  hdr "Deep scan: vendored PEM bundles"
  local f
  while IFS= read -r f; do
    check_bundle "$f" "vendored"
  done < <(find "$HOME" /Applications \( -path "$HOME/Library/Caches" -o -path "$HOME/.Trash" \) -prune -o \
             -type f \( -name 'cacert.pem' -o -name 'ca-bundle.crt' -o -name 'ca-bundle.pem' \
             -o -name 'ca-certificates.crt' \) -print 2>/dev/null)
}

run_audit() {
  PASS=0; WARN=0; FAIL=0; PEND=0; UNV=0; SEEN=""; BUNDLE_CACHE=""; RESULTS=(); NOT_COVERED=()
  NODE_FIX=(); JDK_FIX=(); CERTIFI_FIX=(); PIP_FIX=(); UV_FIX=(); BREW_PKGS=""; MANUAL=()
  LAST_KS_ALIAS=""
  is_system_pass && timed "macos" audit_macos
  is_user_pass   && timed "env" audit_env
  timed "node"   audit_node
  timed "java"   audit_java
  timed "python" audit_python
  timed "uv"     audit_uv
  timed "go"     audit_go
  timed "bundles" audit_bundles
  is_user_pass   && timed "git" audit_git
  timed "other"  audit_other
  [ $DEEP -eq 1 ] && timed "deep" audit_deep
  return 0
}

# PROTECTED only when nothing is exposed, pending or unproven; WARN lines are
# advisories (hygiene, rebuild hints) and never make a machine look protected
# when it is not, nor exposed when it is not.
pass_status() {
  if [ $FAIL -gt 0 ]; then echo EXPOSED
  elif [ $UNV -gt 0 ]; then echo UNVERIFIED
  elif [ $PEND -gt 0 ]; then echo VENDOR_PENDING
  else echo PROTECTED; fi
}
counts() { echo "pass=$PASS fail=$FAIL pending=$PEND unverified=$UNV advisory=$WARN"; }

# =============================================================================
# blocked.certs acquisition
# =============================================================================
FETCH_ERR=""
# A browser on macOS uses the keychain and the system/PAC proxy; curl uses
# neither. Retry with admin-installed keychain roots and the scutil proxy.
fetch_url() {   # fetch_url URL OUT
  local url="$1" out="$2" rc e bundle="" px="" opts=""
  dbg "fetching $url"
  e=$(curl -fsSL --max-time 30 -o "$out" "$url" 2>&1); rc=$?
  dbg "curl rc=$rc ${e:+($e)}"
  [ $rc -eq 0 ] && return 0
  FETCH_ERR="curl exit $rc: ${e:-no detail}"
  if [ $rc -eq 22 ] && printf '%s' "$e" | grep -q ' 403'; then
    FETCH_ERR="$FETCH_ERR | server rejects scripted downloads; host the file internally for \$5"
    return 1
  fi
  if [ "$(uname)" = Darwin ]; then
    if [ $rc -eq 60 ] || [ $rc -eq 35 ] || [ $rc -eq 77 ]; then
      bundle=$(mktemp "${TMPDIR:-/tmp}/kc-roots.XXXXXX")
      { cat /etc/ssl/cert.pem 2>/dev/null
        security find-certificate -a -p /Library/Keychains/System.keychain 2>/dev/null; } > "$bundle"
      opts="--cacert $bundle"
    fi
    if [ -z "${https_proxy:-}${HTTPS_PROXY:-}" ]; then
      px=$(scutil --proxy 2>/dev/null | awk '/HTTPSEnable : 1/{on=1} /HTTPSProxy :/{h=$3} /HTTPSPort :/{p=$3} END{if(on&&h)print h":"p}')
      [ -n "$px" ] && opts="$opts --proxy http://$px"
    fi
    if [ -n "$opts" ]; then
      dbg "retrying with:$opts"
      # shellcheck disable=SC2086
      e=$(curl -fsSL --max-time 30 $opts -o "$out" "$url" 2>&1); rc=$?
      [ -n "$bundle" ] && rm -f "$bundle"
      [ $rc -eq 0 ] && { dbg "downloaded using${px:+ system proxy $px}${bundle:+ keychain-installed CAs}"; return 0; }
      FETCH_ERR="$FETCH_ERR | retry: curl exit $rc: ${e:-no detail}"
    fi
    scutil --proxy 2>/dev/null | grep -q 'ProxyAutoConfigEnable : 1' && \
      FETCH_ERR="$FETCH_ERR | this Mac uses a PAC proxy file, which curl cannot read"
  fi
  return 1
}

BCNEW=""; BC_FAILED=$BC_FAILED_PRESET; BC_SRC=""; BC_SHA=""; BC_LABEL=""; BC_COUNT=0; BLOCKED_CERTS_LABEL="${BLOCKED_CERTS_LABEL:-}"
get_blocked() {   # load the reference blocklist once per process -> $BCNEW
  [ -n "$BCNEW" ] && return 0
  if [ $BC_FAILED -eq 1 ]; then dbg "blocked.certs unavailable for this run (see earlier error)"; return 1; fi
  local src="" got
  BCNEW=$(mktemp "${TMPDIR:-/tmp}/blocked.certs.XXXXXX") || { BC_FAILED=1; return 1; }
  # Optional override (a newer Oracle list): needs a SHA-256 pin outside dev mode.
  if [ -n "$BLOCKED_CERTS_FILE$BLOCKED_CERTS_URL" ]; then
    if [ -z "$BLOCKED_CERTS_SHA256" ]; then
      err_ "blocked.certs override given without a SHA-256 pin (\$6 / BLOCKED_CERTS_SHA256); using the embedded list"
    elif [ -n "$BLOCKED_CERTS_FILE" ]; then
      dbg "blocked.certs override: file $BLOCKED_CERTS_FILE"
      if cp "$BLOCKED_CERTS_FILE" "$BCNEW" 2>/dev/null; then src="$BLOCKED_CERTS_FILE"
      else err_ "cannot read blocked.certs override $BLOCKED_CERTS_FILE; using the embedded list"; fi
    elif fetch_url "$BLOCKED_CERTS_URL" "$BCNEW"; then src="$BLOCKED_CERTS_URL"
    else
      err_ "blocked.certs override download failed: $BLOCKED_CERTS_URL; using the embedded list"
      line ERROR "  $FETCH_ERR"
    fi
    if [ -n "$src" ]; then
      got=$(sha256_of "$BCNEW")
      dbg "override sha256=$got expected=${BLOCKED_CERTS_SHA256:-<not pinned>}"
      if [ -n "$BLOCKED_CERTS_SHA256" ] && [ "$got" != "$BLOCKED_CERTS_SHA256" ]; then
        err_ "blocked.certs override $src: SHA-256 $got does not match the pin; using the embedded list"; src=""
      elif ! head -1 "$BCNEW" | grep -q '^Algorithm='; then
        err_ "blocked.certs override $src has no Algorithm= header; using the embedded list"; src=""
      fi
    fi
  fi
  if [ -z "$src" ]; then
    embedded_blocklist > "$BCNEW"
    got=$(sha256_of "$BCNEW")
    if [ "$got" != "$EMBED_SHA" ]; then
      err_ "embedded blocklist is corrupt (sha256 $got); this copy of the script was altered"
      rm -f "$BCNEW"; BCNEW=""; BC_FAILED=1; return 1
    fi
    src="embedded"
  fi
  BC_SRC="$src"; BC_SHA="$got"; BC_LABEL="${BLOCKED_CERTS_LABEL:-$src}"
  BC_COUNT=$(($(wc -l < "$BCNEW")-1))
  dbg "reference blocklist: $BC_COUNT entries, sha256=$BC_SHA, source=$BC_SRC"
  return 0
}

# bl_missing FILE -> how many of the 16 compromised certificates FILE does not
# block, or BADFORMAT when it is not a clean "Algorithm=SHA-256" + hex list.
bl_missing() {
  local f="$1" keys
  if [ ! -r "$f" ]; then echo "$EMUDHRA_COUNT"; return; fi
  keys=$(awk '
    BEGIN { algo = 0; bad = 0 }
    { sub(/\r$/, ""); sub(/^[ \t]+/, ""); sub(/[ \t]+$/, "") }
    /^[#!]/ || /^$/ { next }
    /^Algorithm[ \t]*=[ \t]*SHA-256$/ { algo++; next }
    { sub(/[ \t]*=[ \t]*$/, ""); v = toupper($0)
      if (length(v) != 64 || v ~ /[^0-9A-F]/) bad = 1; else print v }
    END { if (algo != 1 || bad) exit 1 }' "$f") || { echo BADFORMAT; return; }
  comm -23 <(emudhra_fingerprints | sort -u) <(printf '%s\n' "$keys" | sort -u) | grep -c . | tr -d ' '
}

# jdk_blocklist_path JDK_HOME -> the file this JDK actually reads:
#   JDK 9+  lib/security/blocked.certs
#   JDK 8   jre/lib/security/blacklisted.certs (a JRE 8 home: lib/security/blacklisted.certs)
jdk_blocklist_path() {
  local jh="$1" c
  for c in "$jh/lib/security/blocked.certs" "$jh/jre/lib/security/blacklisted.certs" "$jh/lib/security/blacklisted.certs"; do
    [ -f "$c" ] && { echo "$c"; return; }
  done
  if [ -d "$jh/jre/lib/security" ]; then echo "$jh/jre/lib/security/blacklisted.certs"
  else echo "$jh/lib/security/blocked.certs"; fi
}

# =============================================================================
# Remediation
# =============================================================================
# Categories: java (additive, backed up), *-destructive (removes something:
# old Node versions, cacerts roots). Destructive actions are never implied by
# --yes: they need an interactive answer or --allow-destructive.
ask() {   # ask CATEGORY "question" -> 0 = go ahead
  local cat=$1 q=$2 r
  if [ "$ROLE" != dev ]; then
    if [ "$MODE" = remediate ] && { [ "$cat" = java ] || { [ "$cat" = java-destructive ] && [ $REMOVE_ROOTS -eq 1 ]; }; }; then
      dbg "auto-approved ($cat): $q"; return 0
    fi
    dbg "not auto-approved ($cat): $q"; return 1
  fi
  case "$cat" in
    *-destructive)
      if [ $YES -eq 1 ] && [ $ALLOW_DESTRUCTIVE -eq 0 ] && ! [ -t 0 ]; then
        say "  $q [skipped: destructive; needs an interactive answer or --allow-destructive]"; return 1
      fi
      [ $YES -eq 1 ] && [ $ALLOW_DESTRUCTIVE -eq 1 ] && { say "  $q [auto-yes, --allow-destructive]"; return 0; }
      printf '  %s [y/N] ' "$q"; read -r r </dev/tty || return 1
      case "$r" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac ;;
  esac
  [ $YES -eq 1 ] && { say "  $q [auto-yes]"; return 0; }
  printf '  %s [y/N] ' "$q"; read -r r </dev/tty || return 1
  case "$r" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

fix_java() {
  hdr "Fix: Java"
  local e jh ks alias needbc SUDO n_al al left bc merged hdrline stamp jdk_changed=0 miss
  local -a al_list
  stamp=$(date +%Y%m%d%H%M%S)
  for e in "${JDK_FIX[@]}"; do
    IFS='|' read -r jh ks alias needbc bc <<EOF
$e
EOF
    say "JDK: $jh"
    SUDO=""
    if [ ! -w "$ks" ] || [ ! -w "$(dirname "$ks")" ]; then
      if [ "$ROLE" != dev ] || [ $YES -eq 1 ]; then
        action "JDK $jh: $ks is not writable by $ME (owner $(owner_of "$ks")); fix as that account"; continue
      fi
      ask java "$ks is not writable by you. Use sudo?" || { skip_ "$jh"; continue; }
      SUDO="sudo"
    fi
    if [ -n "$alias" ]; then
      n_al=$(printf '%s' "$alias" | awk -F';' '{print NF}')
      if ask java-destructive "Back up cacerts and delete $n_al emSign root alias(es), matched by key: ${alias//;/, }?"; then
        if $SUDO cp -p "$ks" "$ks.bak-$stamp"; then
          dbg "backed up $ks -> $ks.bak-$stamp"
          # read -a: no pathname expansion ("[jdk]" is a glob and nullglob is on)
          IFS=';' read -r -a al_list <<< "$alias"
          for al in "${al_list[@]}"; do
            if $SUDO env -u JAVA_TOOL_OPTIONS -u JDK_JAVA_OPTIONS -u _JAVA_OPTIONS "$jh/bin/keytool" -delete -keystore "$ks" -storepass changeit -alias "$al" >/dev/null 2>&1 </dev/null; then
              done_ "removed '$al' from $ks"; jdk_changed=1
            else err_ "keytool could not delete '$al' from $ks"; fi
          done
          left=$(ks_emsign_roots "$jh/bin/keytool" "$ks")
          if [ -n "$left" ]; then err_ "G3 alias(es) still present in $ks: ${left//;/, }"
          else dbg "verified: no G3 aliases remain in $ks (backup $ks.bak-$stamp)"; fi
        else err_ "could not back up $ks; nothing deleted"; fi
      else
        if [ "$ROLE" = dev ]; then skip_ "cacerts root removal"
        else action "JDK $jh: delete G3 alias(es) ${alias//;/, } (run with \$4=remediate)"; fi
      fi
    fi

    [ "$needbc" = "1" ] || continue
    if ! ask java "Merge Oracle's blocklist ($BC_COUNT entries) into $bc?"; then
      if [ "$ROLE" = dev ]; then skip_ "blocked.certs"
      else action "JDK $jh: install Oracle blocked.certs (run with \$4=remediate)"; fi
      continue
    fi
    if ! get_blocked; then
      action "JDK $jh: merge Oracle blocked.certs (reference list unavailable this run; see errors)"; continue
    fi
    merged=$(mktemp "${TMPDIR:-/tmp}/blocked.merged.XXXXXX")
    hdrline=$(head -1 "$BCNEW")
    if [ -f "$bc" ] && [ "$(head -1 "$bc")" != "$hdrline" ]; then
      err_ "existing $bc uses a different algorithm header; install manually"; rm -f "$merged"; continue
    fi
    { echo "$hdrline"
      { tail -n +2 "$BCNEW"; [ -f "$bc" ] && tail -n +2 "$bc"; } | grep -v '^[[:space:]]*$' | sort -u
    } > "$merged"
    dbg "merged blocked.certs for $jh: $(($(wc -l < "$merged")-1)) entries ($( [ -f "$bc" ] && echo $(($(wc -l < "$bc")-1)) || echo 0) existing)"
    if { [ ! -f "$bc" ] || $SUDO cp -p "$bc" "$bc.bak-$stamp"; } && $SUDO cp "$merged" "$bc" && $SUDO chmod 644 "$bc"; then
      miss=$(bl_missing "$bc")
      if [ "$miss" -eq 0 ]; then
        done_ "$(basename "$bc") updated in $jh ($(($(wc -l < "$merged")-1)) entries, all $EMUDHRA_COUNT compromised certificates now blocked)"; jdk_changed=1
        echo "$(date '+%Y-%m-%d') sha256=$BC_SHA source=$BC_LABEL" | $SUDO tee "$bc.emudhra-installed" >/dev/null
      else err_ "$bc written but $miss compromised certificates are still not blocked"; fi
    else err_ "could not write $bc"; fi
    rm -f "$merged"
  done
  if [ $jdk_changed -eq 1 ]; then
    if [ "$ROLE" != dev ]; then
      info "running Gradle daemons keep the old trust store until they restart; JDK upgrades restore the old cacerts and the next policy run re-applies the fix"
    elif command -v gradle >/dev/null 2>&1; then
      gradle --stop >/dev/null 2>&1 && done_ "stopped Gradle daemons"
      MANUAL+=("JDK upgrades restore the old cacerts: re-run this script after each until a fixed JDK ships")
    else
      MANUAL+=("Restart Gradle daemons (./gradlew --stop) so builds pick up the new trust store")
      MANUAL+=("JDK upgrades restore the old cacerts: re-run this script after each until a fixed JDK ships")
    fi
  fi
}

fix_node_dev() {
  hdr "Fix: Node.js"
  local NVM_SH nvm_ok=0 majors="" e nb rest v mj f p def
  local -a old_nvm
  old_nvm=()
  NVM_SH="${NVM_DIR:-$HOME/.nvm}/nvm.sh"
  # shellcheck disable=SC1090
  [ -s "$NVM_SH" ] && . "$NVM_SH" >/dev/null 2>&1 && command -v nvm >/dev/null 2>&1 && nvm_ok=1
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
  [ -n "$majors" ] || return 0
  if [ $nvm_ok -eq 0 ]; then
    err_ "nvm installs found but $NVM_SH could not be loaded; run: nvm install <major> for: $majors"; return 0
  fi
  def=$(nvm version default 2>/dev/null); def=${def#v}
  for mj in $majors; do
    if ask node "nvm install $mj (latest $mj.x, carries global packages over)?"; then
      if nvm install "$mj" --reinstall-packages-from="$mj" >/dev/null 2>&1 || nvm install "$mj" >/dev/null 2>&1; then
        done_ "node $(nvm version "$mj") installed"
        if [ "${def%%.*}" = "$mj" ]; then nvm alias default "$mj" >/dev/null && done_ "nvm default -> $mj"; fi
      else err_ "nvm install $mj failed (network/proxy?)"; fi
    else skip_ "node $mj"; fi
  done
  case "${def%%.*}" in
    22|24|26) ;;
    *) case " ${old_nvm[*]} " in *" $def "*)
         if ask node "Your default node $def is end-of-life. Set nvm default to 24?"; then
           nvm alias default 24 >/dev/null && done_ "nvm default -> 24"
         fi ;;
       esac ;;
  esac
  if ask node-destructive "Uninstall the old flagged versions (${old_nvm[*]}) and their global packages?"; then
    nvm use default >/dev/null 2>&1
    for v in "${old_nvm[@]}"; do
      if nvm uninstall "$v" >/dev/null 2>&1; then done_ "removed node $v"
      else err_ "could not remove node $v (in use?)"; fi
    done
  else skip_ "old node versions kept; they stay vulnerable"; fi
}

fix_brew_dev() {
  hdr "Fix: Homebrew"
  command -v brew >/dev/null 2>&1 || { err_ "brew not on PATH"; return 0; }
  say "  Note: brew upgrade can also upgrade or remove dependent formulae."
  if ask brew "brew update && brew upgrade $BREW_PKGS?"; then
    # shellcheck disable=SC2086
    if brew update >/dev/null 2>&1 && brew upgrade $BREW_PKGS; then done_ "brew upgrade $BREW_PKGS"
    else err_ "brew upgrade failed; re-run it manually to see why"; fi
    case " $BREW_PKGS " in *" go "*) MANUAL+=("Rebuild Go binaries you built or 'go install'ed with the old toolchain") ;; esac
  else skip_ "Homebrew packages"; fi
}

fix_pip_dev() {
  hdr "Fix: pip"
  local e py v
  for e in "${PIP_FIX[@]}"; do
    py=${e%%|*}; v=${e#*|}
    if ask pip "$py -m pip install -U pip (currently $v)?"; then
      if "$py" -m pip install -q -U pip 2>/dev/null; then
        done_ "pip $("$py" -m pip --version 2>/dev/null | awk '{print $2}') in $py"
      else err_ "pip upgrade failed for $py (externally managed? Homebrew Python: brew upgrade python; venvs: upgrade inside the venv)"; fi
    else skip_ "pip in $py"; fi
  done
}

fix_uv_dev() {
  hdr "Fix: uv"
  local e u
  for e in "${UV_FIX[@]}"; do
    u=${e%%|*}
    if ask uv "$u self update?"; then
      if "$u" self update >/dev/null 2>&1; then done_ "uv $("$u" --version 2>/dev/null | awk '{print $2}') at $u"
      else err_ "uv self update failed for $u (installed by pipx/pip? upgrade it there)"; fi
    else skip_ "uv at $u"; fi
  done
}

fix_python_dev() {
  hdr "Fix: Python certifi"
  local py
  for py in "${CERTIFI_FIX[@]}"; do
    if ask pip "$py -m pip install -U certifi?"; then
      if "$py" -m pip install -q -U certifi 2>/dev/null; then
        done_ "certifi $("$py" -c 'import certifi;print(certifi.__version__)' 2>/dev/null) in $py"
      else err_ "pip failed for $py (externally managed? use its venv or: pipx upgrade-all)"; fi
    else skip_ "$py"; fi
  done
}

# Fleet passes: non-Java findings become developer actions (no unattended
# network installs or brew side effects).
record_dev_actions() {
  local e nb rest v mj py
  if [ ${#NODE_FIX[@]} -gt 0 ]; then
    for e in "${NODE_FIX[@]}"; do
      nb=${e%%|*}; rest=${e#*|}; v=${rest%%|*}; mj=${rest##*|}
      restate "Node $v at $nb: upgrade to a fixed $mj.x release (nvm install $mj / brew upgrade / nodejs.org pkg)"
    done
  fi
  [ -n "$BREW_PKGS" ] && restate "Homebrew owner ($ME): brew upgrade $BREW_PKGS"
  if [ ${#CERTIFI_FIX[@]} -gt 0 ]; then
    for py in "${CERTIFI_FIX[@]}"; do restate "$py: pip install -U certifi (>= 2026.10.19)"; done
  fi
  if [ ${#PIP_FIX[@]} -gt 0 ]; then
    for e in "${PIP_FIX[@]}"; do restate "${e%%|*}: pip ${e#*|} -> python -m pip install -U pip (>= 26.2.2; Homebrew Python: brew upgrade python)"; done
  fi
  if [ ${#UV_FIX[@]} -gt 0 ]; then
    for e in "${UV_FIX[@]}"; do restate "${e%%|*}: uv ${e#*|} -> uv self update (>= 0.13.4)"; done
  fi
  return 0
}

# Fleet audit mode: list what remediate would do, change nothing.
record_java_actions() {
  local e jh ks alias needbc
  for e in "${JDK_FIX[@]}"; do
    IFS='|' read -r jh ks alias needbc bc <<EOF
$e
EOF
    [ -n "$alias" ] && restate "JDK $jh: delete G3 alias(es) ${alias//;/, } from cacerts (remediate with root removal enabled does this)"
    [ "$needbc" = "1" ] && restate "JDK $jh: merge Oracle's blocklist into $bc (remediate mode does this)"
  done
  return 0
}

run_fixes() {
  FIXED=0; SKIPPED=0; ERRORS=${ERRORS:-0}
  if [ "$ROLE" != dev ] && [ "$MODE" = audit ]; then
    record_dev_actions
    [ ${#JDK_FIX[@]} -gt 0 ] && record_java_actions
    return 0
  fi
  if [ "$ROLE" = dev ]; then
    [ ${#NODE_FIX[@]} -gt 0 ] && fix_node_dev
    [ -n "$BREW_PKGS" ] && fix_brew_dev
  else
    record_dev_actions
  fi
  [ ${#JDK_FIX[@]} -gt 0 ] && fix_java
  [ "$ROLE" = dev ] && [ ${#PIP_FIX[@]} -gt 0 ] && fix_pip_dev
  [ "$ROLE" = dev ] && [ ${#CERTIFI_FIX[@]} -gt 0 ] && fix_python_dev
  [ "$ROLE" = dev ] && [ ${#UV_FIX[@]} -gt 0 ] && fix_uv_dev
  return 0
}

has_fixables() { [ $FAIL -gt 0 ] || [ ${#JDK_FIX[@]} -gt 0 ]; }

# =============================================================================
# One pass = audit -> (fix -> verify)
# =============================================================================
ACTIONS=(); ERRORS=0; FIXED=0; SKIPPED=0; RESULTS=(); MANUAL=(); PIP_FIX=(); UV_FIX=()
PASS=0; WARN=0; FAIL=0; PEND=0; UNV=0; BUNDLE_CACHE=""
run_pass() {
  local st
  say "${B}eMudhra/emSign trust audit${N} v$VERSION - $(hostname -s 2>/dev/null) - account $ME - mode $MODE"
  dbg "HOME=$HOME PATH=$PATH perl-timeout=$([ -n "$PERL" ] && echo yes || echo no)"
  run_audit
  st=$(pass_status)
  say "${B}Audit result: $st${N}  $(counts)"

  if ! has_fixables; then return 0; fi
  if [ "$ROLE" = dev ]; then
    [ "$MODE" = audit ] && return 0
    if [ $YES -eq 0 ] && ! [ -t 0 ]; then return 0; fi
    say ""; say "${B}Remediation available${N}"
    [ ${#NODE_FIX[@]} -gt 0 ]    && say "  - Node: ${#NODE_FIX[@]} unpatched install(s)"
    [ -n "$BREW_PKGS" ]          && say "  - Homebrew: brew upgrade $BREW_PKGS"
    [ ${#JDK_FIX[@]} -gt 0 ]     && say "  - Java: ${#JDK_FIX[@]} JDK(s) (cacerts root removal and/or Oracle blocked.certs)"
    [ ${#PIP_FIX[@]} -gt 0 ]     && say "  - pip: ${#PIP_FIX[@]} interpreter(s) below 26.2.2"
    [ ${#CERTIFI_FIX[@]} -gt 0 ] && say "  - Python: certifi in ${#CERTIFI_FIX[@]} interpreter(s)"
    [ ${#UV_FIX[@]} -gt 0 ]      && say "  - uv: ${#UV_FIX[@]} install(s) below 0.13.4"
    say ""
    ask any "Proceed to remediation? Each fix is confirmed separately." || { say "  No changes made."; return 0; }
  fi
  run_fixes
  if [ "$ROLE" != dev ] && [ "$MODE" = audit ]; then say "Audit only: ${#ACTIONS[@]} action(s) recorded, nothing changed"
  else say "${B}Remediation: fixed=$FIXED skipped=$SKIPPED errors=$ERRORS actions=${#ACTIONS[@]}${N}"; fi
  if [ ${#MANUAL[@]} -gt 0 ]; then
    local m; local -a saved_manual; saved_manual=("${MANUAL[@]}")
    for m in "${saved_manual[@]}"; do action "$m"; done
  fi
  if [ $FIXED -gt 0 ]; then
    hdr "Verification"
    local -a keep_errors; keep_errors=()
    # errors from fixing survive the re-audit (guarded: bash 3.2 + set -u rejects empty "${a[@]}")
    [ ${#RESULTS[@]} -gt 0 ] && keep_errors=("${RESULTS[@]}")
    run_audit
    local r
    if [ ${#keep_errors[@]} -gt 0 ]; then
      for r in "${keep_errors[@]}"; do case "$r" in ERROR\|*) RESULTS+=("$r") ;; esac; done
    fi
    say "${B}Verified result: $(pass_status)${N}  $(counts)"
  fi
  return 0
}

# Machine-readable summary consumed by the fleet orchestrator.
emit_summary() {
  local r a
  printf '@@SUMMARY|%s|%s|%s|%s|%s|%s|%s\n' "$PASS" "$WARN" "$FAIL" "$FIXED" "$ERRORS" "$PEND" "$UNV"
  if [ ${#RESULTS[@]} -gt 0 ]; then for r in "${RESULTS[@]}"; do printf '@@RESULT|%s\n' "$r"; done; fi
  if [ ${#ACTIONS[@]} -gt 0 ]; then for a in "${ACTIONS[@]}"; do printf '@@ACTION|%s\n' "$a"; done; fi
  if [ ${#NOT_COVERED[@]} -gt 0 ]; then for a in "${NOT_COVERED[@]}"; do printf '@@NOTCOV|%s\n' "$a"; done; fi
}

# print_summary STATUS EXIT_CODE
# Plain-language end of run, built from SUM_ITEMS ("who|SEV|message<US>fix"),
# SUM_ACTIONS ("who|text") and SUM_NOTC. Identical lines are shown once.
SUM_ITEMS=(); SUM_ACTIONS=(); SUM_NOTC=()
print_summary() {
  local st=$1 code=$2 r who rest sev body msg fix nf=0 np=0 nu=0 i shown="" key tag
  local -a fixl pendl revl
  fixl=(); pendl=(); revl=()
  if [ ${#SUM_ITEMS[@]} -gt 0 ]; then
    for r in "${SUM_ITEMS[@]}"; do
      who=${r%%|*}; rest=${r#*|}; sev=${rest%%|*}; body=${rest#*|}
      msg=${body%%"$US"*}; fix=""; case "$body" in *"$US"*) fix=${body#*"$US"} ;; esac
      key="$sev|$msg"
      case "$shown" in *"<$key>"*) continue ;; esac
      shown="$shown<$key>"
      tag=""; [ -n "$who" ] && tag="[$who] "
      case "$sev" in
        FAIL)              fixl+=("$tag$msg$US$fix"); nf=$((nf+1)) ;;
        PENDING)           pendl+=("$tag$msg$US$fix"); np=$((np+1)) ;;
        UNVERIFIED|ERROR)  revl+=("$tag$msg$US$fix"); nu=$((nu+1)) ;;
      esac
    done
  fi
  echo ""
  echo "======================== SUMMARY ========================"
  echo "STATUS: $st   ($nf to fix, $np waiting on a vendor, $nu to review)"
  case "$st" in
    PROTECTED)      echo "Every inspected runtime rejects the compromised certificates." ;;
    EXPOSED)        echo "Something here still trusts the compromised certificates and has a fix. Start with 'Fix now'." ;;
    UNVERIFIED)     echo "Nothing is known to be exposed, but some items could not be proven. See 'Review'." ;;
    VENDOR_PENDING) echo "Nothing left to fix here; the remaining items wait on Apple or an IDE vendor." ;;
  esac
  if [ $nf -gt 0 ]; then
    echo ""; echo "Fix now:"
    i=0; for r in "${fixl[@]}"; do i=$((i+1)); echo "  $i. ${r%%"$US"*}"; [ -n "${r#*"$US"}" ] && echo "     Fix: ${r#*"$US"}"; done
  fi
  if [ $np -gt 0 ]; then
    echo ""; echo "Waiting on a vendor (nothing to do now):"
    for r in "${pendl[@]}"; do echo "  - ${r%%"$US"*}"; [ -n "${r#*"$US"}" ] && echo "     Next: ${r#*"$US"}"; done
  fi
  if [ $nu -gt 0 ]; then
    echo ""; echo "Review (could not be proven either way):"
    for r in "${revl[@]}"; do echo "  - ${r%%"$US"*}"; [ -n "${r#*"$US"}" ] && echo "     Check: ${r#*"$US"}"; done
  fi
  if [ ${#SUM_ACTIONS[@]} -gt 0 ] && printf '%s\n' "${SUM_ACTIONS[@]}" | grep -qv '^[^|]*|~'; then
    echo ""; echo "Also to do:"
    shown=""
    for r in "${SUM_ACTIONS[@]}"; do
      who=${r%%|*}; body=${r#*|}; case "$body" in "~"*) continue ;; esac
      case "$shown" in *"<$body>"*) continue ;; esac; shown="$shown<$body>"
      tag=""; [ -n "$who" ] && tag="[$who] "; echo "  - $tag$body"
    done
  fi
  [ "$WARN_TOTAL" -gt 0 ] && { echo ""; echo "Advisories: $WARN_TOTAL (WARN lines above; they do not change the status)"; }
  if [ ${#SUM_NOTC[@]} -gt 0 ]; then
    echo ""; echo "Not covered by this audit (not counted):"
    shown=""
    for r in "${SUM_NOTC[@]}"; do case "$shown" in *"<$r>"*) continue ;; esac; shown="$shown<$r>"; echo "  - $r"; done
  fi
  echo ""
  echo "Technical: exit $code | $SUM_COUNTS | jamf-emsign.sh v$VERSION"
  [ "$st" = PROTECTED ] || echo "Anything other than PROTECTED is not proof of protection."
  echo "=========================================================="
}

# =============================================================================
# Entry points
# =============================================================================
if [ "$ROLE" = dev ]; then
  run_pass
  st=$(pass_status)
  if [ $EA -eq 1 ]; then
    f=""; [ ${#RESULTS[@]} -gt 0 ] && f=$(printf '%s; ' "${RESULTS[@]}" | sed "s/$US/ | fix: /g")
    echo "<result>$st ($FAIL fail, $WARN warn) ${f% }</result>"; exit 0
  fi
  [ $ERRORS -gt 0 ] && [ "$st" != EXPOSED ] && st=UNVERIFIED
  case "$st" in EXPOSED) rc=2 ;; UNVERIFIED) rc=3 ;; VENDOR_PENDING) rc=1 ;; *) rc=0 ;; esac
  for r in ${RESULTS[@]+"${RESULTS[@]}"}; do SUM_ITEMS+=("|$r"); done
  for a in ${ACTIONS[@]+"${ACTIONS[@]}"}; do SUM_ACTIONS+=("|$a"); done
  for a in ${NOT_COVERED[@]+"${NOT_COVERED[@]}"}; do SUM_NOTC+=("$a"); done
  WARN_TOTAL=$WARN; SUM_COUNTS=$(counts)
  print_summary "$st" "$rc"
  exit $rc
fi

if [ "$ROLE" = userpass ]; then
  run_pass
  emit_summary
  exit 0
fi

# ---- fleet orchestrator (root) -----------------------------------------------
# Same PATH as the user passes, so a local sudo test behaves like Jamf.
export PATH="$SYS_PATH"
case "$MODE" in audit|remediate) ;; *) echo "invalid mode '$MODE' (use audit or remediate)" >&2; exit 2 ;; esac
case "$USER_SCOPE" in all|console) ;; *) echo "invalid users scope '$USER_SCOPE' (use all or console)" >&2; exit 2 ;; esac

# Log to the policy output and a local file.
if [ -n "$LOGFILE" ] && mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null && touch "$LOGFILE" 2>/dev/null; then
  if [ "$(wc -c < "$LOGFILE")" -gt 5242880 ]; then mv -f "$LOGFILE" "$LOGFILE.1"; fi
  exec > >(tee -a "$LOGFILE") 2>&1
fi

LOCK=/var/run/emsign-check.lock
[ -d /var/run ] || LOCK=/tmp/emsign-check.lock
if ! mkdir "$LOCK" 2>/dev/null; then
  if [ -n "$(find "$LOCK" -maxdepth 0 -mmin +120 2>/dev/null)" ]; then
    line WARN "removing stale lock $LOCK"; rm -rf "$LOCK"; mkdir "$LOCK" || exit 2
  else
    line ERROR "another run holds $LOCK; exiting"; exit 2
  fi
fi
WORK=$(mktemp -d /tmp/emsign-check.XXXXXX) || exit 2
chmod 755 "$WORK"
cleanup() { rm -rf "$WORK" "$LOCK"; [ -n "$BCNEW" ] && rm -f "$BCNEW"; }
trap cleanup EXIT
if ! { cp "$0" "$WORK/jamf-emsign.sh" && chmod 755 "$WORK/jamf-emsign.sh"; }; then
  line ERROR "cannot stage script copy"; exit 2
fi

line INFO "===== emsign-check v$VERSION start: mode=$MODE users=$USER_SCOPE verbose=$VERBOSE fail_on_exposed=$FAIL_ON_EXPOSED recon=$RUN_RECON remove_roots=$REMOVE_ROOTS ====="
line INFO "host=$(hostname 2>/dev/null) serial=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformSerialNumber/{print $4}') console_user=$(stat -f%Su /dev/console 2>/dev/null || echo n/a)"
dbg "blocked.certs: url=${BLOCKED_CERTS_URL:-<none>} file=${BLOCKED_CERTS_FILE:-<none>} sha256=${BLOCKED_CERTS_SHA256:-<none>}"

# Stage the reference blocklist once (embedded, or a pinned override); user
# passes get a read-only copy so every account is judged against the same list.
STAGED_BC=""; STAGED_LABEL=""
if get_blocked; then
    STAGED_BC="$WORK/blocked.certs"; cp "$BCNEW" "$STAGED_BC" && chmod 644 "$STAGED_BC"
    BLOCKED_CERTS_FILE="$STAGED_BC"
    STAGED_LABEL=$(printf '%s' "$BC_SRC" | sed 's#.*/##; s/[^A-Za-z0-9._-]/_/g'); BLOCKED_CERTS_LABEL="$STAGED_LABEL"
    line INFO "reference blocklist: $BC_COUNT entries, sha256 $BC_SHA, source $BC_SRC"
else
    line ERROR "no reference blocklist; JDKs cannot be evaluated"
fi

AGG_PASS=0; AGG_WARN=0; AGG_FAIL=0; AGG_FIXED=0; AGG_ERR=0; AGG_PEND=0; AGG_UNV=0
AGG_RESULTS=(); AGG_ACTIONS=(); AGG_NOTC=(); USERS_SCANNED=""; USERS_FAILED=""
agg_add_result() { AGG_RESULTS+=("$1"); }
agg_add_action() { AGG_ACTIONS+=("$1"); }

# 1) system pass, in this process, as root
run_pass
AGG_PASS=$((AGG_PASS+PASS)); AGG_WARN=$((AGG_WARN+WARN)); AGG_FAIL=$((AGG_FAIL+FAIL))
AGG_PEND=$((AGG_PEND+PEND)); AGG_UNV=$((AGG_UNV+UNV))
AGG_FIXED=$((AGG_FIXED+FIXED)); AGG_ERR=$((AGG_ERR+ERRORS))
if [ ${#RESULTS[@]} -gt 0 ]; then for r in "${RESULTS[@]}"; do agg_add_result "system|$r"; done; fi
if [ ${#ACTIONS[@]} -gt 0 ]; then for a in "${ACTIONS[@]}"; do agg_add_action "system|$a"; done; fi
for a in ${NOT_COVERED[@]+"${NOT_COVERED[@]}"}; do AGG_NOTC+=("$a"); done

# 2) user passes, each as that user with a clean environment
list_users() {
  if [ "$USER_SCOPE" = console ]; then
    local cu; cu=$(stat -f%Su /dev/console 2>/dev/null)
    case "$cu" in ""|root|loginwindow|_mbsetupuser) ;; *) echo "$cu" ;; esac
    return
  fi
  if command -v dscl >/dev/null 2>&1; then
    dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 501 && $1 !~ /^_/ {print $1}'
  else
    getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 {print $1}'
  fi
}
home_of() {
  if command -v dscl >/dev/null 2>&1; then
    dscl . -read "/Users/$1" NFSHomeDirectory 2>/dev/null | awk '{print $2}'
  else getent passwd "$1" | cut -d: -f6; fi
}

# Per-pass timeout prefix; ${A[@]+"${A[@]}"} is the bash 3.2-safe way to expand a maybe-empty array.
TIMEOUT_PREFIX=()
[ -n "$PERL" ] && TIMEOUT_PREFIX=("$PERL" -e 'alarm shift @ARGV; exec @ARGV or exit 127' 900)

for u in $(list_users); do
  h=$(home_of "$u")
  if [ -z "$h" ] || [ ! -d "$h" ] || [ "$h" = /var/empty ]; then dbg "skip user $u: no home folder (${h:-none})"; continue; fi
  line INFO "===== user pass: $u (home $h) ====="
  uargs="--user-pass --label=user:$u --mode=$MODE"
  [ $VERBOSE -eq 1 ] && uargs="$uargs --verbose"
  [ $REMOVE_ROOTS -eq 1 ] && uargs="$uargs --remove-roots"
  [ -n "$STAGED_BC" ] && uargs="$uargs --blocked-file=$STAGED_BC"
  [ -n "$STAGED_LABEL" ] && uargs="$uargs --blocked-label=$STAGED_LABEL"
  [ -n "$STAGED_BC" ] && uargs="$uargs --blocked-sha256=$BC_SHA"
  [ -z "$STAGED_BC" ] && uargs="$uargs --blocked-unavailable"
  got_summary=0
  # shellcheck disable=SC2086
  while IFS= read -r l; do
    case "$l" in
      @@SUMMARY\|*)
        IFS='|' read -r _ p w f x e pd uv <<EOF
$l
EOF
        AGG_PASS=$((AGG_PASS+p)); AGG_WARN=$((AGG_WARN+w)); AGG_FAIL=$((AGG_FAIL+f))
        AGG_FIXED=$((AGG_FIXED+x)); AGG_ERR=$((AGG_ERR+e)); AGG_PEND=$((AGG_PEND+${pd:-0})); AGG_UNV=$((AGG_UNV+${uv:-0}))
        got_summary=1
        dbg "summary from $u: pass=$p fail=$f pending=${pd:-0} unverified=${uv:-0} advisory=$w fixed=$x errors=$e" ;;
      @@RESULT\|*) agg_add_result "$u|${l#@@RESULT|}" ;;
      @@ACTION\|*) agg_add_action "$u|${l#@@ACTION|}" ;;
      @@NOTCOV\|*) AGG_NOTC+=("${l#@@NOTCOV|}") ;;
      *) printf '%s\n' "$l" ;;
    esac
  done < <(cd / && sudo -n -H -u "$u" /usr/bin/env -i HOME="$h" USER="$u" LOGNAME="$u" \
             PATH="$SYS_PATH" TMPDIR=/tmp LANG=en_US.UTF-8 SHELL=/bin/bash PERL_BADLANG=0 \
             COREPACK_ENABLE_DOWNLOAD_PROMPT=0 COREPACK_ENABLE_NETWORK=0 npm_config_update_notifier=false \
             ${TIMEOUT_PREFIX[@]+"${TIMEOUT_PREFIX[@]}"} \
             /bin/bash "$WORK/jamf-emsign.sh" $uargs </dev/null 2>&1)
  USERS_SCANNED="${USERS_SCANNED:+$USERS_SCANNED,}$u"
  if [ $got_summary -eq 0 ]; then
    line ERROR "user pass for $u ended without a summary (timeout, sudo refused, or crash)"
    AGG_ERR=$((AGG_ERR+1)); USERS_FAILED="${USERS_FAILED:+$USERS_FAILED,}$u"
    agg_add_result "$u|ERROR|user pass incomplete"
  fi
done
[ -z "$USERS_SCANNED" ] && line WARN "no user accounts scanned (scope=$USER_SCOPE)"

# ---- final report -------------------------------------------------------------
# Errors and incomplete user passes mean the machine was not fully proven.
if [ $AGG_FAIL -gt 0 ]; then FINAL=EXPOSED
elif [ $AGG_UNV -gt 0 ] || [ $AGG_ERR -gt 0 ]; then FINAL=UNVERIFIED
elif [ $AGG_PEND -gt 0 ]; then FINAL=VENDOR_PENDING
else FINAL=PROTECTED; fi
DURATION=$(( $(date +%s) - START_EPOCH ))

line INFO "result=$FINAL pass=$AGG_PASS fail=$AGG_FAIL pending=$AGG_PEND unverified=$AGG_UNV advisory=$AGG_WARN fixed=$AGG_FIXED errors=$AGG_ERR users=${USERS_SCANNED:-none} duration=${DURATION}s"
case "$FINAL" in EXPOSED|UNVERIFIED) frc=$FAIL_ON_EXPOSED ;; *) frc=0 ;; esac
SUM_ITEMS=(${AGG_RESULTS[@]+"${AGG_RESULTS[@]}"}); SUM_ACTIONS=(${AGG_ACTIONS[@]+"${AGG_ACTIONS[@]}"}); SUM_NOTC=(${AGG_NOTC[@]+"${AGG_NOTC[@]}"})
WARN_TOTAL=$AGG_WARN
SUM_COUNTS="pass=$AGG_PASS fail=$AGG_FAIL pending=$AGG_PEND unverified=$AGG_UNV advisory=$AGG_WARN fixed=$AGG_FIXED errors=$AGG_ERR users=${USERS_SCANNED:-none} ${DURATION}s"
print_summary "$FINAL" "$frc"

# Status file for the extension attribute.
xml_esc() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
plist_str() { printf '  <key>%s</key><string>%s</string>\n' "$1" "$(xml_esc "$2")"; }
plist_int() { printf '  <key>%s</key><integer>%s</integer>\n' "$1" "$2"; }
fails_text=""; acts_text=""
if [ ${#AGG_RESULTS[@]} -gt 0 ]; then
  for r in "${AGG_RESULTS[@]}"; do case "$r" in *\|FAIL\|*|*\|ERROR\|*|*\|UNVERIFIED\|*|*\|PENDING\|*) fails_text="$fails_text${r%%"$US"*}; " ;; esac; done
fi
if [ ${#AGG_ACTIONS[@]} -gt 0 ]; then for a in "${AGG_ACTIONS[@]}"; do acts_text="$acts_text${a/|~/|}; "; done; fi
if mkdir -p "$ORG_DIR" 2>/dev/null; then
  tmpp="$STATUS_PLIST.tmp.$$"
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0"><dict>'
    plist_str Result "$FINAL"
    plist_str LastRun "$(date '+%Y-%m-%d %H:%M:%S %z')"
    plist_str Mode "$MODE"
    plist_str Version "$VERSION"
    plist_int Pass "$AGG_PASS"; plist_int Fail "$AGG_FAIL"; plist_int Pending "$AGG_PEND"
    plist_int Unverified "$AGG_UNV"; plist_int Advisory "$AGG_WARN"
    plist_int Fixed "$AGG_FIXED"; plist_int Errors "$AGG_ERR"
    plist_str Users "${USERS_SCANNED:-}"
    plist_str UsersIncomplete "${USERS_FAILED:-}"
    plist_str Failures "$(printf '%s' "${fails_text% }" | cut -c1-4000)"
    plist_str Actions "$(printf '%s' "${acts_text% }" | cut -c1-4000)"
    plist_int DurationSeconds "$DURATION"
    echo '</dict></plist>'
  } > "$tmpp"
  if mv -f "$tmpp" "$STATUS_PLIST" && chmod 644 "$STATUS_PLIST"; then line INFO "status written to $STATUS_PLIST"
  else line ERROR "could not write $STATUS_PLIST"; fi
else
  line ERROR "cannot create $ORG_DIR"
fi

if [ $RUN_RECON -eq 1 ] && [ -x /usr/local/bin/jamf ]; then
  line INFO "running jamf recon"; /usr/local/bin/jamf recon >/dev/null 2>&1 || line WARN "jamf recon failed"
fi

line INFO "===== emsign-check end: $FINAL (${DURATION}s) ====="
if [ $FAIL_ON_EXPOSED -eq 1 ] && { [ "$FINAL" = EXPOSED ] || [ "$FINAL" = UNVERIFIED ]; }; then exit 1; fi
exit 0
