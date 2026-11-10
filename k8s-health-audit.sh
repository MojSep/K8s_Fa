#!/bin/bash
# =============================================================================
#  k8s-health-audit.sh — Comprehensive Kubernetes Health & Configuration Audit
#  Visit more at https://github.com/MojSep
#
#  This script performs an exhaustive audit of a Kubernetes node (master or
#  worker) checking: file presence, file permissions, sensitive configuration
#  settings, security-relevant flags, runtime status, certificates, network
#  stack, and workload health.
#
#  Output is color-coded:
#      ✅ PASS   → GREEN
#      ⚠️  WARN   → YELLOW  (best-practice issue, not blocking)
#      ❌ FAIL   → RED     (critical: node/cluster may be unsafe or broken)
#      ℹ️  SKIP   → CYAN    (check not applicable on this node/host)
#
#  Usage:
#      sudo bash k8s-health-audit.sh            # full audit
#      sudo bash k8s-health-audit.sh --no-kubectl   # skip kubectl-based checks
# =============================================================================

set -uo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ─── Counters ────────────────────────────────────────────────────────────────
TOTAL=0; PASS=0; WARN=0; FAIL=0; SKIP=0
declare -a CRITICALS=()
declare -a WARNINGS=()

# ─── Options ─────────────────────────────────────────────────────────────────
SKIP_KUBECTL=false
[ "${1:-}" = "--no-kubectl" ] && SKIP_KUBECTL=true

# ─── Detect role ─────────────────────────────────────────────────────────────
IS_MASTER=false
IS_WORKER=false
if [ -d /etc/kubernetes/manifests ] && [ -f /etc/kubernetes/manifests/kube-apiserver.yaml ]; then
    IS_MASTER=true
fi
if [ -f /etc/kubernetes/kubelet.conf ]; then
    IS_WORKER=true
fi

# =============================================================================
#  PRINT HELPERS
# =============================================================================

print_banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                                      ║${NC}"
    echo -e "${CYAN}║          ██╗  ██╗ █████╗ ███████╗    █████╗ ██╗   ██╗██████╗        ║${NC}"
    echo -e "${CYAN}║          ██║ ██╔╝██╔══██╗██╔════╝   ██╔══██╗██║   ██║██╔══██╗       ║${NC}"
    echo -e "${CYAN}║          █████╔╝ ╚█████╔╝███████╗   ███████║██║   ██║██║  ██║       ║${NC}"
    echo -e "${CYAN}║          ██╔═██╗ ██╔══██╗╚════██║   ██╔══██║██║   ██║██║  ██║       ║${NC}"
    echo -e "${CYAN}║          ██║  ██╗╚█████╔╝███████║   ██║  ██║╚██████╔╝██████╔╝       ║${NC}"
    echo -e "${CYAN}║          ╚═╝  ╚═╝ ╚════╝ ╚══════╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝        ║${NC}"
    echo -e "${CYAN}║                                                                      ║${NC}"
    echo -e "${CYAN}║  ${BOLD}Visit more at https://github.com/MojSep${NC}${CYAN}                              ║${NC}"
    echo -e "${CYAN}║                                                                      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${DIM}  Date      : $(date -u +"%Y-%m-%d %H:%M:%S UTC")${NC}"
    echo -e "${DIM}  Hostname  : $(hostname)${NC}"
    echo -e "${DIM}  Role      : $([ "$IS_MASTER" = true ] && echo -n 'master ' || true)$([ "$IS_WORKER" = true ] && echo -n 'worker' || true)${NC}"
    echo -e "${DIM}  Kernel    : $(uname -r)${NC}"
    echo -e "${DIM}  Distro    : $(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'\"' -f2 || echo 'unknown')${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}▶ $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_ok() {
    TOTAL=$((TOTAL+1)); PASS=$((PASS+1))
    echo -e "  ${GREEN}✅ PASS${NC}  $1"
    [ -n "${2:-}" ] && echo -e "         ${GREEN}→ ${NC}$2"
}

print_warn() {
    TOTAL=$((TOTAL+1)); WARN=$((WARN+1))
    local msg="$1"; local issue="${2:-}"; local fix="${3:-}"
    WARNINGS+=("$msg | $issue")
    echo -e "  ${YELLOW}⚠️  WARN${NC}  $msg"
    [ -n "$issue" ] && echo -e "         ${YELLOW}→ ISSUE:${NC} $issue"
    [ -n "$fix"   ] && echo -e "         ${YELLOW}→ FIX:${NC}   $fix"
}

print_fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    local msg="$1"; local issue="${2:-}"; local fix="${3:-}"
    CRITICALS+=("$msg | $issue")
    echo -e "  ${RED}❌ FAIL${NC}  $msg"
    [ -n "$issue" ] && echo -e "         ${RED}→ ISSUE:${NC} $issue"
    [ -n "$fix"   ] && echo -e "         ${RED}→ FIX:${NC}   $fix"
}

print_skip() {
    TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1))
    echo -e "  ${CYAN}ℹ️  SKIP${NC}  $1"
}

# =============================================================================
#  REUSABLE CHECK FUNCTIONS
# =============================================================================

check_file() {
    local file="$1" severity="${2:-critical}" description="${3:-}"
    [ -z "$description" ] && description="File: $file"
    if [ -f "$file" ]; then
        print_ok "$description"
    else
        if [ "$severity" = "critical" ]; then
            print_fail "$description" "Required file is missing: $file" \
                "Reinstall/reinitialize Kubernetes or restore from backup"
        else
            print_warn "$description" "Optional file is missing: $file" \
                "Verify whether the feature tied to this file is required"
        fi
    fi
}

check_perm() {
    local file="$1" expected="$2"
    if [ ! -e "$file" ]; then return; fi
    local actual
    actual=$(stat -c "%a" "$file" 2>/dev/null)
    if [ "$actual" = "$expected" ]; then
        print_ok "Permissions correct ($actual): $file"
    else
        print_fail "Insecure permissions: $file" \
            "Expected mode $expected but found $actual — file is more permissive than allowed" \
            "chmod $expected $file && chown root:root $file"
    fi
}

check_dir_perm() {
    local dir="$1" expected="$2"
    if [ ! -d "$dir" ]; then return; fi
    local actual
    actual=$(stat -c "%a" "$dir" 2>/dev/null)
    if [ "$actual" = "$expected" ]; then
        print_ok "Directory permissions correct ($actual): $dir"
    else
        print_warn "Directory permissions non-standard: $dir" \
            "Expected mode $expected but found $actual" \
            "chmod $expected $dir"
    fi
}

# check_grep <file> <grep-ERE-pattern> <expected-substring> <desc> <severity> <fix>
check_grep() {
    local file="$1" pattern="$2" expected="$3" desc="$4"
    local severity="${5:-critical}" fix="${6:-}"

    if [ ! -f "$file" ]; then
        print_skip "$desc (file not present: $file)"
        return
    fi

    local match
    match=$(grep -E "$pattern" "$file" 2>/dev/null | head -1)

    if [ -z "$match" ]; then
        if [ "$severity" = "critical" ]; then
            print_fail "$desc" \
                "Required setting not found in $(basename "$file"): $expected" \
                "${fix:-Add the required configuration to $file}"
        else
            print_warn "$desc" \
                "Recommended setting not found in $(basename "$file"): $expected" \
                "${fix:-Consider adding $expected to $file}"
        fi
        return
    fi

    if echo "$match" | grep -qF -- "$expected"; then
        print_ok "$desc ($expected)"
    else
        if [ "$severity" = "critical" ]; then
            print_fail "$desc" \
                "Setting '$expected' expected but found: ${match:0:120}" \
                "${fix:-Replace the value in $file}"
        else
            print_warn "$desc" \
                "Setting '$expected' expected but found: ${match:0:120}" \
                "${fix:-Update $file to use $expected}"
        fi
    fi
}

check_sysctl() {
    local key="$1" expected="$2" desc="$3" severity="${4:-critical}"
    local val
    val=$(sysctl -n "$key" 2>/dev/null | tr -d ' ')
    if [ -z "$val" ]; then
        if [ "$severity" = "critical" ]; then
            print_fail "$desc" "sysctl key $key is not available" \
                "Ensure kernel module loaded and /etc/sysctl.d/99-kubernetes-cri.conf applied"
        else
            print_warn "$desc" "sysctl key $key is not available" \
                "Verify kernel configuration"
        fi
        return
    fi
    if [ "$val" = "$expected" ]; then
        print_ok "$desc = $val"
    else
        if [ "$severity" = "critical" ]; then
            print_fail "$desc" "Current value = $val, expected = $expected" \
                "sysctl -w $key=$expected  (and persist in /etc/sysctl.d/)"
        else
            print_warn "$desc" "Current value = $val, expected = $expected" \
                "Consider updating for best-practice"
        fi
    fi
}

check_service() {
    local svc="$1" severity="${2:-critical}"
    if ! systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
        print_skip "Service $svc is not installed on this host"
        return
    fi
    local state
    state=$(systemctl is-active "$svc" 2>/dev/null)
    if [ "$state" = "active" ]; then
        print_ok "Service active: $svc"
    else
        if [ "$severity" = "critical" ]; then
            print_fail "Service not running: $svc" \
                "systemctl status $svc reports '$state'" \
                "systemctl restart $svc && journalctl -u $svc -n 50"
        else
            print_warn "Service not running: $svc" "state=$state" \
                "systemctl restart $svc"
        fi
    fi
    # Enabled check
    local enabled
    enabled=$(systemctl is-enabled "$svc" 2>/dev/null)
    if [ "$enabled" = "enabled" ]; then
        print_ok "Service enabled at boot: $svc"
    else
        print_warn "Service not enabled at boot: $svc" "state=$enabled" \
            "systemctl enable $svc"
    fi
}

kc() { command -v kubectl >/dev/null 2>&1 && sudo -n true 2>/dev/null; }

kubectl_available() {
    command -v kubectl >/dev/null 2>&1 && kubectl get --raw='/healthz' >/dev/null 2>&1
}

# =============================================================================
#  SECTION 1 — OPERATING SYSTEM PREREQUISITES
# =============================================================================

section_os() {
    print_section "1. OPERATING SYSTEM PREREQUISITES"

    # Swap
    if [ -r /proc/swaps ]; then
        if [ "$(wc -l < /proc/swaps)" -gt 1 ]; then
            print_fail "Swap is enabled" \
                "Active swap files/partitions found — kubelet with failSwapOn=true will refuse to run" \
                "swapoff -a && sed -i '/ swap / s/^/#/' /etc/fstab"
        else
            print_ok "Swap is disabled"
        fi
    fi

    # Kernel modules
    if lsmod 2>/dev/null | grep -q '^overlay'; then
        print_ok "Kernel module loaded: overlay"
    else
        print_fail "Kernel module not loaded: overlay" \
            "Container runtime (overlay2/overlayfs) requires 'overlay' kernel module" \
            "modprobe overlay && echo overlay > /etc/modules-load.d/k8s.conf"
    fi

    if lsmod 2>/dev/null | grep -q '^br_netfilter'; then
        print_ok "Kernel module loaded: br_netfilter"
    else
        print_fail "Kernel module not loaded: br_netfilter" \
            "iptables-based service routing will not work without br_netfilter" \
            "modprobe br_netfilter && echo br_netfilter >> /etc/modules-load.d/k8s.conf"
    fi

    # Sysctl
    check_sysctl "net.ipv4.ip_forward"                     "1" "IPv4 forwarding enabled"               critical
    check_sysctl "net.bridge.bridge-nf-call-iptables"      "1" "Bridge netfilter iptables call"        critical
    check_sysctl "net.bridge.bridge-nf-call-ip6tables"     "1" "Bridge netfilter ip6tables call"       warning
    check_sysctl "vm.swappiness"                           "0" "vm.swappiness lowered"                 warning

    # /etc/modules-load.d/k8s.conf
    check_file "/etc/modules-load.d/k8s.conf" warning "Kernel modules load file"

    # /etc/sysctl.d/99-kubernetes-cri.conf
    if [ -f /etc/sysctl.d/99-kubernetes-cri.conf ]; then
        print_ok "Sysctl persistence file present: /etc/sysctl.d/99-kubernetes-cri.conf"
    else
        print_warn "Sysctl persistence file missing: /etc/sysctl.d/99-kubernetes-cri.conf" \
            "Kernel settings will not survive reboot" \
            "Create the file with required net.* sysctl entries"
    fi

    # /etc/hosts sanity
    if getent hosts "$(hostname)" >/dev/null 2>&1; then
        print_ok "Hostname resolves via /etc/hosts or DNS: $(hostname)"
    else
        print_warn "Hostname does not resolve: $(hostname)" \
            "kubelet/apiserver may fail certificate SAN checks" \
            "Add '$(hostname)' to /etc/hosts"
    fi

    # Time sync
    if timedatectl 2>/dev/null | grep -q "System clock synchronized: yes"; then
        print_ok "System clock is synchronized (NTP)"
    else
        print_warn "System clock may not be synchronized" \
            "etcd and TLS validation depend on accurate time" \
            "systemctl enable --now chrony  (or systemd-timesyncd)"
    fi

    # Time skew upper-bound
    local skew
    skew=$(chronyc tracking 2>/dev/null | awk '/System time/ {print $4}')
    if [ -n "${skew:-}" ]; then
        if awk -v v="$skew" 'BEGIN{exit !(v>0.5)}'; then
            print_warn "Large clock skew detected: ${skew}s" \
                "etcd may lose leader; consider re-syncing NTP" \
                "chronyc makestep"
        else
            print_ok "Clock skew within tolerance (${skew}s)"
        fi
    fi

    # Disk space on critical paths
    for path in / /var/lib/containerd /var/lib/kubelet /var/lib/etcd; do
        [ -d "$path" ] || continue
        local usage
        usage=$(df -P "$path" 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%')
        if [ -z "${usage:-}" ]; then continue; fi
        if [ "$usage" -ge 90 ]; then
            print_fail "Disk usage critical on $path: ${usage}%" \
                "Node is at risk of DiskPressure eviction" \
                "Clean logs/images: crictl rmi --prune; find /var/log/pods -name '*.log' -mtime +7 -delete"
        elif [ "$usage" -ge 80 ]; then
            print_warn "Disk usage high on $path: ${usage}%" \
                "Approaching DiskPressure threshold (default 85%)" \
                "Plan cleanup or expand the volume"
        else
            print_ok "Disk usage on $path: ${usage}%"
        fi

        # Inodes
        local iuse
        iuse=$(df -iP "$path" 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%')
        if [ -n "${iuse:-}" ] && [ "$iuse" -ge 90 ]; then
            print_warn "Inode usage high on $path: ${iuse}%" \
                "Filesystem can run out of inodes before running out of space" \
                "Identify large directories with: du -x -i --max-depth=1 $path"
        fi
    done

    # PID pressure
    local pid_cur pid_max
    pid_cur=$(ls /proc 2>/dev/null | grep -c '^[0-9]\+$')
    pid_max=$(cat /proc/sys/kernel/pid_max 2>/dev/null || echo 4194304)
    if [ "$pid_max" -gt 0 ]; then
        local pct=$(( pid_cur * 100 / pid_max ))
        if [ "$pct" -ge 80 ]; then
            print_warn "PID usage high: ${pid_cur}/${pid_max} (${pct}%)" \
                "Risk of PIDPressure eviction" \
                "Inspect heavy processes; consider raising kernel.pid_max"
        else
            print_ok "PID usage normal: ${pid_cur}/${pid_max} (${pct}%)"
        fi
    fi
}

# =============================================================================
#  SECTION 2 — CONTAINER RUNTIME (containerd / docker / crio)
# =============================================================================

section_runtime() {
    print_section "2. CONTAINER RUNTIME (CRI)"

    local runtime=""
    if systemctl list-unit-files 2>/dev/null | grep -q "^containerd.service"; then
        runtime="containerd"
    elif systemctl list-unit-files 2>/dev/null | grep -q "^crio.service"; then
        runtime="crio"
    elif systemctl list-unit-files 2>/dev/null | grep -q "^docker.service"; then
        runtime="docker"
    fi

    if [ -z "$runtime" ]; then
        print_fail "No container runtime service found" \
            "containerd, docker, and crio are all absent" \
            "Install containerd (recommended) before running kubelet"
        return
    fi

    print_ok "Detected container runtime: $runtime"
    check_service "$runtime" critical

    case "$runtime" in
        containerd)
            check_file "/etc/containerd/config.toml" critical "containerd main configuration"
            if [ -f /etc/containerd/config.toml ]; then
                check_grep "/etc/containerd/config.toml" \
                    'SystemdCgroup' 'true' \
                    "containerd SystemdCgroup enabled" critical \
                    "Set 'SystemdCgroup = true' under runc options to match kubelet cgroupDriver"
                check_grep "/etc/containerd/config.toml" \
                    'sandbox_image' 'pause' \
                    "containerd sandbox_image configured" warning \
                    "Set a valid pause sandbox image (e.g., registry.k8s.io/pause:3.10)"
                # Registry TLS check
                if grep -q 'insecure_skip_verify = true' /etc/containerd/config.toml 2>/dev/null; then
                    print_warn "containerd configured to skip registry TLS verification" \
                        "insecure_skip_verify = true exposes image pulls to MITM" \
                        "Use proper CA-signed certificates for the registry"
                else
                    print_ok "containerd registry TLS verification not globally disabled"
                fi
            fi

            # Socket
            if [ -S /run/containerd/containerd.sock ]; then
                print_ok "containerd CRI socket present: /run/containerd/containerd.sock"
            else
                print_fail "containerd CRI socket missing" \
                    "/run/containerd/containerd.sock not found — kubelet cannot connect to runtime" \
                    "systemctl restart containerd && check its logs"
            fi
            ;;
        crio)
            check_file "/etc/crio/crio.conf" critical "CRI-O main configuration"
            ;;
        docker)
            print_warn "Docker detected as runtime" \
                "Docker Engine was deprecated from CRI in Kubernetes 1.24+ (dockershim removed)" \
                "Migrate to containerd or CRI-O for supported operation"
            check_file "/etc/docker/daemon.json" warning "Docker daemon configuration"
            if [ -f /etc/docker/daemon.json ]; then
                check_grep "/etc/docker/daemon.json" \
                    '"exec-opts"' 'systemd' \
                    "Docker exec-opts uses systemd cgroup driver" critical \
                    "Add 'native.cgroupdriver=systemd' to avoid cgroup driver mismatch"
            fi
            ;;
    esac

    # crictl config
    if [ -f /etc/crictl.yaml ]; then
        print_ok "crictl configuration present: /etc/crictl.yaml"
    else
        print_warn "crictl configuration missing: /etc/crictl.yaml" \
            "crictl will fall back to defaults and may target the wrong endpoint" \
            "Create /etc/crictl.yaml with runtime-endpoint set"
    fi

    # crictl functional test
    if command -v crictl >/dev/null 2>&1; then
        if timeout 10 crictl version >/dev/null 2>&1; then
            local ver
            ver=$(crictl version 2>/dev/null | awk '/RuntimeName|RuntimeVersion/ {printf "%s ", $2}')
            print_ok "crictl can reach CRI endpoint ($ver)"
        else
            print_fail "crictl cannot reach CRI endpoint" \
                "CRI socket unreachable or misconfigured — kubelet will fail too" \
                "Check /etc/crictl.yaml and the runtime service"
        fi
    else
        print_warn "crictl not installed" \
            "Diagnostic tool for CRI missing" \
            "Install crictl from kubernetes-sigs/cri-tools releases"
    fi
}

# =============================================================================
#  SECTION 3 — KUBELET
# =============================================================================

section_kubelet() {
    print_section "3. KUBELET SERVICE AND CONFIGURATION"

    check_service kubelet critical

    check_file "/var/lib/kubelet/config.yaml" critical "Kubelet configuration file"
    check_file "/var/lib/kubelet/kubeadm-flags.env" warning "Kubelet kubeadm-flags environment file"

    # Kubelet config settings
    if [ -f /var/lib/kubelet/config.yaml ]; then
        check_grep "/var/lib/kubelet/config.yaml" \
            'cgroupDriver' 'systemd' \
            "Kubelet cgroupDriver = systemd" critical \
            "Set 'cgroupDriver: systemd' to match containerd SystemdCgroup=true"

        # Anonymous auth — accept both YAML nested and flat forms
        if grep -A2 'authentication:' /var/lib/kubelet/config.yaml 2>/dev/null | grep -A1 'anonymous:' | grep -q 'enabled: true' \
           || grep -qE 'anonymous:\s*\n\s*enabled:\s*true' /var/lib/kubelet/config.yaml 2>/dev/null; then
            print_fail "Kubelet anonymous authentication is ENABLED" \
                "Unauthenticated users can query kubelet API on :10250 — severe security risk" \
                "Set authentication.anonymous.enabled: false in /var/lib/kubelet/config.yaml"
        else
            print_ok "Kubelet anonymous authentication disabled"
        fi

        check_grep "/var/lib/kubelet/config.yaml" \
            'mode: Webhook' 'Webhook' \
            "Kubelet authorization mode = Webhook" critical \
            "Set 'authorization.mode: Webhook' to enforce RBAC on kubelet API"

        # readOnlyPort
        if grep -q 'readOnlyPort: 0' /var/lib/kubelet/config.yaml 2>/dev/null \
           || ! grep -q 'readOnlyPort' /var/lib/kubelet/config.yaml 2>/dev/null; then
            print_ok "Kubelet readOnlyPort disabled (0 or unset)"
        else
            print_warn "Kubelet readOnlyPort is non-zero" \
                "Unauthenticated read-only port exposes node data" \
                "Set readOnlyPort: 0 in /var/lib/kubelet/config.yaml"
        fi

        # Certificate rotation
        if grep -q 'rotateCertificates: true' /var/lib/kubelet/config.yaml 2>/dev/null; then
            print_ok "Kubelet certificate rotation enabled"
        else
            print_warn "Kubelet certificate rotation not enabled" \
                "Client certs may expire without automatic renewal" \
                "Set 'rotateCertificates: true' in /var/lib/kubelet/config.yaml"
        fi

        # serverTLSBootstrap
        if grep -q 'serverTLSBootstrap: true' /var/lib/kubelet/config.yaml 2>/dev/null; then
            print_ok "Kubelet serverTLSBootstrap enabled"
        else
            print_warn "Kubelet serverTLSBootstrap not enabled" \
                "Serving certificate will remain self-signed (default)" \
                "Consider 'serverTLSBootstrap: true' for managed serving certs"
        fi

        # protectKernelDefaults
        if grep -q 'protectKernelDefaults: true' /var/lib/kubelet/config.yaml 2>/dev/null; then
            print_ok "Kubelet protectKernelDefaults enabled"
        else
            print_warn "Kubelet protectKernelDefaults not enabled" \
                "Kubelet will not refuse to start if unsafe kernel defaults are detected" \
                "Set 'protectKernelDefaults: true' in /var/lib/kubelet/config.yaml"
        fi
    fi

    # Kubelet kubeconfig
    check_file "/etc/kubernetes/kubelet.conf" critical "Kubelet authentication kubeconfig"

    # Kubelet client cert
    if [ -f /var/lib/kubelet/pki/kubelet-client-current.pem ]; then
        print_ok "Kubelet current client certificate present"
        local exp
        exp=$(openssl x509 -in /var/lib/kubelet/pki/kubelet-client-current.pem -noout -enddate 2>/dev/null | cut -d= -f2)
        if [ -n "${exp:-}" ]; then
            local exp_epoch now_epoch days
            exp_epoch=$(date -d "$exp" +%s 2>/dev/null || echo 0)
            now_epoch=$(date +%s)
            days=$(( (exp_epoch - now_epoch) / 86400 ))
            if [ "$days" -lt 0 ]; then
                print_fail "Kubelet client certificate EXPIRED" \
                    "Expired $((-days)) days ago — node will fail authentication" \
                    "kubeadm certs renew all && systemctl restart kubelet"
            elif [ "$days" -lt 30 ]; then
                print_warn "Kubelet client certificate expires in $days days" \
                    "Rotation is enabled — verify renewal is happening" \
                    "Check kubelet logs for cert rotation errors"
            else
                print_ok "Kubelet client certificate valid for $days days"
            fi
        fi
    else
        print_fail "Kubelet client certificate missing" \
            "/var/lib/kubelet/pki/kubelet-client-current.pem not found — kubelet cannot authenticate to apiserver" \
            "Re-run: kubeadm init phase kubeconfig kubelet"
    fi

    # systemd unit + drop-ins
    check_file "/etc/systemd/system/kubelet.service" warning "Kubelet systemd unit file"
    if [ -d /etc/systemd/system/kubelet.service.d ]; then
        local n
        n=$(ls /etc/systemd/system/kubelet.service.d/*.conf 2>/dev/null | wc -l)
        print_ok "Kubelet drop-in files present ($n file(s))"
    else
        print_warn "Kubelet drop-in directory missing" \
            "/etc/systemd/system/kubelet.service.d/ not found" \
            "Reinstall kubeadm/kubelet or restore drop-in files"
    fi
}

# =============================================================================
#  SECTION 4 — CONTROL-PLANE STATIC POD MANIFESTS (MASTER ONLY)
# =============================================================================

section_controlplane_manifests() {
    print_section "4. CONTROL-PLANE STATIC POD MANIFESTS"

    if [ "$IS_MASTER" != "true" ]; then
        print_skip "Not a control-plane node — skipping static manifest audit"
        return
    fi

    check_file "/etc/kubernetes/manifests/kube-apiserver.yaml" critical "kube-apiserver static pod manifest"
    check_file "/etc/kubernetes/manifests/kube-controller-manager.yaml" critical "kube-controller-manager static pod manifest"
    check_file "/etc/kubernetes/manifests/kube-scheduler.yaml" critical "kube-scheduler static pod manifest"
    check_file "/etc/kubernetes/manifests/etcd.yaml" critical "etcd static pod manifest"

    # ── kube-apiserver checks ────────────────────────────────────────────────
    local api=/etc/kubernetes/manifests/kube-apiserver.yaml
    if [ -f "$api" ]; then
        check_grep "$api" 'authorization-mode' 'Node,RBAC' \
            "kube-apiserver authorization-mode includes Node,RBAC" critical \
            "Add '--authorization-mode=Node,RBAC' to command args"

        if grep -A50 'command:' "$api" 2>/dev/null | grep -q 'enable-admission-plugins' \
           && grep -A50 'command:' "$api" 2>/dev/null | grep -qE 'NodeRestriction'; then
            print_ok "kube-apiserver admission plugin NodeRestriction enabled"
        else
            print_fail "kube-apiserver NodeRestriction admission plugin missing" \
                "Without NodeRestriction, kubelets can modify arbitrary pods/nodes — privilege escalation risk" \
                "Add '--enable-admission-plugins=NodeRestriction,...' to kube-apiserver command"
        fi

        if grep -q 'audit-log-path' "$api" 2>/dev/null; then
            print_ok "kube-apiserver audit logging enabled"
        else
            print_warn "kube-apiserver audit logging not configured" \
                "No audit trail for API operations — weak for forensics/compliance" \
                "Add '--audit-log-path' and '--audit-policy-file' to kube-apiserver"
        fi

        if grep -q 'insecure-port=0' "$api" 2>/dev/null; then
            print_ok "kube-apiserver insecure port disabled (--insecure-port=0)"
        else
            # In recent versions flag is removed; ensure it's not set to non-zero
            if grep -qE -- '--insecure-port=[1-9]' "$api" 2>/dev/null; then
                print_fail "kube-apiserver insecure port is enabled" \
                    "--insecure-port is set to a non-zero value, exposing an unauthenticated endpoint" \
                    "Remove the flag or set '--insecure-port=0'"
            else
                print_ok "kube-apiserver insecure port not enabled"
            fi
        fi

        if grep -q 'profiling=false' "$api" 2>/dev/null; then
            print_ok "kube-apiserver profiling disabled"
        else
            print_warn "kube-apiserver profiling is not explicitly disabled" \
                "/debug/pprof endpoint could be reachable" \
                "Add '--profiling=false' to kube-apiserver"
        fi

        if grep -q 'kubelet-client-certificate' "$api" 2>/dev/null \
           && grep -q 'kubelet-client-key' "$api" 2>/dev/null; then
            print_ok "kube-apiserver → kubelet client cert configured"
        else
            print_fail "kube-apiserver cannot authenticate to kubelet" \
                "Missing --kubelet-client-certificate/--kubelet-client-key" \
                "Add both flags pointing to apiserver-kubelet-client.{crt,key}"
        fi
    fi

    # ── kube-controller-manager ─────────────────────────────────────────────
    local cm=/etc/kubernetes/manifests/kube-controller-manager.yaml
    if [ -f "$cm" ]; then
        if grep -q 'use-service-account-credentials=true' "$cm" 2>/dev/null; then
            print_ok "kube-controller-manager uses per-SA credentials"
        else
            print_warn "kube-controller-manager not using per-SA credentials" \
                "--use-service-account-credentials=true is recommended for RBAC separation" \
                "Add '--use-service-account-credentials=true'"
        fi
    fi

    # ── etcd ────────────────────────────────────────────────────────────────
    local etcd=/etc/kubernetes/manifests/etcd.yaml
    if [ -f "$etcd" ]; then
        if grep -q 'cert-file' "$etcd" 2>/dev/null \
           && grep -q 'key-file' "$etcd" 2>/dev/null \
           && grep -q 'trusted-ca-file' "$etcd" 2>/dev/null; then
            print_ok "etcd TLS configuration present (cert/key/trusted-ca)"
        else
            print_fail "etcd TLS configuration incomplete" \
                "etcd is not fully configured with --cert-file/--key-file/--trusted-ca-file" \
                "Restore the TLS flags in /etc/kubernetes/manifests/etcd.yaml"
        fi

        if grep -q 'client-cert-auth' "$etcd" 2>/dev/null \
           && grep -q 'client-cert-auth=true\|--client-cert-auth' "$etcd" 2>/dev/null; then
            print_ok "etcd client-cert-auth enabled"
        else
            print_warn "etcd client-cert-auth not explicitly enabled" \
                "Clients without certs may reach etcd" \
                "Add '--client-cert-auth=true'"
        fi

        # etcd dataDir
        check_grep "$etcd" 'data-dir' '/var/lib/etcd' \
            "etcd data-dir set to /var/lib/etcd" warning
    fi
}

# =============================================================================
#  SECTION 5 — PKI / CERTIFICATES (MASTER ONLY)
# =============================================================================

section_pki() {
    print_section "5. PKI / CERTIFICATE INVENTORY"

    if [ "$IS_MASTER" != "true" ]; then
        print_skip "Not a control-plane node — skipping PKI audit"
        return
    fi

    local pki=/etc/kubernetes/pki

    # Existence of critical certs
    for f in \
        "$pki/ca.crt" "$pki/ca.key" \
        "$pki/apiserver.crt" "$pki/apiserver.key" \
        "$pki/apiserver-kubelet-client.crt" \
        "$pki/front-proxy-ca.crt" \
        "$pki/sa.key" "$pki/sa.pub" \
        "$pki/etcd/ca.crt" "$pki/etcd/ca.key" \
        "$pki/etcd/server.crt" "$pki/etcd/server.key" \
        "$pki/etcd/peer.crt" "$pki/etcd/peer.key" \
        "$pki/etcd/healthcheck-client.crt"
    do
        [ -f "$f" ] || print_fail "Missing certificate file: $f" \
            "Required for cluster PKI trust chain" \
            "Restore from backup or re-run 'kubeadm init phase certs all'"
    done

    # Excessive permissions on private keys
    for key in "$pki/ca.key" "$pki/sa.key" "$pki/etcd/ca.key" \
               "$pki/etcd/server.key" "$pki/etcd/peer.key" \
               "$pki/apiserver.key"; do
        [ -f "$key" ] && check_perm "$key" "600"
    done

    # kubeconfig permissions
    for kc in /etc/kubernetes/admin.conf /etc/kubernetes/kubelet.conf \
              /etc/kubernetes/controller-manager.conf /etc/kubernetes/scheduler.conf; do
        [ -f "$kc" ] && check_perm "$kc" "600"
    done

    # Expiration via kubeadm if available
    if command -v kubeadm >/dev/null 2>&1; then
        local output
        output=$(kubeadm certs check-expiration 2>/dev/null || true)
        if [ -n "$output" ]; then
            # Parse lines with remaining days
            while IFS= read -r line; do
                local name days
                name=$(awk '{print $1}' <<<"$line")
                days=$(grep -oE '[0-9]+d' <<<"$line" | head -1 | tr -d 'd')
                [ -z "${days:-}" ] && continue
                if [ "$days" -lt 0 ]; then
                    print_fail "Certificate EXPIRED: $name" \
                        "Expired $((-days)) days ago — cluster may be unable to authenticate" \
                        "kubeadm certs renew all && restart control-plane pods"
                elif [ "$days" -lt 7 ]; then
                    print_fail "Certificate expiring VERY soon: $name (${days}d)" \
                        "Immediate action required" \
                        "kubeadm certs renew all"
                elif [ "$days" -lt 30 ]; then
                    print_warn "Certificate expiring soon: $name (${days}d)" \
                        "Renew during next maintenance window" \
                        "kubeadm certs renew $name"
                else
                    print_ok "Certificate valid: $name (${days}d remaining)"
                fi
            done < <(grep -E '^[a-z].*[0-9]+d' <<<"$output")
        fi
    else
        print_skip "kubeadm not available — cannot check certificate expiration"
    fi
}

# =============================================================================
#  SECTION 6 — KUBECONFIG FILES
# =============================================================================

section_kubeconfig() {
    print_section "6. KUBECONFIG FILES"

    check_file "/etc/kubernetes/admin.conf" critical "Admin kubeconfig: /etc/kubernetes/admin.conf"
    check_perm "/etc/kubernetes/admin.conf" "600"

    if [ -f "$HOME/.kube/config" ]; then
        print_ok "User kubeconfig present: $HOME/.kube/config"
        check_perm "$HOME/.kube/config" "600"
    else
        print_warn "User kubeconfig missing: $HOME/.kube/config" \
            "kubectl may not work for the current user" \
            "mkdir -p $HOME/.kube && cp /etc/kubernetes/admin.conf $HOME/.kube/config"
    fi

    # Check admin.conf points to reachable apiserver
    if [ -f /etc/kubernetes/admin.conf ]; then
        local server
        server=$(grep -E 'server:' /etc/kubernetes/admin.conf | head -1 | awk '{print $2}')
        if [ -n "${server:-}" ]; then
            print_ok "Admin kubeconfig server endpoint: $server"
            if curl -sk --max-time 5 "${server}/healthz" 2>/dev/null | grep -q '^ok$'; then
                print_ok "API server reachable from admin kubeconfig endpoint"
            else
                print_fail "API server NOT reachable at $server" \
                    "Control plane may be down or firewall blocked" \
                    "Check kube-apiserver static pod and firewall on port 6443"
            fi
        fi
    fi
}

# =============================================================================
#  SECTION 7 — etcd HEALTH (MASTER ONLY)
# =============================================================================

section_etcd() {
    print_section "7. etcd HEALTH"

    if [ "$IS_MASTER" != "true" ]; then
        print_skip "Not a control-plane node — skipping etcd audit"
        return
    fi

    check_dir_perm "/var/lib/etcd" "700"

    if command -v etcdctl >/dev/null 2>&1 || [ -x /usr/local/bin/etcdctl ]; then
        local etcdctl_bin
        etcdctl_bin=$(command -v etcdctl || echo /usr/local/bin/etcdctl)
        local ep="https://127.0.0.1:2379"
        local cacert=/etc/kubernetes/pki/etcd/ca.crt
        local cert=/etc/kubernetes/pki/etcd/server.crt
        local key=/etc/kubernetes/pki/etcd/server.key

        if [ -f "$cacert" ] && [ -f "$cert" ] && [ -f "$key" ]; then
            if ETCDCTL_API=3 "$etcdctl_bin" --endpoints="$ep" --cacert="$cacert" --cert="$cert" --key="$key" endpoint health >/dev/null 2>&1; then
                print_ok "etcd endpoint healthy"
            else
                print_fail "etcd endpoint UNHEALTHY" \
                    "etcdctl endpoint health returned failure — cluster state may be at risk" \
                    "journalctl -u kubelet; crictl ps | grep etcd; restore from snapshot if needed"
            fi

            # DB size
            local dbsize
            dbsize=$(ETCDCTL_API=3 "$etcdctl_bin" --endpoints="$ep" --cacert="$cacert" --cert="$cert" --key="$key" endpoint status -w json 2>/dev/null \
                | grep -oE '"dbSize":[0-9]+' | head -1 | cut -d: -f2)
            if [ -n "${dbsize:-}" ] && [ "$dbsize" -gt 0 ]; then
                local mb=$(( dbsize / 1024 / 1024 ))
                if [ "$mb" -gt 4096 ]; then
                    print_fail "etcd DB size too large: ${mb}MB" \
                        "Quota risk and severe performance degradation" \
                        "Compact + defrag etcd, and reduce object churn"
                elif [ "$mb" -gt 2048 ]; then
                    print_warn "etcd DB size elevated: ${mb}MB" \
                        "Compaction/defrag recommended" \
                        "ETCDCTL_API=3 etcdctl compact <rev> && defrag"
                else
                    print_ok "etcd DB size OK (${mb}MB)"
                fi
            fi

            # Leader check
            local leader
            leader=$(ETCDCTL_API=3 "$etcdctl_bin" --endpoints="$ep" --cacert="$cacert" --cert="$cert" --key="$key" endpoint status -w json 2>/dev/null \
                | grep -oE '"leader":[0-9]+' | head -1 | cut -d: -f2)
            if [ -n "${leader:-}" ] && [ "$leader" != "0" ]; then
                print_ok "etcd leader elected (leader-id=$leader)"
            else
                print_fail "etcd has NO leader" \
                    "Raft quorum likely lost — cluster is read-only/unhealthy" \
                    "Verify etcd members are running and network is healthy"
            fi
        else
            print_warn "etcd TLS certs missing — cannot query etcd health" \
                "Some etcd certificates are absent under /etc/kubernetes/pki/etcd" \
                "Restore PKI or re-init"
        fi
    else
        print_skip "etcdctl not installed — cannot query etcd health directly"
    fi
}

# =============================================================================
#  SECTION 8 — CNI / NETWORKING
# =============================================================================

section_network() {
    print_section "8. CNI / POD NETWORK"

    # CNI configuration directory
    if [ -d /etc/cni/net.d ]; then
        local n
        n=$(ls /etc/cni/net.d/*.conf* 2>/dev/null | wc -l)
        if [ "$n" -gt 0 ]; then
            print_ok "CNI configuration present ($n file(s) in /etc/cni/net.d/)"
            if [ "$n" -gt 1 ]; then
                print_warn "Multiple CNI configs detected ($n)" \
                    "More than one CNI plugin is active — behavior is undefined" \
                    "Keep only one conflist and remove the others"
            fi
        else
            print_fail "No CNI configuration found in /etc/cni/net.d/" \
                "Pods will remain in ContainerCreating without networking" \
                "Install a CNI (Calico, Cilium, Flannel) via kubectl apply"
        fi
    else
        print_fail "CNI configuration directory missing: /etc/cni/net.d" \
            "No CNI plugin directory present" \
            "Create /etc/cni/net.d and install a CNI plugin"
    fi

    # CNI binaries
    local missing_bins=()
    for bin in bridge host-local loopback portmap; do
        [ -x "/opt/cni/bin/$bin" ] || missing_bins+=("$bin")
    done
    if [ ${#missing_bins[@]} -eq 0 ]; then
        print_ok "Standard CNI binaries present in /opt/cni/bin"
    else
        print_warn "Missing CNI binaries: ${missing_bins[*]}" \
            "Base networking plugins required by many CNIs" \
            "Install cni-plugins tgz into /opt/cni/bin"
    fi

    # MTU (best-effort sanity)
    local mtu
    mtu=$(ip -o link show 2>/dev/null | awk -F'mtu ' '{print $2}' | awk '{print $1}' | sort -n | head -1)
    if [ -n "${mtu:-}" ] && [ "$mtu" -lt 1200 ]; then
        print_warn "Very small MTU detected on interface: $mtu" \
            "May cause pod-to-pod fragmentation issues" \
            "Align MTU with CNI overlay overhead (typically 1450 for VXLAN)"
    fi

    # kube-proxy on this node
    if systemctl list-unit-files 2>/dev/null | grep -q '^kube-proxy'; then
        check_service kube-proxy warning
    fi
}

# =============================================================================
#  SECTION 9 — LIVE CLUSTER HEALTH (via kubectl)
# =============================================================================

section_cluster() {
    print_section "9. LIVE CLUSTER HEALTH (kubectl)"

    if [ "$SKIP_KUBECTL" = "true" ]; then
        print_skip "kubectl checks skipped (--no-kubectl)"
        return
    fi

    if ! command -v kubectl >/dev/null 2>&1; then
        print_warn "kubectl not installed" \
            "Cannot query cluster live state" \
            "Install kubectl on this host"
        return
    fi

    if ! kubectl get --raw='/healthz' >/dev/null 2>&1; then
        print_fail "kubectl cannot reach API server" \
            "kubectl get --raw=/healthz failed — apiserver unreachable or kubeconfig invalid" \
            "Check /etc/kubernetes/admin.conf, apiserver pod, and firewall"
        return
    fi
    print_ok "kubectl can reach API server"

    # readyz
    if kubectl get --raw='/readyz' 2>/dev/null | grep -q '^ok$'; then
        print_ok "API server /readyz reports ok"
    else
        print_fail "API server /readyz is not ok" \
            "One or more control-plane components are unhealthy" \
            "kubectl get --raw='/readyz?verbose' | tail -30"
    fi

    # Nodes
    local not_ready
    not_ready=$(kubectl get nodes --no-headers 2>/dev/null | awk '$2!="Ready"' | wc -l)
    local total_nodes
    total_nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
    if [ "$total_nodes" -eq 0 ]; then
        print_warn "No nodes registered in cluster" "kubectl get nodes returned empty" "Verify join token or node bootstrap"
    elif [ "$not_ready" -gt 0 ]; then
        print_fail "Nodes NotReady: $not_ready of $total_nodes" \
            "kubelet on those nodes is not reporting Ready" \
            "kubectl describe node <name> and journalctl -u kubelet on that node"
    else
        print_ok "All $total_nodes node(s) report Ready"
    fi

    # Node pressures
    local pressured
    pressured=$(kubectl get nodes -o json 2>/dev/null | \
        grep -oE '"type":"(MemoryPressure|DiskPressure|PIDPressure)","status":"True"' | wc -l)
    if [ "$pressured" -gt 0 ]; then
        print_fail "Node pressure conditions TRUE ($pressured)" \
            "Node is under MemoryPressure, DiskPressure or PIDPressure" \
            "Inspect: kubectl describe node <name> | grep -A6 Conditions"
    else
        print_ok "No node pressure conditions detected"
    fi

    # Control-plane pods
    local cp_unhealthy
    cp_unhealthy=$(kubectl get pods -n kube-system --no-headers 2>/dev/null \
        | grep -E 'etcd|kube-apiserver|kube-controller-manager|kube-scheduler' \
        | awk '$3!="Running"' | wc -l)
    if [ "$cp_unhealthy" -gt 0 ]; then
        print_fail "Unhealthy control-plane pods: $cp_unhealthy" \
            "One or more static control-plane pods are not Running" \
            "kubectl get pods -n kube-system; crictl ps | grep -E 'apiserver|etcd|scheduler|controller'"
    else
        print_ok "All control-plane pods Running"
    fi

    # CoreDNS
    local dns_total dns_ready
    dns_total=$(kubectl get pods -n kube-system -l k8s-app=kube-dns --no-headers 2>/dev/null | wc -l)
    dns_ready=$(kubectl get pods -n kube-system -l k8s-app=kube-dns --no-headers 2>/dev/null | grep -c 'Running')
    if [ "$dns_total" -eq 0 ]; then
        print_fail "CoreDNS Deployment not found" \
            "Cluster DNS unavailable — in-cluster service discovery broken" \
            "Reinstall CoreDNS via kubeadm or Helm"
    elif [ "$dns_ready" -lt "$dns_total" ]; then
        print_fail "CoreDNS partially degraded ($dns_ready/$dns_total Running)" \
            "Some DNS pods are not Running" \
            "kubectl -n kube-system logs <coredns-pod>"
    else
        print_ok "CoreDNS healthy ($dns_ready/$dns_total)"
    fi

    # kube-proxy
    local kp_ready kp_desired
    kp_ready=$(kubectl get ds -n kube-system kube-proxy -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)
    kp_desired=$(kubectl get ds -n kube-system kube-proxy -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo 0)
    if [ "${kp_desired:-0}" -gt 0 ] && [ "$kp_ready" = "$kp_desired" ]; then
        print_ok "kube-proxy DaemonSet ready ($kp_ready/$kp_desired)"
    else
        print_warn "kube-proxy DaemonSet not fully ready ($kp_ready/$kp_desired)" \
            "Missing kube-proxy on some nodes breaks Service routing on them" \
            "kubectl -n kube-system get pods -l k8s-app=kube-proxy -o wide"
    fi

    # CNI DaemonSet (pick any known name)
    local cni_ds=""
    for candidate in calico-node cilium kube-flannel-ds antrea-agent weave-net; do
        if kubectl get ds -n kube-system "$candidate" >/dev/null 2>&1; then
            cni_ds="$candidate"; break
        fi
    done
    if [ -n "$cni_ds" ]; then
        local cni_ready cni_desired
        cni_ready=$(kubectl get ds -n kube-system "$cni_ds" -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)
        cni_desired=$(kubectl get ds -n kube-system "$cni_ds" -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo 0)
        if [ "${cni_desired:-0}" -gt 0 ] && [ "$cni_ready" = "$cni_desired" ]; then
            print_ok "CNI DaemonSet ready: $cni_ds ($cni_ready/$cni_desired)"
        else
            print_fail "CNI DaemonSet not fully ready: $cni_ds ($cni_ready/$cni_desired)" \
                "Pods on nodes without CNI will not get networking" \
                "kubectl -n kube-system logs ds/$cni_ds"
        fi
    else
        print_fail "No recognized CNI DaemonSet found" \
            "Calico, Cilium, Flannel, Antrea, and Weave are all absent" \
            "Install a CNI plugin"
    fi

    # Unhealthy pods (whole cluster)
    local unhealthy
    unhealthy=$(kubectl get pods -A --no-headers 2>/dev/null | awk '$4!="Running" && $4!="Completed"' | wc -l)
    if [ "$unhealthy" -eq 0 ]; then
        print_ok "All pods across cluster are Running or Completed"
    elif [ "$unhealthy" -le 5 ]; then
        print_warn "Unhealthy pods: $unhealthy" \
            "Small number of pods are in abnormal state" \
            "kubectl get pods -A | grep -vE 'Running|Completed'"
    else
        print_fail "Many unhealthy pods: $unhealthy" \
            "Significant cluster degradation" \
            "kubectl get pods -A | grep -vE 'Running|Completed' | head -20"
    fi

    # CrashLoopBackOff
    local crashloops
    crashloops=$(kubectl get pods -A --no-headers 2>/dev/null | grep -c 'CrashLoopBackOff' || true)
    if [ "$crashloops" -gt 0 ]; then
        print_warn "Pods in CrashLoopBackOff: $crashloops" \
            "Container is repeatedly crashing" \
            "kubectl logs <pod> --previous  and  kubectl describe pod <pod>"
    fi

    # Endpoints with no backing pod
    local empty_eps
    empty_eps=$(kubectl get endpointslices -A -o json 2>/dev/null | \
        grep -c '"endpoints":\[\]' || true)
    if [ "${empty_eps:-0}" -gt 0 ]; then
        print_warn "EndpointSlices with no ready backends: $empty_eps" \
            "Services with empty endpoints will refuse connections" \
            "kubectl get endpointslices -A and verify selector/readiness"
    fi

    # PVCs not Bound
    local unbound_pvc
    unbound_pvc=$(kubectl get pvc -A --no-headers 2>/dev/null | awk '$3!="Bound"' | wc -l)
    if [ "$unbound_pvc" -gt 0 ]; then
        print_warn "PVCs not Bound: $unbound_pvc" \
            "Storage claims waiting for provisioning" \
            "kubectl describe pvc <name> -n <ns>"
    else
        print_ok "All PVCs Bound"
    fi

    # Deployments under-replicated
    local bad_deploys
    bad_deploys=$(kubectl get deploy -A --no-headers 2>/dev/null | awk '$3!=$4' | wc -l)
    if [ "$bad_deploys" -gt 0 ]; then
        print_warn "Deployments under-replicated: $bad_deploys" \
            "Replicas not all Ready — rollout may be stuck" \
            "kubectl rollout status deploy/<name> -n <ns>"
    else
        print_ok "All Deployments fully ready"
    fi

    # High restart count
    local high_restarts
    high_restarts=$(kubectl get pods -A --no-headers 2>/dev/null | awk '$5+0 > 5' | wc -l)
    if [ "${high_restarts:-0}" -gt 0 ]; then
        print_warn "Pods with >5 restarts: $high_restarts" \
            "Frequent restarts indicate instability" \
            "kubectl get pods -A | awk '\$5>5'"
    fi

    # Advisory webhooks with failurePolicy=Fail (can block API)
    local fail_webhooks
    fail_webhooks=$(kubectl get validatingwebhookconfigurations -o json 2>/dev/null | \
        grep -c '"failurePolicy":"Fail"' || true)
    if [ "${fail_webhooks:-0}" -gt 0 ]; then
        print_warn "Admission webhooks with failurePolicy=Fail: $fail_webhooks" \
            "If any such webhook backend is unreachable, all matching admissions will be blocked" \
            "kubectl get validatingwebhookconfigurations"
    fi

    # API latency simple measurement
    local t0 t1 ms
    t0=$(date +%s%N)
    kubectl get nodes >/dev/null 2>&1
    t1=$(date +%s%N)
    ms=$(( (t1 - t0) / 1000000 ))
    if [ "$ms" -gt 3000 ]; then
        print_fail "API server latency very high: ${ms}ms" \
            "kubectl get nodes took over 3s — apiserver or etcd overloaded" \
            "Check etcd DB size, disk IO, and apiserver CPU"
    elif [ "$ms" -gt 1500 ]; then
        print_warn "API server latency elevated: ${ms}ms" \
            "kubectl get nodes over 1.5s" \
            "Investigate etcd performance and apiserver load"
    else
        print_ok "API server latency ${ms}ms"
    fi
}

# =============================================================================
#  SECTION 10 — RBAC & SERVICE ACCOUNTS (basic)
# =============================================================================

section_rbac() {
    print_section "10. RBAC EXPOSURE SNAPSHOT"

    if ! kubectl_available; then
        print_skip "Cluster not reachable — skipping RBAC audit"
        return
    fi

    # Count cluster-admin subjects
    local admins
    admins=$(kubectl get clusterrolebindings -o json 2>/dev/null | \
        grep -c '"name": *"cluster-admin"' || true)
    if [ "${admins:-0}" -gt 0 ]; then
        print_ok "cluster-admin bindings exist ($admins) — inspect manually for scope"
    fi

    # Check for default SA with elevated bindings
    if kubectl get clusterrolebinding -o json 2>/dev/null | \
        grep -A3 'system:serviceaccount:default' | grep -q 'cluster-admin'; then
        print_fail "default ServiceAccount bound to cluster-admin" \
            "Any pod in a 'default' SA can control the whole cluster" \
            "Remove this binding: kubectl delete clusterrolebinding <name>"
    else
        print_ok "default ServiceAccount is not cluster-admin"
    fi

    # Pods using hostPath volumes (surface, not block)
    local hp
    hp=$(kubectl get pods -A -o json 2>/dev/null | \
        grep -c '"hostPath"' || true)
    if [ "${hp:-0}" -gt 0 ]; then
        print_warn "Pods mounting hostPath volumes: $hp" \
            "hostPath can break container isolation if misused" \
            "Review: kubectl get pods -A -o json | grep hostPath"
    fi
}

# =============================================================================
#  FINAL SUMMARY
# =============================================================================

print_summary() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}▶ SUMMARY${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  Total checks : ${BOLD}${TOTAL}${NC}"
    echo -e "  ${GREEN}✅ PASS      : ${PASS}${NC}"
    echo -e "  ${YELLOW}⚠️  WARN      : ${WARN}${NC}"
    echo -e "  ${RED}❌ FAIL      : ${FAIL}${NC}"
    echo -e "  ${CYAN}ℹ️  SKIP      : ${SKIP}${NC}"
    echo ""

    if [ ${#CRITICALS[@]} -gt 0 ]; then
        echo -e "${RED}${BOLD}CRITICAL ISSUES:${NC}"
        for i in "${CRITICALS[@]}"; do
            echo -e "  ${RED}❌${NC} $i"
        done
        echo ""
    fi

    if [ ${#WARNINGS[@]} -gt 0 ]; then
        echo -e "${YELLOW}${BOLD}WARNINGS:${NC}"
        for w in "${WARNINGS[@]}"; do
            echo -e "  ${YELLOW}⚠️${NC}  $w"
        done
        echo ""
    fi

    if [ "$FAIL" -eq 0 ] && [ "$WARN" -eq 0 ]; then
        echo -e "${GREEN}${BOLD}  ██████╗ ██╗     ██╗   ██╗███████╗██████╗ ${NC}"
        echo -e "${GREEN}${BOLD}  ██╔══██╗██║     ██║   ██║██╔════╝██╔══██╗${NC}"
        echo -e "${GREEN}${BOLD}  ██████╔╝██║     ██║   ██║█████╗  ██████╔╝${NC}"
        echo -e "${GREEN}${BOLD}  ██╔═══╝ ██║     ██║   ██║██╔══╝  ██╔══██╗${NC}"
        echo -e "${GREEN}${BOLD}  ██║     ███████╗╚██████╔╝███████╗██║  ██║${NC}"
        echo -e "${GREEN}${BOLD}  ╚═╝     ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝${NC}"
        echo -e "${GREEN}${BOLD}  Cluster looks healthy.${NC}"
    elif [ "$FAIL" -eq 0 ]; then
        echo -e "${YELLOW}${BOLD}  Cluster is functional but has $WARN warning(s). Review above.${NC}"
    else
        echo -e "${RED}${BOLD}  Cluster has $FAIL critical issue(s). Address FAIL items immediately.${NC}"
    fi
}

# =============================================================================
#  ENTRY POINT
# =============================================================================

main() {
    print_banner

    section_os
    section_runtime
    section_kubelet
    section_controlplane_manifests
    section_pki
    section_kubeconfig
    section_etcd
    section_network
    section_cluster
    section_rbac

    print_summary

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                                      ║${NC}"
    echo -e "${CYAN}║                  ${BOLD}Visit more at https://github.com/MojSep${NC}${CYAN}                  ║${NC}"
    echo -e "${CYAN}║                                                                      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Exit code: 0 healthy, 1 warnings, 2 criticals
    if [ "$FAIL" -gt 0 ]; then exit 2; fi
    if [ "$WARN" -gt 0 ]; then exit 1; fi
    exit 0
}

main "$@"
