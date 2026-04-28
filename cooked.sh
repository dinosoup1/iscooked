#!/usr/bin/env bash
# iscooked.com — Am I Cooked? Local AI Security Scanner
# https://iscooked.com | MIT License
#
# Scans your local AI setup for security and privacy risks.
# Runs locally. Sends nothing anywhere. Ever.

set -euo pipefail

VERSION="1.0.0"

# ─── Colors & Formatting ───────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

COOKED="${RED}${BOLD}🔥 COOKED${RESET}"
WARMING="${YELLOW}⚠  WARMING UP${RESET}"
SAFE="${GREEN}✅ SAFE${RESET}"

# ─── State ──────────────────────────────────────────────────────────────────────

TOTAL_CHECKS=0
COOKED_COUNT=0
WARMING_COUNT=0
SAFE_COUNT=0
SCORE=0

# ─── Helpers ────────────────────────────────────────────────────────────────────

banner() {
    echo ""
    echo -e "${RED}${BOLD}"
    cat << 'BANNER'
                    __            __       __
  _________  ____  / /_____  ____/ /  ____/ /_
 / ___/ __ \/ __ \/ //_/ _ \/ __  /  / ___/ __ \
/ /__/ /_/ / /_/ / ,< /  __/ /_/ /_ (__  ) / / /
\___/\____/\____/_/|_|\___/\__,_/(_)____/_/ /_/

BANNER
    echo -e "${RESET}"
    echo -e "${DIM}  Am I Cooked? — Local AI Security Scanner v${VERSION}${RESET}"
    echo -e "${DIM}  https://iscooked.com${RESET}"
    echo ""
    echo -e "  ${CYAN}${BOLD}Scanning your setup...${RESET}"
    echo ""
    echo -e "${DIM}──────────────────────────────────────────────────────────────${RESET}"
}

section() {
    echo ""
    echo -e "  ${MAGENTA}${BOLD}[$1]${RESET} ${WHITE}${BOLD}$2${RESET}"
    echo -e "  ${DIM}$(printf '%.0s─' {1..56})${RESET}"
}

result_cooked() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    COOKED_COUNT=$((COOKED_COUNT + 1))
    SCORE=$((SCORE + 10))
    echo -e "  ${COOKED}  $1"
}

result_warming() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    WARMING_COUNT=$((WARMING_COUNT + 1))
    SCORE=$((SCORE + 4))
    echo -e "  ${WARMING}  $1"
}

result_safe() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    SAFE_COUNT=$((SAFE_COUNT + 1))
    echo -e "  ${SAFE}  $1"
}

result_skip() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    echo -e "  ${DIM}⏭  SKIP${RESET}  $1"
}

command_exists() {
    command -v "$1" &>/dev/null
}

# ─── Checks ─────────────────────────────────────────────────────────────────────

check_network_exposure() {
    section "01" "Network Exposure"

    local ai_ports=(
        "11434:Ollama"
        "8080:LM Studio / text-gen-webui"
        "5000:text-gen-webui (alt)"
        "7860:Gradio / Stable Diffusion WebUI"
        "8188:ComfyUI"
        "3000:Open WebUI"
        "1234:LM Studio (alt)"
        "8000:vLLM / FastChat"
        "5001:LocalAI"
        "9090:Prometheus (AI metrics)"
    )

    for entry in "${ai_ports[@]}"; do
        local port="${entry%%:*}"
        local name="${entry#*:}"

        # Check if anything is listening on this port
        local listen_line=""
        if command_exists ss; then
            listen_line=$(ss -tlnp 2>/dev/null | grep -E "[:\.]${port}([[:space:]]|$)" || true)
        elif command_exists netstat; then
            listen_line=$(netstat -tlnp 2>/dev/null | grep -E "[:\.]${port}([[:space:]]|$)" || true)
        fi

        if [[ -n "$listen_line" ]]; then
            # Check if bound to 0.0.0.0 or :: (all interfaces)
            if echo "$listen_line" | grep -qE '(0\.0\.0\.0|\*|::):'"${port}"; then
                result_cooked "${name} (port ${port}) is listening on ALL interfaces"
            else
                result_safe "${name} (port ${port}) is bound to localhost only"
            fi
        fi
    done

    # Check if any of the above were found at all
    local found_any=false
    for entry in "${ai_ports[@]}"; do
        local port="${entry%%:*}"
        local listen_line=""
        if command_exists ss; then
            listen_line=$(ss -tlnp 2>/dev/null | grep -E "[:\.]${port}([[:space:]]|$)" || true)
        elif command_exists netstat; then
            listen_line=$(netstat -tlnp 2>/dev/null | grep -E "[:\.]${port}([[:space:]]|$)" || true)
        fi
        if [[ -n "$listen_line" ]]; then
            found_any=true
            break
        fi
    done

    if [[ "$found_any" == "false" ]]; then
        result_safe "No common AI service ports detected as listening"
    fi
}

check_api_auth() {
    section "02" "API Authentication"

    # Check Ollama
    if command_exists curl; then
        # Ollama
        local ollama_resp
        ollama_resp=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 http://127.0.0.1:11434/ 2>/dev/null) || ollama_resp="000"
        if [[ "$ollama_resp" == "200" ]]; then
            # Check if OLLAMA_ORIGINS or any auth is set
            local ollama_env
            ollama_env=$(env | grep -i "OLLAMA" || true)
            if echo "$ollama_env" | grep -qi "OLLAMA_AUTH\|OLLAMA_API_KEY"; then
                result_safe "Ollama API is responding with auth configured"
            else
                result_warming "Ollama API is responding without authentication"
            fi
        elif [[ "$ollama_resp" != "000" ]]; then
            result_safe "Ollama API returned ${ollama_resp} (not open)"
        fi

        # LM Studio
        local lms_resp
        lms_resp=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 http://127.0.0.1:1234/v1/models 2>/dev/null) || lms_resp="000"
        if [[ "$lms_resp" == "200" ]]; then
            result_warming "LM Studio API is responding without authentication"
        fi

        # Open WebUI
        local webui_resp
        webui_resp=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 http://127.0.0.1:3000/ 2>/dev/null) || webui_resp="000"
        if [[ "$webui_resp" == "200" ]]; then
            result_warming "Open WebUI is accessible without checking for auth"
        fi
    else
        result_skip "curl not found, skipping API auth checks"
    fi
}

check_model_permissions() {
    section "03" "Model File Permissions"

    local model_dirs=(
        "$HOME/.ollama/models"
        "$HOME/.cache/lm-studio/models"
        "$HOME/.cache/huggingface/hub"
        "$HOME/models"
        "$HOME/.local/share/nomic.ai"
        "/usr/share/ollama/.ollama/models"
    )

    local found_models=false

    for dir in "${model_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            found_models=true
            # Check if world-readable
            local world_readable
            world_readable=$(find "$dir" -maxdepth 1 -type f -perm -o+r 2>/dev/null | head -5)
            if [[ -n "$world_readable" ]]; then
                result_warming "Model directory ${dir} is world-readable"
            else
                result_safe "Model directory ${dir} has restrictive permissions"
            fi

            # Check if world-writable
            local world_writable
            world_writable=$(find "$dir" -maxdepth 2 -perm -o+w 2>/dev/null | head -5)
            if [[ -n "$world_writable" ]]; then
                result_cooked "Files in ${dir} are world-writable!"
            fi
        fi
    done

    if [[ "$found_models" == "false" ]]; then
        result_skip "No common model directories found"
    fi
}

check_docker_risks() {
    section "04" "Docker / Container Risks"

    if ! command_exists docker; then
        result_skip "Docker not installed, skipping container checks"
        return
    fi

    # Check if docker daemon is reachable
    if ! docker info &>/dev/null; then
        result_skip "Docker daemon not reachable (not running or no permissions)"
        return
    fi

    local ai_containers
    ai_containers=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | grep -iE 'ollama|llama|text-gen|webui|comfy|vllm|localai|stable|diffusion|lmstudio|open-webui|litellm' || true)

    if [[ -z "$ai_containers" ]]; then
        result_skip "No AI-related containers running"
        return
    fi

    while IFS= read -r container_line; do
        local cname
        cname=$(echo "$container_line" | awk '{print $1}')

        # Check if running as root
        local user
        user=$(docker inspect --format '{{.Config.User}}' "$cname" 2>/dev/null || echo "")
        if [[ -z "$user" || "$user" == "root" || "$user" == "0" ]]; then
            result_cooked "Container '${cname}' is running as root"
        else
            result_safe "Container '${cname}' is running as user '${user}'"
        fi

        # Check privileged mode
        local privileged
        privileged=$(docker inspect --format '{{.HostConfig.Privileged}}' "$cname" 2>/dev/null || echo "false")
        if [[ "$privileged" == "true" ]]; then
            result_cooked "Container '${cname}' is running in PRIVILEGED mode"
        fi

        # Check host network
        local network
        network=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$cname" 2>/dev/null || echo "")
        if [[ "$network" == "host" ]]; then
            result_warming "Container '${cname}' is using host networking"
        fi

        # Check mounted volumes for sensitive paths
        local mounts
        mounts=$(docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$cname" 2>/dev/null || echo "")
        if echo "$mounts" | grep -qE '(/etc|/root|/home/[^/]+$)'; then
            result_warming "Container '${cname}' has sensitive host paths mounted"
        fi

    done <<< "$ai_containers"
}

check_gpu_exposure() {
    section "05" "GPU Driver Exposure"

    # NVIDIA
    if command_exists nvidia-smi; then
        # Check if nvidia-persistenced or nv-hostengine is exposed
        if ss -tlnp 2>/dev/null | grep -iE "nvidia|nv-host" | grep -vi "nvidia-settings" | grep -q .; then
            result_warming "NVIDIA management service has network-exposed ports"
        else
            result_safe "NVIDIA GPU detected, no management ports exposed"
        fi

        # Check nvidia-smi device permissions
        if [[ -e /dev/nvidia0 ]]; then
            local nv_perms
            nv_perms=$(stat -c '%a' /dev/nvidia0 2>/dev/null || echo "000")
            if [[ "${nv_perms: -1}" -ge 6 ]]; then
                result_warming "/dev/nvidia0 is accessible to all users (mode ${nv_perms})"
            else
                result_safe "/dev/nvidia0 has restrictive permissions (mode ${nv_perms})"
            fi
        fi
    fi

    # AMD ROCm
    if [[ -d /dev/dri ]]; then
        local render_perms
        render_perms=$(stat -c '%a' /dev/dri/renderD128 2>/dev/null || echo "000")
        if [[ -e /dev/dri/renderD128 && "${render_perms: -1}" -ge 6 ]]; then
            result_warming "/dev/dri/renderD128 is world-accessible (mode ${render_perms})"
        fi
    fi

    if ! command_exists nvidia-smi && [[ ! -d /dev/dri ]]; then
        result_skip "No GPU devices detected"
    fi
}

check_telemetry() {
    section "06" "Telemetry / Phoning Home"

    local telemetry_domains=(
        "telemetry.ollama.ai"
        "telemetry.vllm.ai"
        "sentry.io"
        "segment.io"
        "amplitude.com"
        "mixpanel.com"
        "analytics.google.com"
        "stats.lmstudio.ai"
    )

    # Check active connections
    local active_conns=""
    if command_exists ss; then
        active_conns=$(ss -tnp 2>/dev/null || true)
    fi

    # Check if OLLAMA_NO_CLOUD or telemetry opt-outs are set
    if [[ -n "${OLLAMA_NO_CLOUD:-}" ]]; then
        result_safe "OLLAMA_NO_CLOUD is set"
    fi

    local do_not_track="${DO_NOT_TRACK:-}"
    if [[ "$do_not_track" == "1" ]]; then
        result_safe "DO_NOT_TRACK=1 is set (good!)"
    else
        result_warming "DO_NOT_TRACK is not set — some tools respect this env var"
    fi

    # Check /etc/hosts for blocked telemetry
    if [[ -f /etc/hosts ]]; then
        local blocked=0
        for domain in "${telemetry_domains[@]}"; do
            if grep -qE "^\\s*0\\.0\\.0\\.0\\s+${domain}$" /etc/hosts 2>/dev/null; then
                blocked=$((blocked + 1))
            fi
        done
        if [[ $blocked -gt 0 ]]; then
            result_safe "${blocked} telemetry domains blocked in /etc/hosts"
        fi
    fi

}

check_firewall() {
    section "07" "Firewall Status"

    local has_firewall=false

    # UFW
    if command_exists ufw; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null || echo "inactive")
        if echo "$ufw_status" | grep -qi "active"; then
            result_safe "UFW firewall is active"
            has_firewall=true
        else
            result_cooked "UFW is installed but INACTIVE"
        fi
    fi

    # firewalld
    if command_exists firewall-cmd; then
        if firewall-cmd --state &>/dev/null; then
            result_safe "firewalld is active"
            has_firewall=true
        else
            result_cooked "firewalld is installed but INACTIVE"
        fi
    fi

    # iptables — check if any rules exist
    if command_exists iptables; then
        local rule_count
        rule_count=$(iptables -L 2>/dev/null | grep -c -v -E "^Chain|^target|^$" || true)
        rule_count=$((rule_count + 0))
        if [[ "$rule_count" -gt 2 ]]; then
            result_safe "iptables has ${rule_count} rules configured"
            has_firewall=true
        elif [[ "$has_firewall" == "false" ]]; then
            result_warming "iptables has minimal/no rules"
        fi
    fi

    # nftables
    if command_exists nft; then
        local nft_rules
        nft_rules=$(nft list ruleset 2>/dev/null | wc -l || true)
        nft_rules=$((nft_rules + 0))
        if [[ "$nft_rules" -gt 5 ]]; then
            result_safe "nftables has rules configured"
            has_firewall=true
        fi
    fi

    if [[ "$has_firewall" == "false" ]]; then
        result_cooked "No active firewall detected!"
    fi
}

check_ssl_tls() {
    section "08" "SSL/TLS Configuration"

    local ai_ports=(11434 8080 5000 7860 8188 3000 1234 8000)
    local found_http=false

    for port in "${ai_ports[@]}"; do
        # Check if port is open and serving HTTP (not HTTPS)
        local listen_line=""
        if command_exists ss; then
            listen_line=$(ss -tlnp 2>/dev/null | grep ":${port} " || true)
        fi

        if [[ -n "$listen_line" ]]; then
            # Check if it's bound to non-localhost
            if echo "$listen_line" | grep -qE '(0\.0\.0\.0|\*|::):'"${port}"; then
                # Try to detect if HTTPS
                if command_exists curl; then
                    local http_code
                    http_code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 "http://127.0.0.1:${port}/" 2>/dev/null || echo "000")
                    if [[ "$http_code" != "000" && -n "$http_code" ]]; then
                        result_cooked "Port ${port} is exposed on all interfaces over plain HTTP"
                        found_http=true
                    fi
                else
                    result_warming "Port ${port} is exposed on all interfaces (cannot verify TLS without curl)"
                    found_http=true
                fi
            fi
        fi
    done

    if [[ "$found_http" == "false" ]]; then
        result_safe "No AI services exposed over plain HTTP on non-localhost"
    fi
}

check_processes() {
    section "09" "AI Process Enumeration"

    local ai_process_patterns="ollama|llama\.cpp|llama-server|text-generation|vllm|lmstudio|comfyui|stable-diffusion|koboldcpp|localai|whisper|faster-whisper|tabbyAPI"

    local ai_procs
    local my_pid=$$
    ai_procs=$(ps aux 2>/dev/null | grep -iE "$ai_process_patterns" | awk -v pid="$my_pid" '$2 != pid {print}' || true)

    if [[ -z "$ai_procs" ]]; then
        result_skip "No AI-related processes running"
        return
    fi

    while IFS= read -r proc_line; do
        local proc_user proc_cmd
        proc_user=$(echo "$proc_line" | awk '{print $1}')
        proc_cmd=$(echo "$proc_line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}' | head -c 60)

        if [[ "$proc_user" == "root" ]]; then
            result_cooked "AI process running as root: ${proc_cmd}"
        else
            result_safe "AI process running as '${proc_user}': ${proc_cmd}"
        fi
    done <<< "$ai_procs"
}

check_sensitive_files() {
    section "10" "Sensitive File Exposure"

    # Check .env files in common locations
    local env_files=()
    local search_dirs=(
        "$HOME"
        "$HOME/Projects"
        "$HOME/projects"
        "$HOME/code"
        "$HOME/dev"
        "/opt"
        "/srv"
    )

    local seen_files=()
    for dir in "${search_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r f; do
                # Resolve to absolute path and deduplicate
                local real_path
                real_path=$(realpath "$f" 2>/dev/null || echo "$f")
                local already_seen=false
                for seen in "${seen_files[@]+"${seen_files[@]}"}"; do
                    if [[ "$seen" == "$real_path" ]]; then
                        already_seen=true
                        break
                    fi
                done
                if [[ "$already_seen" == "false" ]]; then
                    seen_files+=("$real_path")
                    env_files+=("$f")
                fi
            done < <(find "$dir" -maxdepth 3 \( -name ".env" -o -name ".env.local" -o -name "*.env" \) 2>/dev/null | head -20)
        fi
    done

    local found_exposed_env=false
    for env_file in "${env_files[@]}"; do
        if [[ -f "$env_file" ]]; then
            local perms
            perms=$(stat -c '%a' "$env_file" 2>/dev/null || echo "000")
            if [[ "${perms: -1}" -ge 4 ]]; then
                # Check if it contains API keys
                if grep -qiE '(api_key|api_secret|token|password|secret)=' "$env_file" 2>/dev/null; then
                    result_cooked ".env file with API keys is world-readable: ${env_file} (mode ${perms})"
                    found_exposed_env=true
                fi
            fi
        fi
    done

    if [[ "$found_exposed_env" == "false" ]]; then
        result_safe "No world-readable .env files with API keys found"
    fi

    # Check if models directory is owned properly
    if [[ -d "$HOME/.ollama" ]]; then
        local ollama_owner
        ollama_owner=$(stat -c '%U' "$HOME/.ollama" 2>/dev/null || echo "unknown")
        if [[ "$ollama_owner" != "$(whoami)" && "$ollama_owner" != "ollama" ]]; then
            result_warming "~/.ollama is owned by '${ollama_owner}' instead of you"
        fi
    fi
}

check_history_logs() {
    section "11" "History & Logs Leakage"

    # Check shell history for API keys
    local history_files=(
        "$HOME/.bash_history"
        "$HOME/.zsh_history"
        "$HOME/.local/share/fish/fish_history"
    )

    for hist_file in "${history_files[@]}"; do
        if [[ -f "$hist_file" ]]; then
            local key_leaks
            key_leaks=$(grep -ciE '(sk-[a-zA-Z0-9]{20,}|api_key=|OPENAI_API_KEY|ANTHROPIC_API_KEY|HF_TOKEN)' "$hist_file" 2>/dev/null || echo "0")
            if [[ "$key_leaks" -gt 0 ]]; then
                result_cooked "Shell history contains ~${key_leaks} potential API key(s): $(basename "$hist_file")"
            else
                result_safe "No API keys found in $(basename "$hist_file")"
            fi

            # Check permissions on history file
            local hist_perms
            hist_perms=$(stat -c '%a' "$hist_file" 2>/dev/null || echo "000")
            if [[ "${hist_perms: -1}" -ge 4 ]]; then
                result_warming "$(basename "$hist_file") is world-readable (mode ${hist_perms})"
            fi
        fi
    done

    # Check common AI log locations
    local log_dirs=(
        "$HOME/.ollama/logs"
        "$HOME/.cache/lm-studio/logs"
        "/var/log/ollama"
    )

    for log_dir in "${log_dirs[@]}"; do
        if [[ -d "$log_dir" ]]; then
            local log_perms
            log_perms=$(stat -c '%a' "$log_dir" 2>/dev/null || echo "000")
            if [[ "${log_perms: -1}" -ge 4 ]]; then
                result_warming "AI log directory is world-readable: ${log_dir}"
            else
                result_safe "AI log directory has restrictive permissions: ${log_dir}"
            fi
        fi
    done
}

check_ollama_config() {
    section "12" "Ollama-Specific Checks"

    if ! command_exists ollama; then
        result_skip "Ollama not installed"
        return
    fi

    # Check OLLAMA_HOST
    local ollama_host="${OLLAMA_HOST:-}"
    if [[ -n "$ollama_host" ]]; then
        if echo "$ollama_host" | grep -qE '^0\.0\.0\.0|^::'; then
            result_cooked "OLLAMA_HOST is set to ${ollama_host} — exposed to network!"
        elif echo "$ollama_host" | grep -qE '^127\.|^localhost'; then
            result_safe "OLLAMA_HOST is bound to localhost (${ollama_host})"
        else
            result_warming "OLLAMA_HOST is set to ${ollama_host} — verify this is intentional"
        fi
    else
        result_safe "OLLAMA_HOST not set (defaults to localhost)"
    fi

    # Check OLLAMA_ORIGINS
    local ollama_origins="${OLLAMA_ORIGINS:-}"
    if [[ "$ollama_origins" == "*" ]]; then
        result_cooked "OLLAMA_ORIGINS=* — any website can access your Ollama!"
    elif [[ -n "$ollama_origins" ]]; then
        result_warming "OLLAMA_ORIGINS is set to: ${ollama_origins}"
    fi

    # Check systemd service file if exists
    if [[ -f /etc/systemd/system/ollama.service ]]; then
        local svc_user
        svc_user=$(grep -oP 'User=\K.*' /etc/systemd/system/ollama.service 2>/dev/null || echo "")
        if [[ "$svc_user" == "root" || -z "$svc_user" ]]; then
            result_warming "Ollama systemd service runs as root (or no User= set)"
        else
            result_safe "Ollama systemd service runs as '${svc_user}'"
        fi
    fi
}

# ─── Score & Summary ────────────────────────────────────────────────────────────

print_summary() {
    echo ""
    echo -e "${DIM}──────────────────────────────────────────────────────────────${RESET}"
    echo ""

    # Cap score at 100
    if [[ $SCORE -gt 100 ]]; then
        SCORE=100
    fi

    # Determine cooked level
    local level_text level_color bar_char
    if [[ $SCORE -ge 70 ]]; then
        level_text="FULLY COOKED"
        level_color="$RED"
        bar_char="█"
    elif [[ $SCORE -ge 40 ]]; then
        level_text="MEDIUM RARE"
        level_color="$YELLOW"
        bar_char="▓"
    elif [[ $SCORE -ge 15 ]]; then
        level_text="SLIGHTLY WARM"
        level_color="$CYAN"
        bar_char="▒"
    else
        level_text="LOOKING FRESH"
        level_color="$GREEN"
        bar_char="░"
    fi

    # Score bar
    local bar_width=40
    local filled=$((SCORE * bar_width / 100))
    local empty=$((bar_width - filled))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="$bar_char"; done
    for ((i=0; i<empty; i++)); do bar+=" "; done

    echo -e "  ${WHITE}${BOLD}YOUR COOKED SCORE${RESET}"
    echo ""
    echo -e "  ${level_color}${BOLD}${SCORE}%${RESET} ${DIM}cooked${RESET}  [${level_color}${bar}${RESET}]"
    echo ""
    echo -e "  ${level_color}${BOLD}${level_text}${RESET}"
    echo ""
    echo -e "  ${RED}${BOLD}${COOKED_COUNT}${RESET} critical  ${YELLOW}${BOLD}${WARMING_COUNT}${RESET} warnings  ${GREEN}${BOLD}${SAFE_COUNT}${RESET} passed  ${DIM}(${TOTAL_CHECKS} total checks)${RESET}"
    echo ""

    if [[ $SCORE -ge 70 ]]; then
        echo -e "  ${RED}You are absolutely cooked. Fix the critical issues above ASAP.${RESET}"
    elif [[ $SCORE -ge 40 ]]; then
        echo -e "  ${YELLOW}You're getting warm. Address the warnings to tighten things up.${RESET}"
    elif [[ $SCORE -ge 15 ]]; then
        echo -e "  ${CYAN}Not bad! A few things to clean up but you're mostly good.${RESET}"
    else
        echo -e "  ${GREEN}Looking fresh! Your local AI setup is pretty well locked down.${RESET}"
    fi

    echo ""
    echo -e "  ${DIM}Run with sudo for more thorough checks (firewall, ports, etc.)${RESET}"
    echo -e "  ${DIM}Report issues: https://github.com/johnpippett/iscooked${RESET}"
    echo ""
}

# ─── Main ───────────────────────────────────────────────────────────────────────

main() {
    banner

    check_network_exposure
    check_api_auth
    check_model_permissions
    check_docker_risks
    check_gpu_exposure
    check_telemetry
    check_firewall
    check_ssl_tls
    check_processes
    check_sensitive_files
    check_history_logs
    check_ollama_config

    print_summary
}

main "$@"
