#!/usr/bin/env sh

START_DIR="$(pwd)"
LOG_FILE="$START_DIR/kyanite_black_error_log.txt"
ERROR_FOUND=false

: > "$LOG_FILE"

# Terminal colors.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    ESC="$(printf '\033')"
    RESET="${ESC}[0m"
    GREEN="${ESC}[38;5;82m"
    CYAN="${ESC}[38;5;75m"
    GRAY="${ESC}[38;5;245m"
    YELLOW="${ESC}[38;5;220m"
    RED="${ESC}[38;5;196m"
else
    RESET=''
    GREEN=''
    CYAN=''
    GRAY=''
    YELLOW=''
    RED=''
fi

info() {
    printf '%s[*]%s %s\n' "$GRAY" "$RESET" "$*"
}

success() {
    printf '%s[+]%s %s\n' "$GREEN" "$RESET" "$*"
}

warning() {
    printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$*"
}

error() {
    printf '%s[✗]%s %s\n' "$RED" "$RESET" "$*"
}

# Run a command silently and save its output to the log.
run_logged() {
    tmp="${TMPDIR:-/tmp}/kyanite-log-$$"

    printf '\n===== COMMAND: %s =====\n' "$*" >> "$LOG_FILE"

    "$@" > "$tmp" 2>&1
    rc=$?

    cat "$tmp" >> "$LOG_FILE"
    rm -f "$tmp"

    if [ "$rc" -ne 0 ]; then
        ERROR_FOUND=true
        printf '[ERROR] Exit code: %s | %s\n' "$rc" "$*" >> "$LOG_FILE"
        return "$rc"
    fi

    return 0
}

# Run a test and check its output and exit status.
assert() {
    expected="$1"
    shift

    tmp="${TMPDIR:-/tmp}/kyanite-assert-$$"
    result="$tmp.output"
    status_file="$tmp.status"

    rm -f "$result" "$status_file"

    printf '\n===== ASSERT: %s =====\nExpected: %s\n' "$*" "$expected" >> "$LOG_FILE"

    (
        "$@" > "$result" 2>&1
        rc=$?
        printf '%s\n' "$rc" > "$status_file"
    ) &

    pid=$!
    width=24
    filled=0

    while [ ! -f "$status_file" ]; do
        filled=$(( (filled + 1) % (width + 1) ))
        bar=""
        i=0

        while [ "$i" -lt "$width" ]; do
            if [ "$i" -lt "$filled" ]; then
                bar="${bar}━"
            else
                bar="${bar}─"
            fi
            i=$((i + 1))
        done

        printf '\r\033[2K[%s] Testing...' "$bar"
        sleep 1
    done

    wait "$pid" 2>/dev/null || true

    command_status="$(cat "$status_file")"
    output="$(cat "$result")"

    cat "$result" >> "$LOG_FILE"
    printf '\n[EXIT CODE: %s]\n' "$command_status" >> "$LOG_FILE"

    case "$output" in
        *"$expected"*)
            if [ "$command_status" -eq 0 ]; then
                printf '\r\033[2K%s[✓]%s %s\n' "$GREEN" "$RESET" "$*"
                rm -f "$result" "$status_file"
                return 0
            fi
            ;;
    esac

    ERROR_FOUND=true

    printf '\r\033[2K%s[✗]%s %s\n' "$RED" "$RESET" "$*"
    printf 'Expected: %s\nGot:\n%s\n' "$expected" "$output"

    printf '[ERROR] Assertion failed: %s\n' "$*" >> "$LOG_FILE"

    rm -f "$result" "$status_file"
    return 1
}

# Start installation.
printf '\n'
printf '%sKyanite Black%s\n' "$CYAN" "$RESET"
printf '%sInstalling security tools and running tests...%s\n\n' "$GRAY" "$RESET"

ARCH="$(uname -m)"

info "Detected architecture: $ARCH"

# Prepare working directory.
info "Preparing /KyaniteBlack..."

if ! rm -rf /KyaniteBlack 2>/dev/null ||
   ! mkdir -p /KyaniteBlack; then
    error "Could not prepare /KyaniteBlack."
    ERROR_FOUND=true
    exit 1
fi

cd /KyaniteBlack || {
    error "Could not enter /KyaniteBlack."
    exit 1
}

success "Working directory ready."

# Update packages.
info "Updating package lists..."

if run_logged kpkg update; then
    success "Package lists updated."
else
    error "Package list update failed."
fi

# Upgrade packages.
info "Upgrading installed packages..."

if run_logged kpkg upgrade; then
    success "Packages upgraded."
else
    error "Package upgrade failed."
fi

# Install Git.
info "Installing Git..."

if run_logged kpkg add git; then
    success "Git installed."
else
    error "Git installation failed."
fi

# Install Python.
info "Installing Python pip..."

if run_logged kpkg add python3-pip; then
    success "Python pip installed."
else
    error "Python pip installation failed."
fi

# Install Arjun.
info "Installing Arjun..."

if run_logged pip3 install arjun --break-system-packages; then
    success "Arjun installed."
else
    error "Arjun installation failed."
fi

# Test Arjun.
info "Testing Arjun against the Kyanite Black lab..."

assert 'parameter detected: category, based on: body length' \
    arjun -u 'https://kyanite-black-lab.netlify.app/api/search' -t 50

# Install Commix.
info "Downloading Commix..."

if run_logged git clone https://github.com/commixproject/commix.git commix; then
    success "Commix downloaded."

    info "Installing Commix wrapper..."

    if cat > /bin/commix <<'WRAP'
#!/usr/bin/env sh
set -e

COMMIX_HOME=/KyaniteBlack/commix

[ -d "$COMMIX_HOME" ] || {
    echo "commix is not installed: $COMMIX_HOME" >&2
    exit 1
}

cd "$COMMIX_HOME"
exec python3 commix.py "$@"
WRAP
    then
        if run_logged chmod +x /bin/commix; then
            success "Commix wrapper installed."

            info "Testing Commix against the Kyanite Black lab..."

            assert "appears to be injectable via results-based classic command injection technique" \
                commix \
                --url="https://kyanite-black-lab.netlify.app/api/commix?host=127.0.0.1" \
                --os="Unix-like" \
                --technique=r \
                --skip-heuristics \
                --batch \
                --flush-session \
                -v 1
        else
            error "Could not make the Commix wrapper executable."
        fi
    else
        ERROR_FOUND=true
        error "Could not create the Commix wrapper."
    fi
else
    error "Commix download failed. Skipping its test."
fi

# Install curl.
info "Installing curl..."

if run_logged kpkg add curl; then
    success "Curl installed."
else
    error "Curl installation failed."
fi

# Test curl.
info "Testing HTTPS connectivity..."

assert '<title>Example Domain</title>' curl https://example.com/

# Install Crunch.
info "Downloading Crunch..."

if [ "$ARCH" = "aarch64" ]; then
    URL="https://github.com/StringManolo/Kyanite-Black/releases/download/crunch/crunch_64"
elif [ "$ARCH" = "x86_64" ]; then
    URL="https://github.com/StringManolo/Kyanite-Black/releases/download/crunch/crunch_x86_64"
else
    URL="https://github.com/StringManolo/Kyanite-Black/releases/download/crunch/crunch_32"
fi

if run_logged curl -sfL "$URL" -o /usr/local/bin/crunch.bin; then
    if run_logged chmod +x /usr/local/bin/crunch.bin; then

        if cat > /usr/local/bin/crunch <<'WRAPPER'
#!/usr/bin/env sh
export LC_ALL=C
exec /usr/local/bin/crunch.bin "$@"
WRAPPER
        then
            if run_logged chmod +x /usr/local/bin/crunch; then
                success "Crunch installed."

                info "Testing Crunch..."

                assert 'Crunch will now generate the following number of lines: 7' \
                    crunch 1 1 Kyanite
            else
                error "Could not make Crunch executable."
            fi
        else
            ERROR_FOUND=true
            error "Could not create Crunch wrapper."
        fi
    else
        error "Could not make Crunch binary executable."
    fi
else
    error "Crunch download failed."
fi

# Install dig.
info "Installing DNS utilities..."

if run_logged kpkg add bind9-dnsutils; then
    success "DNS utilities installed."

    info "Testing dig against Google DNS..."
    assert '8.8.4.4' dig dns.google +short
else
    error "DNS utilities installation failed. Skipping dig test."
fi

# Install Feroxbuster dependencies.
info "Installing Feroxbuster dependencies..."

if run_logged kpkg add unzip fontconfig gawk; then
    success "Feroxbuster dependencies installed."
else
    error "Feroxbuster dependencies installation failed."
fi

# Select Feroxbuster architecture.
info "Selecting Feroxbuster architecture..."

case "$ARCH" in
    aarch64)
        FEROX_ARCHIVE="aarch64-linux-feroxbuster.zip"
        ;;
    x86_64)
        FEROX_ARCHIVE="x86_64-linux-feroxbuster.zip"
        ;;
    *)
        error "Feroxbuster does not support architecture: $ARCH"
        FEROX_ARCHIVE=""
        ;;
esac

# Download and install Feroxbuster.
if [ -n "$FEROX_ARCHIVE" ]; then
    FEROX_URL="https://github.com/epi052/feroxbuster/releases/latest/download/$FEROX_ARCHIVE"

    info "Downloading Feroxbuster..."

    if run_logged curl -fL "$FEROX_URL" -o "$FEROX_ARCHIVE"; then
        if run_logged unzip -o "$FEROX_ARCHIVE"; then
            rm -f "$FEROX_ARCHIVE"

            if run_logged mv feroxbuster /bin/feroxbuster &&
               run_logged chmod +x /bin/feroxbuster; then

                success "Feroxbuster installed."

                info "Preparing Feroxbuster test wordlist..."

                if cat > /tmp/ferox-lab-wordlist.txt <<'EOF'
admin
login
robots.txt
api
api/
api/v1/users
api/v1/status
api/v1/keys
backup
backup/
backup.zip
.git
.git/config
server-status
config.php
old-panel
private
uploads
dashboard
test
EOF
                then
                    success "Feroxbuster wordlist prepared."

                    info "Testing Feroxbuster against the Kyanite Black lab..."

                    assert 'FEROX_HTTP_200_OK' sh -c '
                        feroxbuster \
                            -u https://kyanite-black-lab.netlify.app/ferox-lab/ \
                            -w /tmp/ferox-lab-wordlist.txt \
                            -s 200,301,401,403 \
                            -t 10 \
                            --no-state 2>&1 |
                        awk '\''$1 == "200" && $0 ~ /\/backup\.zip([[:space:]]|$)/ {
                            found=1
                        }
                        END {
                            if (found) print "FEROX_HTTP_200_OK"
                        }'\''
                    '
                else
                    ERROR_FOUND=true
                    error "Could not create Feroxbuster wordlist."
                fi
            else
                error "Feroxbuster binary installation failed."
            fi
        else
            error "Could not extract Feroxbuster archive."
            rm -f "$FEROX_ARCHIVE"
        fi
    else
        error "Feroxbuster download failed."
    fi
fi

# Final result.
printf '\n'

if [ "$ERROR_FOUND" = true ]; then
    error "Installation finished with errors."
    warning "Error log saved to: $LOG_FILE"
else
    rm -f "$LOG_FILE"
    success "Installation completed successfully. No errors found."
fi

printf '\n'
