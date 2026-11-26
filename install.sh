#!/usr/bin/env sh

START_DIR="$(pwd)"
LOG_FILE="$START_DIR/kyanite_black_error_log.txt"
ERROR_FOUND=false

: > "$LOG_FILE"

printf 'Installing Kyanite Black, this may take a while ...\n'

ARCH="$(uname -m)"

printf '\nArch detected as %s. If it is wrong, stop the script and fix it ...\n' "$ARCH"
sleep 7

printf '\nSetting up test helpers ...\n'

# Execute an external command, display its output and save it to the log.
run_logged() {
    tmp="${TMPDIR:-/tmp}/kyanite-log-$$"

    printf '\n===== COMMAND: %s =====\n' "$*" >> "$LOG_FILE"

    "$@" > "$tmp" 2>&1
    rc=$?

    cat "$tmp"
    cat "$tmp" >> "$LOG_FILE"
    rm -f "$tmp"

    if [ "$rc" -ne 0 ]; then
        ERROR_FOUND=true
        printf '[ERROR] Exit code: %s | %s\n' "$rc" "$*" >> "$LOG_FILE"
        return "$rc"
    fi

    return 0
}

assert() {
    expected="$1"
    shift

    tmp="${TMPDIR:-/tmp}/kyanite-assert-$$"
    result="$tmp.output"
    status_file="$tmp.status"

    rm -f "$result" "$status_file"

    printf '\n===== ASSERT: %s =====\nExpected: %s\n' "$*" "$expected" >> "$LOG_FILE"

    # Save command output and exit status separately.
    (
        "$@" > "$result" 2>&1
        rc=$?
        printf '%s\n' "$rc" > "$status_file"
    ) &

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

    command_status="$(cat "$status_file")"
    output="$(cat "$result")"

    # Preserve the complete output in the log.
    cat "$result" >> "$LOG_FILE"
    printf '\n[EXIT CODE: %s]\n' "$command_status" >> "$LOG_FILE"

    case "$output" in
        *"$expected"*)
            if [ "$command_status" -eq 0 ]; then
                printf '\r\033[2K[✓] %s\n' "$*"
                rm -f "$result" "$status_file"
                return 0
            fi
            ;;
    esac

    ERROR_FOUND=true

    printf '\r\033[2K[✗] %s\n' "$*"
    printf 'Expected: %s\nGot:\n%s\n' "$expected" "$output"
    printf '[ERROR] Assertion failed: %s\n' "$*" >> "$LOG_FILE"

    rm -f "$result" "$status_file"
    return 1
}



printf '\nMaking /KyaniteBlack folder ...\n'
rm -rf /KyaniteBlack 2>/dev/null || true
mkdir /KyaniteBlack 2>/dev/null || true

printf '\nUsing /KyaniteBlack as the working folder ...\n'
cd /KyaniteBlack || exit 1

printf '\nDownloading list of available packages ...\n'
run_logged kpkg update

printf '\nUpgrading already installed packages to the last version ...\n'
run_logged kpkg upgrade

printf '\nInstalling git to download packages ...\n'
run_logged kpkg add git

printf '\nInstalling python3-pip ...\n'
run_logged kpkg add python3-pip

printf '\nInstalling arjun. HTTP parameter discovery suite ...\n'
run_logged pip3 install arjun --break-system-packages

printf '\nTesting arjun against https://kyanite-black-lab.netlify.app ...\n'
assert 'parameter detected: category, based on: body length' \
    arjun -u 'https://kyanite-black-lab.netlify.app/api/search' -t 50

printf '\nInstalling commix. Automated All-in-One OS command injection exploitation tool ...\n'
run_logged git clone https://github.com/commixproject/commix.git commix

printf '\nInstalling commix wrapper in /bin ...\n'

cat > /bin/commix <<'WRAP'
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

chmod +x /bin/commix

printf '\nTesting commix against https://kyanite-black-lab.netlify.app ...\n'

assert "appears to be injectable via results-based classic command injection technique" \
    commix \
    --url="https://kyanite-black-lab.netlify.app/api/commix?host=127.0.0.1" \
    --os="Unix-like" \
    --technique=r \
    --skip-heuristics \
    --batch \
    --flush-session \
    -v 1

printf '\nInstalling curl. Command line tool for transferring data ...\n'
run_logged kpkg add curl

assert '<title>Example Domain</title>' curl https://example.com/

printf '\nInstalling crunch. Wordlist generator ...\n'

if [ "$ARCH" = "aarch64" ]; then
    URL="https://github.com/StringManolo/Kyanite-Black/releases/download/crunch/crunch_64"
elif [ "$ARCH" = "x86_64" ]; then
    URL="https://github.com/StringManolo/Kyanite-Black/releases/download/crunch/crunch_x86_64"
else
    URL="https://github.com/StringManolo/Kyanite-Black/releases/download/crunch/crunch_32"
fi

run_logged curl -sfL "$URL" -o /usr/local/bin/crunch.bin
chmod +x /usr/local/bin/crunch.bin

cat > /usr/local/bin/crunch <<'WRAPPER'
#!/usr/bin/env sh
export LC_ALL=C
exec /usr/local/bin/crunch.bin "$@"
WRAPPER

chmod +x /usr/local/bin/crunch

assert 'Crunch will now generate the following number of lines: 7' \
    crunch 1 1 Kyanite

# Final result
printf '\n'

if [ "$ERROR_FOUND" = true ]; then
    printf '[!] Installation finished with errors.\n'
    printf '[!] Error log saved to: %s\n' "$LOG_FILE"
else
    rm -f "$LOG_FILE"
    printf '[✓] Installation completed successfully. No errors found.\n'
fi
