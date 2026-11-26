#!/usr/bin/env sh

printf 'Installing Kyanite Black, this may take a while ...\n'

ARCH="$(uname -m)"

echo -e "\nArch detected as $ARCH. If it's wrong, stop the script and fix it ..."

sleep 7

printf '\nSetting up test helpers ...\n'

assert() {
    expected="$1"
    shift

    tmp="${TMPDIR:-/tmp}/kyanite-assert-$$"
    result="$tmp.output"
    status_file="$tmp.status"

    rm -f "$result" "$status_file"

    # El centinela se crea SOLO después de que el comando termina
    # y su fd sobre $result se ha cerrado → el archivo está completo.
    (
        "$@" > "$result" 2>&1
        : > "$status_file"
    ) &

    width=24
    filled=0

    while [ ! -e "$status_file" ]; do
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

    # Sin grep ni wait: match de subcadena literal vía glob de case.
    output=$(cat "$result")

    case "$output" in
        *"$expected"*)
            printf '\r\033[2K[✓] %s\n' "$*"
            rm -f "$result" "$status_file"
            return 0
            ;;
        *)
            printf '\r\033[2K[✗] %s\n' "$*"
            printf 'Expected: %s\nGot:\n%s\n' "$expected" "$output"
            rm -f "$result" "$status_file"
            return 1
            ;;
    esac
}


printf '\nMaking /KyaniteBlack folder ...\n'
mkdir /KyaniteBlack 2>/dev/null || true

printf '\nUsing /KyaniteBlack the working folder ...\n'
cd /KyaniteBlack || exit 1

printf '\nDownloading list of available packages ...\n'
# kpkg update

printf '\nUpgrading already installed packages to the last version ...\n'
# kpkg upgrade

printf '\nInstalling git to download packages ...\n'
kpkg add git

printf '\nInstalling python3-pip ...\n'
kpkg add python3-pip

printf '\nInstalling arjun. HTTP parameter discovery suite ...\n'
pip3 install arjun --break-system-packages

printf '\nTesting arjun against https://kyanite-black-lab.netlify.app ...\n'
assert 'parameter detected: category, based on: body length' \
  arjun -u 'https://kyanite-black-lab.netlify.app/api/search' -t 50

printf '\nInstalling commix. Automated All-in-One OS command injection exploitation tool ...\n'
git clone https://github.com/commixproject/commix.git commix

printf '\nInstalling commix wrapper in /bin ...\n'

cat > /bin/commix <<'WRAP'
#!/usr/bin/env sh
set -e
COMMIX_HOME=/KyaniteBlack/commix
[ -d "$COMMIX_HOME" ] || { echo "commix is not installed $COMMIX_HOME" >&2; exit 1; }
cd "$COMMIX_HOME"
exec python3 commix.py "$@"
WRAP
chmod +x /bin/commix

printf '\nTesting commix against https://kyanite-black-lab.netlify.app ...\n'

assert 'Payload: 127.0.0.1;printf %s\\40 AOQQEX$((88+78))$(printf AOQQEX)AOQQEX;' \
  commix \
   --url="https://kyanite-black-lab.netlify.app/api/commix?host=127.0.0.1" \
   --os="Unix-like" \
   --technique=r \
   --skip-heuristics \
   --batch \
   -v 1

printf '\nInstalling curl. Command line tool for transferring data ...\n'
# kpkg add curl
assert '<title>Example Domain</title>' curl https://example.com/


printf '\nInstalling crunch. Wordlist generator of all possible combinations and permutations from a charset ...\n'
if [[ "$ARCH" == "aarch64" ]]; then
    URL="https://github.com/StringManolo/Kyanite-Black/releases/download/crunch/crunch_64"
elif [[ "$ARCH" == "x86_64" ]]; then
    URL="https://github.com/StringManolo/Kyanite-Black/releases/download/crunch/crunch_x86_64"
else
    URL="https://github.com/StringManolo/Kyanite-Black/releases/download/crunch/crunch_32"
fi
curl -sfL "$URL" -o crunch
chmod +x crunch
ln -sf "$(pwd)/crunch" /usr/local/bin/crunch

assert 'Crunch will now generate the following number of lines: 7' crunch 1 1 Kyanite

# TODO: COMPILE FOR THE 3 ARCHS FROM THE WORKFLOW THAT GENERATES THE ROOTFS, DISABLE PREVIOUS METHOD 
# git clone https://github.com/crunchsec/crunch

# TODO:
# - Add auto update of commix
# - Check if netlify reachable, if not, run instance localy
# - Upagrade version manually, download MOTD, etc
