// Simulates a vulnerable shell — deterministic commix detection.
const FAKE_ID = "uid=1000(lab) gid=1000(lab) groups=1000(lab)";

const FAKE_PASSWD = [
  "root:x:0:0:root:/root:/bin/sh",
  "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
  "lab:x:1000:1000:Lab User:/home/lab:/bin/sh",
].join("\n");

const FAKE_OS_RELEASE = [
  'NAME="Kyanite Lab OS"',
  'ID=kyanite-lab',
  'VERSION="1.0-simulated"',
  'PRETTY_NAME="Kyanite Lab OS 1.0"',
].join("\n");

function decodeLoose(v) { return String(v ?? ""); }

// Split on shell separators: ; & && | || real-newline literal-\n
function splitSegments(raw) {
  return raw.split(/(?:;|&&?|\|\|?|\r?\n|\\n)/);
}

function normalizeCommand(raw) {
  return String(raw)
    .replace(/\$\{IFS\}|\$IFS/g, " ")      // space2ifs / space2htab
    .replace(/\\\r?\n/g, " ")              // line continuations only
    .replace(/[\t\r\n]+/g, " ")
    .trim()
    .replace(/^[\s"'`]+|[\s"'`]+$/g, "");
}

// $((A+B)) etc.
function expandArithmetic(s) {
  return s.replace(
    /\$\(\(\s*(\d{1,7})\s*([+\-*\/%])\s*(\d{1,7})\s*\)\)/g,
    (_, a, op, b) => {
      const x = Number(a), y = Number(b);
      let r;
      switch (op) {
        case "+": r = x + y; break;
        case "-": r = x - y; break;
        case "*": r = x * y; break;
        case "/": r = y === 0 ? NaN : Math.floor(x / y); break;
        case "%": r = y === 0 ? NaN : x % y; break;
        default: return `${a}${op}${b}`;
      }
      return Number.isFinite(r) ? String(r) : `${a}${op}${b}`;
    }
  );
}

// $(printf X) $(echo X) `expr A + B` `printf X` `echo X` — iterated (nested)
function expandSubshells(s) {
  let prev, cur = s;
  const arith = (a, op, b) => {
    const x = Number(a), y = Number(b);
    let r;
    switch (op) {
      case "+": r = x + y; break;
      case "-": r = x - y; break;
      case "*": r = x * y; break;
      case "/": r = y === 0 ? NaN : Math.floor(x / y); break;
      case "%": r = y === 0 ? NaN : x % y; break;
      default: return `${a}${op}${b}`;
    }
    return Number.isFinite(r) ? String(r) : `${a}${op}${b}`;
  };
  do {
    prev = cur;
    cur = cur
      .replace(/\$\(\s*printf\s+([A-Za-z0-9_]+)\s*\)/g, "$1")
      .replace(/\$\(\s*echo\s+([A-Za-z0-9_]+)\s*\)/g, "$1")
      .replace(/\$\(\s*expr\s+(\d{1,7})\s*([+\-*\/%])\s*(\d{1,7})\s*\)/g,
               (_, a, op, b) => arith(a, op, b))
      .replace(/`\s*expr\s+(\d{1,7})\s*([+\-*\/%])\s*(\d{1,7})\s*`/g,
               (_, a, op, b) => arith(a, op, b))
      .replace(/`\s*printf\s+([A-Za-z0-9_]+)\s*`/g, "$1")
      .replace(/`\s*echo\s+([A-Za-z0-9_]+)\s*`/g, "$1");
  } while (cur !== prev);
  return cur;
}

// Results-based probes. Handles BOTH format orderings + backtick/echo tampers.
// `\\{0,2}0?40` matches: 40, 040, \40, \040, \\40, \\040
function matchResultsProbe(n) {
  let m;

  // printf %s\\40  PREFIX$((A+B))$(printf INNER)SUFFIX
  m = n.match(/^printf\s+%s\s*\\{0,2}0?40\s+([A-Za-z0-9_]{0,64})\$\(\((\d{1,7})\+(\d{1,7})\)\)\$\(\s*printf\s+([A-Za-z0-9_]{1,64})\s*\)([A-Za-z0-9_]{0,64})$/);
  if (m) return `${m[1]}${Number(m[2]) + Number(m[3])}${m[4]}${m[5]}`;

  // printf \\040%s  PREFIX$((A+B))$(printf INNER)SUFFIX
  m = n.match(/^printf\s+\\{0,2}0?40\s*%s\s+([A-Za-z0-9_]{0,64})\$\(\((\d{1,7})\+(\d{1,7})\)\)\$\(\s*printf\s+([A-Za-z0-9_]{1,64})\s*\)([A-Za-z0-9_]{0,64})$/);
  if (m) return `${m[1]}${Number(m[2]) + Number(m[3])}${m[4]}${m[5]}`;

  // printf %s\\40  PREFIX$((A+B))`printf INNER`SUFFIX
  m = n.match(/^printf\s+%s\s*\\{0,2}0?40\s+([A-Za-z0-9_]{0,64})\$\(\((\d{1,7})\+(\d{1,7})\)\)`\s*printf\s+([A-Za-z0-9_]{1,64})\s*`([A-Za-z0-9_]{0,64})$/);
  if (m) return `${m[1]}${Number(m[2]) + Number(m[3])}${m[4]}${m[5]}`;

  // printf \\040%s  PREFIX$((A+B))`printf INNER`SUFFIX
  m = n.match(/^printf\s+\\{0,2}0?40\s*%s\s+([A-Za-z0-9_]{0,64})\$\(\((\d{1,7})\+(\d{1,7})\)\)`\s*printf\s+([A-Za-z0-9_]{1,64})\s*`([A-Za-z0-9_]{0,64})$/);
  if (m) return `${m[1]}${Number(m[2]) + Number(m[3])}${m[4]}${m[5]}`;

  // printf %s\\40  PREFIX$((A+B))SUFFIX  (no inner)
  m = n.match(/^printf\s+%s\s*\\{0,2}0?40\s+([A-Za-z0-9_]{0,64})\$\(\((\d{1,7})\+(\d{1,7})\)\)([A-Za-z0-9_]{0,64})$/);
  if (m) return `${m[1]}${Number(m[2]) + Number(m[3])}${m[4]}`;

  // printf \\040%s  PREFIX$((A+B))SUFFIX  (no inner)
  m = n.match(/^printf\s+\\{0,2}0?40\s*%s\s+([A-Za-z0-9_]{0,64})\$\(\((\d{1,7})\+(\d{1,7})\)\)([A-Za-z0-9_]{0,64})$/);
  if (m) return `${m[1]}${Number(m[2]) + Number(m[3])}${m[4]}`;

  // echo PREFIX$((A+B))$(echo INNER)SUFFIX       (printf2echo)
  m = n.match(/^echo\s+([A-Za-z0-9_]{0,64})\$\(\((\d{1,7})\+(\d{1,7})\)\)\$\(\s*echo\s+([A-Za-z0-9_]{1,64})\s*\)([A-Za-z0-9_]{0,64})$/);
  if (m) return `${m[1]}${Number(m[2]) + Number(m[3])}${m[4]}${m[5]}`;

  // echo PREFIX$((A+B))`echo INNER`SUFFIX
  m = n.match(/^echo\s+([A-Za-z0-9_]{0,64})\$\(\((\d{1,7})\+(\d{1,7})\)\)`\s*echo\s+([A-Za-z0-9_]{1,64})\s*`([A-Za-z0-9_]{0,64})$/);
  if (m) return `${m[1]}${Number(m[2]) + Number(m[3])}${m[4]}${m[5]}`;

  // echo PREFIX`expr A + B``echo INNER`SUFFIX   (backticks)
  m = n.match(/^echo\s+([A-Za-z0-9_]{0,64})`\s*expr\s+(\d{1,7})\s*\+\s*(\d{1,7})\s*`\s*`\s*echo\s+([A-Za-z0-9_]{1,64})\s*`([A-Za-z0-9_]{0,64})$/);
  if (m) return `${m[1]}${Number(m[2]) + Number(m[3])}${m[4]}${m[5]}`;

  // echo PREFIX$((A+B))SUFFIX  (no inner)
  m = n.match(/^echo\s+([A-Za-z0-9_]{0,64})\$\(\((\d{1,7})\+(\d{1,7})\)\)([A-Za-z0-9_]{0,64})$/);
  if (m) return `${m[1]}${Number(m[2]) + Number(m[3])}${m[4]}`;

  // echo PREFIX`expr A + B`SUFFIX
  m = n.match(/^echo\s+([A-Za-z0-9_]{0,64})`\s*expr\s+(\d{1,7})\s*\+\s*(\d{1,7})\s*`([A-Za-z0-9_]{0,64})$/);
  if (m) return `${m[1]}${Number(m[2]) + Number(m[3])}${m[4]}`;

  return null;
}

function emulateCommand(raw) {
  const cmd = normalizeCommand(raw);
  if (!cmd) return "";

  const normalized = cmd
    .replace(/^\s*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)+/, "")
    .replace(/\s*[<>]{1,2}\s*[^\s]+/g, "")
    .trim();

  // Probes MUST run first
  const probe = matchResultsProbe(normalized);
  if (probe !== null) return probe;

  // Generic emulation after expansion
  const e = expandSubshells(expandArithmetic(normalized));

  if (/^id(?:\s|$)/.test(e)) {
    if (/\s-[uU]\s*-n\b|\s-un\b/.test(e)) return "lab";
    if (/\s-[uU]\b|\s--user\b/.test(e)) return "1000";
    if (/\s-g\s*-n\b|\s-gn\b/.test(e)) return "lab";
    if (/\s-g\b|\s--group\b/.test(e)) return "1000";
    if (/\s-G\b|\s--groups\b/.test(e)) return "1000";
    return FAKE_ID;
  }
  if (/^whoami(?:\s|$)/.test(e)) return "lab";
  if (/^hostname(?:\s|$)/.test(e)) return /\s-i\b/.test(e) ? "127.0.1.1" : "kyanite-lab-sim";
  if (/^pwd(?:\s|$)/.test(e)) return "/home/lab";
  if (/^uname(?:\s|$)/.test(e)) {
    if (/\s-a\b/.test(e)) return "Linux kyanite-lab-sim 6.1.0-lab #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux";
    if (/\s-s\b/.test(e)) return "Linux";
    if (/\s-n\b/.test(e)) return "kyanite-lab-sim";
    if (/\s-r\b/.test(e)) return "6.1.0-lab";
    if (/\s-m\b/.test(e)) return "x86_64";
    return "Linux";
  }
  if (/^cat\s+\/etc\/passwd(?:\s|$)/.test(e)) return FAKE_PASSWD;
  if (/^cat\s+\/etc\/os-release(?:\s|$)/.test(e)) return FAKE_OS_RELEASE;
  if (/^cat\s+\/etc\/hostname(?:\s|$)/.test(e)) return "kyanite-lab-sim";
  if (/^cat\s+\/etc\/hosts(?:\s|$)/.test(e)) return "127.0.0.1\tlocalhost\n127.0.1.1\tkyanite-lab-sim";
  if (/^cat\s+\/proc\/version(?:\s|$)/.test(e)) return "Linux version 6.1.0-lab (root@kyanite-lab) #1 SMP PREEMPT_DYNAMIC";
  if (/^cat\s+\/proc\/self\/status(?:\s|$)/.test(e)) return "Name:\tsh\nState:\tR (running)\nPid:\t887\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000";
  if (/^ls(?:\s+\/)?\s*$/.test(e)) return "bin  dev  etc  home  proc  tmp  usr  var";
  if (/^ls\s+\/etc(?:\s|$)/.test(e)) return "hostname  hosts  issue  os-release  passwd  profile  shadow";
  if (/^ls\s+\/home(?:\s|$)/.test(e)) return "lab";
  if (/^ps(?:\s|$)/.test(e)) {
    if (/\s-ef\b|\s-aux\b/.test(e)) {
      return [
        "UID        PID  PPID  C STIME TTY          TIME CMD",
        "root         1     0  0 Nov20 ?        00:00:01 /sbin/init",
        "root       142     1  0 Nov20 ?        00:00:00 /usr/sbin/kpkg-daemon",
        "lab        887     1  0 19:00 pts/0    00:00:00 /bin/sh",
        "lab        901   887  0 19:13 pts/0    00:00:00 ps -ef",
      ].join("\n");
    }
    return "  PID TTY          TIME CMD\n    1 ?        00:00:01 init\n  887 pts/0    00:00:00 sh\n  901 pts/0    00:00:00 ps";
  }
  if (/^env(?:\s|$)/.test(e)) return "USER=lab\nHOME=/home/lab\nPATH=/usr/local/bin:/usr/bin:/bin\nSHELL=/bin/sh\nPWD=/home/lab";
  if (/^echo(?:\s|$)/.test(e)) {
    return e.replace(/^echo(?:\s+-[neE]+)*\s*/, "")
            .replace(/^(['"])([\s\S]*)\1$/, "$2")
            .replace(/\\0?40/g, " ").replace(/\\n/g, "\n")
            .replace(/\\t/g, "\t").replace(/\\r/g, "\r");
  }
  if (/^printf(?:\s|$)/.test(e)) {
    const q = e.match(/^printf\s+(['"])([\s\S]*?)\1(?:\s+([\s\S]*))?$/);
    if (q) {
      const fmt = q[2].replace(/\\0?40/g, " ").replace(/\\n/g, "\n")
                      .replace(/\\t/g, "\t").replace(/\\r/g, "\r");
      const args = (q[3] ?? "").split(/\s+/).filter(Boolean);
      let i = 0;
      return fmt.replace(/%[sd]/g, () => args[i++] ?? "");
    }
    return e.replace(/^printf\s+/, "")
            .replace(/\\0?40/g, " ").replace(/\\n/g, "\n")
            .replace(/\\t/g, "\t").replace(/\\r/g, "\r")
            .replace(/%s/g, "");
  }
  if (/^true(?:\s|$)/.test(e) || /^false(?:\s|$)/.test(e)) return "";
  if (/^(?:sleep|ping|nc|netcat|ncat|telnet)\s+\d+/i.test(e)) return "";
  if (/^(?:which|command\s+-v|type)\s+(?:sh|bash|id|whoami|uname|cat|echo|printf|ls|pwd|hostname|wget|curl|nc|sleep)(?:\s|$)/.test(e)) {
    return `/usr/bin/${e.split(/\s+/).pop()}`;
  }
  if (/^(?:curl|wget|nslookup|dig|host|base64|xxd|od|hexdump)\b/.test(e)) return "";
  if (/^(?:rm|mv|cp|touch|mkdir|chmod|chown|ln)\b/.test(e)) return "";

  // Command ran but printed nothing (realistic for unknown commands)
  return "";
}

function emulateShellInjection(input) {
  const value = decodeLoose(input);
  const outputs = [];
  const chunks = splitSegments(value);

  // (1) Post-separator injections
  let matched = false;
  for (let i = 1; i < chunks.length; i++) {
    const r = emulateCommand(chunks[i]);
    if (r) { outputs.push(r); matched = true; }
  }

  // (2) Fallback: $(...) / `...` anywhere
  if (!matched) {
    for (const m of value.matchAll(/\$\(([^()]*)\)|`([^`]*)`/g)) {
      const r = emulateCommand(m[1] ?? m[2] ?? "");
      if (r) outputs.push(r);
    }
  }

  // (3) Whole parameter is itself a command
  if (!matched && chunks.length === 1) {
    const t = value.trim();
    if (/^(?:[\d.]+\s*)?(?:id|whoami|uname|pwd|hostname|ls|cat|echo|printf|sleep|curl|wget)\b/.test(t)) {
      const r = emulateCommand(t);
      if (r) outputs.push(r);
    }
  }

  return [...new Set(outputs)].join("\n");
}

// Avoid echoing the whole payload back — commix filters that as "reflection"
function extractHostForEcho(host) {
  const ip = host.match(/^(\d{1,3}\.){3}\d{1,3}/);
  if (ip) return ip[0];
  const h = host.match(/^[a-zA-Z0-9.-]+/);
  return h ? h[0] : "127.0.0.1";
}

export default async (request) => {
  const url  = new URL(request.url);
  const host = url.searchParams.get("host") ?? "127.0.0.1";
  const inj  = emulateShellInjection(host);
  const base = `Host: ${extractHostForEcho(host)}`;
  const body = inj ? `${base}\n${inj}\n` : `${base}\n`;

  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "x-kyanite-sim": "shell-v5",
    },
  });
};
