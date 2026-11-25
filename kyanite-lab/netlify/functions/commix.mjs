const FAKE_ID = "uid=1000(lab) gid=1000(lab) groups=1000(lab)";

const FAKE_PASSWD = [
  "root:x:0:0:root:/root:/bin/sh",
  "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
  "lab:x:1000:1000:Lab User:/home/lab:/bin/sh"
].join("\n");

function decodeLoose(value) {
  return String(value ?? "");
}

function normalizeCommand(raw) {
  return String(raw)
    .replace(/\$\{IFS\}|\$IFS/g, " ")
    // Solo continuaciones de línea: NO tocar \40 / \\40 / \040
    .replace(/\\\r?\n/g, " ")
    .replace(/[\t\r\n]+/g, " ")
    .trim()
    .replace(/^[\s"'`]+|[\s"'`]+$/g, "");
}

function emulateCommand(raw) {
  const cmd = normalizeCommand(raw);
  if (!cmd) return "";

  const normalized = cmd
    .replace(/^\s*[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+/, "")
    .replace(/\s*[<>]{1,2}\s*[^ ]+/g, "")
    .trim();

  // ---------------------------------------------------------------------
  // Probe clásico de commix (results-based):
  //   printf %s\40  PREFIX$((A+B))$(printf INNER)SUFFIX
  // Acepta 1 ó 2 barras, opcional 0 octal, y variante tras space2ifs.
  // ---------------------------------------------------------------------
  const probe = normalized.match(
    /^printf\s+%s\\{1,2}0?40\s+([A-Za-z0-9_]{1,64})\$\(\((\d{1,6})\+(\d{1,6})\)\)\$\(\s*printf\s+([A-Za-z0-9_]{1,64})\s*\)([A-Za-z0-9_]{1,64})$/
  );

  if (probe) {
    const [, prefix, left, right, inner, suffix] = probe;
    const a = Number(left);
    const b = Number(right);
    const sum = a + b;
    if (Number.isSafeInteger(sum) && a <= 999999 && b <= 999999) {
      // Emula: <prefix><sum><inner><suffix><espacio>
      return `${prefix}${sum}${inner}${suffix} `;
    }
  }

  // Probe alternativo con echo (commix a veces verifica con echo).
  const echoProbe = normalized.match(
    /^echo\s+([A-Za-z0-9_]{1,64})\$\(\((\d{1,6})\+(\d{1,6})\)\)([A-Za-z0-9_]{1,64})$/
  );
  if (echoProbe) {
    const [, prefix, left, right, suffix] = echoProbe;
    return `${prefix}${Number(left) + Number(right)}${suffix}`;
  }

  if (/^id(?:\s|$)/.test(normalized)) return FAKE_ID;
  if (/^whoami(?:\s|$)/.test(normalized)) return "lab";
  if (/^hostname(?:\s|$)/.test(normalized)) return "kyanite-lab-sim";
  if (/^pwd(?:\s|$)/.test(normalized)) return "/home/lab";

  if (/^uname(?:\s|$)/.test(normalized)) {
    return /(?:^|\s)-a(?:\s|$)/.test(normalized)
      ? "Linux kyanite-lab-sim 6.1.0-lab #1 SMP x86_64 GNU/Linux"
      : "Linux";
  }

  if (/^cat\s+\/etc\/passwd(?:\s|$)/.test(normalized)) return FAKE_PASSWD;
  if (/^cat\s+\/etc\/os-release(?:\s|$)/.test(normalized)) {
    return 'NAME="Kyanite Lab OS"\nID=kyanite-lab\nVERSION="1.0-simulated"';
  }

  if (/^ls(?:\s+\/)?\s*$/.test(normalized)) {
    return "bin  dev  etc  home  proc  tmp  usr  var";
  }
  if (/^ls\s+\/etc(?:\s|$)/.test(normalized)) {
    return "hostname  os-release  passwd";
  }

  if (/^echo(?:\s|$)/.test(normalized)) {
    return normalized
      .replace(/^echo(?:\s+-n)?\s*/, "")
      .replace(/^(['"])([\s\S]*)\1$/, "$2")
      .replace(/\$\(\((\d{1,6})\+(\d{1,6})\)\)/g,
               (_, a, b) => String(Number(a) + Number(b)))
      .replace(/\\n/g, "\n")
      .replace(/\\t/g, "\t")
      .replace(/\\r/g, "\r");
  }

  if (/^printf(?:\s|$)/.test(normalized)) {
    const match = normalized.match(/^printf\s+(['"])([\s\S]*?)\1/);
    if (match) {
      return match[2]
        .replace(/\$\(\((\d{1,6})\+(\d{1,6})\)\)/g,
                 (_, a, b) => String(Number(a) + Number(b)))
        .replace(/\\n/g, "\n")
        .replace(/\\t/g, "\t")
        .replace(/\\r/g, "\r");
    }
    // printf sin comillas: expandimos aritmética simple.
    const bare = normalized.replace(/^printf\s+/, "");
    return bare
      .replace(/^%s\\{1,2}0?40\s+/, (m, off) => m)   // conservamos prefijo
      .replace(/\$\(\((\d{1,6})\+(\d{1,6})\)\)/g,
               (_, a, b) => String(Number(a) + Number(b)))
      .replace(/\\n/g, "\n")
      .replace(/\\t/g, "\t")
      .replace(/\\r/g, "\r");
  }

  if (/^true(?:\s|$)/.test(normalized)) return "";
  if (/^false(?:\s|$)/.test(normalized)) return "";

  if (/^(?:which|command\s+-v)\s+(?:sh|bash|id|whoami|uname|cat|echo|printf)(?:\s|$)/.test(normalized)) {
    const name = normalized.split(/\s+/).pop();
    return `/usr/bin/${name}`;
  }

  return "";
}

function emulateShellInjection(input) {
  const value = decodeLoose(input);
  const outputs = [];

  // 1) Comandos tras separadores (; & && | || salto de línea)
  const chunks = value.split(/(?:;|&&?|\|\|?|\r?\n)/);
  let matchedChunk = false;
  for (const chunk of chunks.slice(1)) {
    const result = emulateCommand(chunk);
    if (result) {
      outputs.push(result);
      matchedChunk = true;
    }
  }

  // 2) Si no hubo chunk válido, probamos sustituciones $(...) y `...`
  if (!matchedChunk) {
    const substitutions = [
      ...value.matchAll(/\$\(([^()]*)\)|`([^`]*)`/g)
    ];
    for (const match of substitutions) {
      const result = emulateCommand(match[1] ?? match[2] ?? "");
      if (result) outputs.push(result);
    }
  }

  // 3) Parámetro que ES directamente un comando
  if (
    chunks.length === 1 &&
    /^(?:id|whoami|uname|pwd|hostname|ls|cat|echo|printf)\b/.test(value.trim())
  ) {
    const result = emulateCommand(value);
    if (result) outputs.push(result);
  }

  return [...new Set(outputs)].join("\n");
}

export default async (request) => {
  const url = new URL(request.url);

  const host = url.searchParams.get("host") ?? "127.0.0.1";
  const injectedOutput = emulateShellInjection(host);

  const base = `Host: ${host.split(/[;&|]/, 1)[0] || "127.0.0.1"}`;

  const body = injectedOutput
    ? `${base}\n${injectedOutput}\n`
    : `${base}\n`;

  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "x-lab-simulator": "fake-shell-v4"
    }
  });
};
