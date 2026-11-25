# Kyanite Lab

A multi-project security testing lab hosted as one Netlify site.

## Layout

- `/` — lab homepage
- `/arjun/` — HTTP parameter discovery playground
- `/api/search` — Arjun endpoint
- `/commix/` — public fake-shell command-injection simulator
- `/api/commix` — Commix simulator endpoint

## Deploy to Netlify

From this directory:

```bash
npm install -g netlify-cli
netlify login
netlify init
netlify deploy --prod
```

Create one site when prompted. The publish directory is `public`; functions are in `netlify/functions`, as configured in `netlify.toml`.

## Arjun

```bash
arjun -u 'https://YOUR-SITE.netlify.app/api/search' -m GET
```

## Commix simulator

```bash
commix --url='https://YOUR-SITE.netlify.app/api/commix?host=127.0.0.1'
```

The Commix endpoint uses a deliberately limited fake-shell emulator. It recognizes a small allowlist of harmless commands and returns synthetic Linux-like output. It does not invoke a real shell, execute arbitrary commands, access files, or provide a real operating-system environment. Time-based command injection is not simulated, and Commix may not identify every technique or version-specific probe.

This simulator is designed for public, low-risk tool compatibility testing. Do not treat it as a real command-injection vulnerability or as evidence that arbitrary command execution is possible.

## Add more labs

Put static files in `public/<lab-name>/` and add any serverless endpoints under `netlify/functions/`. Each lab can have its own route while sharing this one Netlify site.
