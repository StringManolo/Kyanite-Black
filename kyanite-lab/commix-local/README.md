# Local Commix Target

This is an intentionally vulnerable command-injection training service. It must remain local and isolated.

## Build and run

```bash
docker build -t kyanite-commix-lab .
docker run --rm --name kyanite-commix-lab \
  --network none \
  -p 127.0.0.1:5001:5000 \
  kyanite-commix-lab
```

## Test

```bash
curl 'http://127.0.0.1:5001/?host=127.0.0.1'
commix --url='http://127.0.0.1:5001/?host=127.0.0.1'
```

The app runs as an unprivileged container user. Docker networking is disabled and the published port is bound to loopback only.

Do not bind this port to `0.0.0.0`, use a public tunnel, deploy it to Netlify, or expose it to untrusted users.
