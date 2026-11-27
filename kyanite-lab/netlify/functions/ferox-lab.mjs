const BASE = "/ferox-lab";

const routes = {
  "": {
    status: 200,
    type: "text/html",
    body: `<!doctype html>
<html>
<head><title>Feroxbuster Test Lab</title></head>
<body>
<h1>Feroxbuster Test Lab</h1>
<p>Controlled directory discovery target.</p>
<ul>
<li><a href="/ferox-lab/admin/">Admin</a></li>
<li><a href="/ferox-lab/api/">API</a></li>
<li><a href="/ferox-lab/login">Login</a></li>
</ul>
</body></html>`
  },

  "robots.txt": {
    status: 200,
    type: "text/plain",
    body: "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /.git/\n"
  },

  "admin": {
    status: 301,
    location: "/ferox-lab/admin/",
    body: ""
  },

  "admin/": {
    status: 200,
    type: "text/html",
    body: "<h1>Admin Panel</h1><a href='/ferox-lab/admin/dashboard'>Dashboard</a>"
  },

  "admin/dashboard": {
    status: 200,
    type: "text/html",
    body: "<h1>Dashboard</h1><p>Test administrative dashboard.</p>"
  },

  "login": {
    status: 200,
    type: "text/html",
    body: "<h1>Login</h1><form><input name='user'><input name='password'></form>"
  },

  "api": {
    status: 200,
    type: "application/json",
    body: '{"service":"ferox-lab","version":"1.0","status":"ok"}'
  },

  "api/": {
    status: 200,
    type: "application/json",
    body: '{"endpoints":["/api/v1/users","/api/v1/status"]}'
  },

  "api/v1/users": {
    status: 200,
    type: "application/json",
    body: '{"users":[{"id":1,"name":"test"},{"id":2,"name":"demo"}]}'
  },

  "api/v1/status": {
    status: 200,
    type: "application/json",
    body: '{"status":"operational"}'
  },

  "api/v1/keys": {
    status: 401,
    type: "application/json",
    body: '{"error":"authentication_required"}'
  },

  "backup": {
    status: 301,
    location: "/ferox-lab/backup/",
    body: ""
  },

  "backup/": {
    status: 403,
    type: "text/plain",
    body: "Forbidden"
  },

  "backup.zip": {
    status: 200,
    type: "application/octet-stream",
    body: "FEROX-LAB-FAKE-BACKUP"
  },

  ".git": {
    status: 403,
    type: "text/plain",
    body: "Forbidden"
  },

  ".git/config": {
    status: 200,
    type: "text/plain",
    body: "[core]\nrepositoryformatversion = 0\n"
  },

  "server-status": {
    status: 403,
    type: "text/plain",
    body: "Forbidden"
  },

  "config.php": {
    status: 200,
    type: "text/plain",
    body: "<?php // simulated configuration file ?>"
  },

  "old-panel": {
    status: 301,
    location: "/ferox-lab/admin/",
    body: ""
  },

  "private": {
    status: 403,
    type: "text/plain",
    body: "Forbidden"
  },

  "uploads": {
    status: 200,
    type: "text/html",
    body: "<h1>Uploads</h1>"
  }
};

export default async (request) => {
  const url = new URL(request.url);

  let path;

  try {
    path = decodeURIComponent(url.pathname);
  } catch {
    return new Response("Bad path", { status: 400 });
  }

  if (!path.startsWith(BASE)) {
    return new Response("Not found", { status: 404 });
  }

  let key = path.slice(BASE.length).replace(/^\/+/, "");

  const trailingSlash = key.endsWith("/");
  if (trailingSlash && key !== "") {
    key = key.replace(/\/+$/, "") + "/";
  }

  const route = routes[key];

  if (!route) {
    return new Response("Not found", {
      status: 404,
      headers: {
        "Content-Type": "text/plain",
        "X-Ferox-Lab": "miss",
        "Cache-Control": "no-store"
      }
    });
  }

  const headers = {
    "Content-Type": route.type || "text/plain",
    "X-Ferox-Lab": "hit",
    "Cache-Control": "no-store"
  };

  if (route.location) {
    headers.Location = route.location;
  }

  return new Response(
    request.method === "HEAD" ? null : route.body,
    {
      status: route.status,
      headers
    }
  );
};

export const config = {
  path: "/ferox-lab/*",
  method: ["GET", "HEAD"]
};
