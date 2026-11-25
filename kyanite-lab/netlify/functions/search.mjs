const ALLOWED = new Set([
  "q", "category", "debug", "id",
]);

export default async (request) => {
  const url = new URL(request.url);
  const received = {};

  for (const [key, value] of url.searchParams.entries()) {
    if (ALLOWED.has(key)) received[key] = value;
  }

  const q = received.q ?? received.query ?? received.search ?? "";
  const results = q
    ? [
        { id: 101, title: `Test result for: ${q}`, category: received.category ?? "all" },
        { id: 102, title: `Secondary match for: ${q}`, category: received.category ?? "all" }
      ]
    : [];

  const body = {
    ok: true,
    endpoint: "/api/search",
    message: q ? "Query processed" : "Enter q, query, or search",
    parameters: received,
    result_count: results.length,
    results,
    ...(received.debug === "1" ? { debug: { handler: "search", mode: "lab" } } : {})
  };

  return new Response(JSON.stringify(body, null, 2), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-lab-endpoint": "parameter-playground"
    }
  });
};
