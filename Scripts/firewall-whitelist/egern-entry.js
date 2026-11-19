export default async function (ctx) {
  const storage = {
    get(key) { try { return ctx.storage.get(key); } catch (_) { return null; } },
    set(key, value) { try { ctx.storage.set(key, value); } catch (_) { /* 下次运行再记录。 */ } },
  };
  const notify = (title, subtitle, body) => ctx.notify({ title, subtitle, body });
  const request = async ({ method, url }) => {
    const options = { policy: "DIRECT", timeout: REQUEST_TIMEOUT_MS };
    const response = method === "POST"
      ? await ctx.http.post(url, { ...options, body: "", headers: { "Content-Type": "application/json" } })
      : await ctx.http.get(url, options);
    const body = typeof response.text === "function" ? await response.text() : response.body;
    return { status: response.status, body };
  };
  try {
    await runFirewallWhitelist({ config: ctx.env || {}, trigger: ctx.cron ? "schedule" : "network", request, storage, notify });
  } catch (_) {
    notify(TITLE, "脚本运行异常", "");
  }
}
