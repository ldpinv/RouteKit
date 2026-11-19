function surgeConfig(argument) {
  if (argument && typeof argument === "object") return argument;
  if (typeof argument !== "string") return {};
  const input = argument.trim().replace(/^(["'])([\s\S]*)\1$/, "$2");
  // guguyun 放在最后，完整保留分享链接中的 &、= 和百分号编码。
  const match = /^po0_tokens=([\s\S]*?)&guguyun_links=([\s\S]*)$/.exec(input);
  return match ? { po0_tokens: match[1], guguyun_links: match[2] } : {};
}

function surgeRequest({ method, url }) {
  return new Promise((resolve, reject) => {
    const options = { url, policy: "DIRECT", timeout: REQUEST_TIMEOUT_MS / 1000 };
    const callback = (error, response, body) => {
      const status = response && (response.status || response.statusCode);
      if (status) resolve({ status, body });
      else if (error) reject(error);
      else resolve({});
    };
    if (method === "POST") {
      options.headers = { "Content-Type": "application/json" };
      options.body = "";
      $httpClient.post(options, callback);
    } else {
      $httpClient.get(options, callback);
    }
  });
}

(async () => {
  const type = typeof $script !== "undefined" && $script ? $script.type : "";
  const event = typeof $event !== "undefined" && $event && $event.name;
  const trigger = type === "generic" ? "panel" : type === "event" || event ? "network" : "schedule";
  const storage = {
    get(key) { try { return $persistentStore.read(key); } catch (_) { return null; } },
    set(key, value) { try { $persistentStore.write(value, key); } catch (_) { /* 下次运行再记录。 */ } },
  };
  const notify = (title, subtitle, body) => $notification.post(title, subtitle, body);
  let panel = {};
  try {
    const config = surgeConfig(typeof $argument === "undefined" ? undefined : $argument);
    panel = await runFirewallWhitelist({ config, trigger, request: surgeRequest, storage, notify });
  } catch (_) {
    const content = "脚本运行异常";
    if (trigger === "panel") panel = { title: TITLE, content, style: "alert" };
    else notify(TITLE, content, "");
  } finally {
    $done(trigger === "panel" ? panel : {});
  }
})();
