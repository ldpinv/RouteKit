const PO0_API = "https://124.221.69.228/api/firewall/";
const REQUEST_TIMEOUT_MS = 5000;
const RETRY_DELAYS_MS = [1000, 2500];
const SETTLE_MS = 1000;
const CONFIRM_MS = 15000;
const STATE_KEY = "routekit_firewall_whitelist_v1";
const TITLE = "防火墙自动加白";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function configured(value) {
  const text = typeof value === "string" ? value.trim() : "";
  return /^\{\{\{\w+\}\}\}$/.test(text) ? "" : text;
}

function targets(config) {
  const tokens = configured(config.po0_tokens).split(/[,，;；|、\s]+/).filter(Boolean);
  const links = configured(config.guguyun_links).split(/[;；\r\n]+/).map((link) => link.trim()).filter(Boolean);
  return [
    ...tokens.map((token, index) => {
      const name = `po0 #${index + 1}`;
      const match = /^(pgnfw_[A-Za-z0-9_-]+)(?:@(\d+))?$/.exec(token);
      const slot = match && match[2] !== undefined ? Number(match[2]) : null;
      if (!match || (slot !== null && !Number.isSafeInteger(slot))) {
        return { name, error: "令牌或固定槽位格式有误" };
      }
      const query = slot === null ? "" : `?slot=${slot}`;
      return { name, method: "POST", slot, url: `${PO0_API}${match[1]}/add${query}` };
    }),
    ...links.map((url, index) => {
      const name = `guguyun #${index + 1}`;
      if (!/^https:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:[/?][^\s#]*)?$/i.test(url)) {
        return { name, error: "需要完整的 HTTPS 加白链接" };
      }
      return { name, method: "GET", url };
    }),
  ];
}

function ipv4(value) {
  if (typeof value !== "string") return null;
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(value.trim());
  if (!match) return null;
  const octets = match.slice(1, 5).map(Number);
  const prefix = match[5] === undefined ? null : Number(match[5]);
  if (octets.some((octet) => octet > 255) || prefix > 32) return null;
  const address = octets.join(".");
  const network = `${octets.slice(0, 3).join(".")}.0/24`;
  return { value: prefix === null ? address : `${address}/${prefix}`, prefix, network };
}

function samePo0Entry(entry, current) {
  if (!entry || !current) return false;
  if (entry.value === current.value) return true;
  const supported = (prefix) => prefix === 24 || prefix === null;
  return supported(entry.prefix) && supported(current.prefix) &&
    (entry.prefix === 24 || current.prefix === 24) && entry.network === current.network;
}

function decode(response) {
  try {
    const payload = JSON.parse(response.body);
    if (payload && typeof payload === "object" && !Array.isArray(payload)) return payload;
  } catch (_) { /* 接口可能返回非 JSON 错页。 */ }
  return null;
}

function failure(detail, retry = false) {
  return { ok: false, detail, retry };
}

function po0Result(target, payload) {
  if (payload.enabled === false) return failure("服务端防火墙未启用");
  if (payload.enabled !== true || !Array.isArray(payload.whitelist)) return failure("服务端未返回有效白名单");
  const current = ipv4(payload.currentIp);
  const applied = payload.whitelist.some((item) => {
    const objectEntry = item && typeof item === "object";
    if (target.slot !== null && (!objectEntry || item.slot == null || String(item.slot) !== String(target.slot))) {
      return false;
    }
    return samePo0Entry(ipv4(objectEntry ? item.ip : item), current);
  });
  if (!applied) return failure(target.slot === null ? "当前出口未出现在白名单" : "当前出口未出现在指定槽位");
  const slot = target.slot === null ? "" : `，槽位 ${target.slot}`;
  const capacity = Number.isInteger(payload.limit) ? `/${payload.limit}` : "";
  return {
    ok: true,
    detail: `${current.value}${slot}，白名单 ${payload.whitelist.length}${capacity}`,
    state: current.network,
  };
}

function guguyunResult(payload) {
  const status = Number(payload.status);
  if (status !== 200) {
    if (status === 400) return failure("加白分享链接无效或已失效（业务状态 400）");
    if (Number.isInteger(status) && status >= 400 && status < 600) {
      return failure(`加白接口返回业务状态 ${status}`, status >= 500);
    }
    return failure("服务端未返回可识别的加白状态");
  }
  const data = payload.data || {};
  const network = ipv4(data.cidr || data.ip || data.ip_segment);
  const removed = ipv4(data.removed_cidr);
  return {
    ok: true,
    detail: [network ? `已加白 ${network.value}` : "接口返回成功，未提供加白网段", removed ? `移出 ${removed.value}` : ""].filter(Boolean).join("，"),
    state: network ? network.value : "unknown",
  };
}

function classify(target, response) {
  const status = Number(response.status);
  if (!status) return failure("请求失败，可能是网络超时或握手异常", true);
  const body = typeof response.body === "string" ? response.body.trim() : "";
  if (status >= 500) return failure(`服务端暂时异常（HTTP ${status}）`, true);
  if (status === 400 && /^error$/i.test(body)) return failure("服务端暂时异常（HTTP 400）", true);
  if (status === 403 && target.method === "POST") {
    return failure(target.slot === null ? "po0 拒绝加白（HTTP 403），请检查令牌" : "po0 拒绝加白（HTTP 403），请检查令牌或槽位占用");
  }
  if (status < 200 || status >= 300) return failure(`请求失败（HTTP ${status}）`);
  const payload = decode(response);
  if (!payload) return failure("加白接口未返回有效 JSON");
  return target.method === "POST" ? po0Result(target, payload) : guguyunResult(payload);
}

function thrownResponse(error) {
  // 仅提取状态码和响应体供协议解析，异常原文与请求链接都不进入通知。
  const message = error && error.message ? error.message : String(error || "");
  const match = /status:\s*(\d{3})(?:\s*,\s*body:\s*([\s\S]*))?/i.exec(message);
  return match ? { status: Number(match[1]), body: match[2] } : {};
}

async function authorize(target, request) {
  if (target.error) return failure(target.error);
  for (const delay of [...RETRY_DELAYS_MS, null]) {
    let response;
    try { response = await request(target); } catch (error) { response = thrownResponse(error); }
    const result = classify(target, response);
    if (!result.retry || delay === null) return result;
    await sleep(delay);
  }
}

async function runFirewallWhitelist({ config, trigger, request, storage, notify }) {
  const list = targets(config);
  if (list.length === 0) {
    if (trigger !== "panel") notify(TITLE, "请填写 po0_tokens 或 guguyun_links", "");
    return { title: TITLE, content: "请填写 po0_tokens 或 guguyun_links", style: "alert" };
  }

  const confirm = trigger === "network";
  if (confirm) await sleep(SETTLE_MS);
  const results = await Promise.all(list.map(async (target) => {
    const first = await authorize(target, request);
    if (!confirm || !first.ok) return first;
    await sleep(CONFIRM_MS);
    const second = await authorize(target, request);
    return second.ok ? second : failure(`首次加白已响应，切网确认失败 · ${second.detail}`);
  }));

  const succeeded = results.filter((result) => result.ok).length;
  const title = `${TITLE} ${succeeded}/${list.length}`;
  const content = results.map((result, index) => `${result.ok ? "✅" : "❌"} ${list[index].name} · ${result.detail}`).join("\n");
  const style = succeeded === list.length ? "good" : "alert";

  if (trigger !== "panel") {
    const state = JSON.stringify(results.map((result, index) => [list[index].name, result.ok, result.ok ? result.state : result.detail]));
    if (storage.get(STATE_KEY) !== state) {
      storage.set(STATE_KEY, state);
      notify(TITLE, `${confirm ? "网络事件" : "定时检查"} · ${succeeded}/${list.length}`, content);
    }
  }
  return { title, content, style };
}
