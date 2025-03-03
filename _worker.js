// _worker.js

const PREFLIGHT_INIT = {
  headers: new Headers({
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS",
    "access-control-max-age": "1728000",
  }),
};

function makeRes(body, status = 200, headers = {}) {
  headers["access-control-allow-origin"] = "*";
  return new Response(body, { status, headers });
}

function newUrl(urlStr) {
  try {
    return new URL(urlStr);
  } catch (err) {
    return null;
  }
}
const IP_WHITELIST = ["39.170.67.86", "111.22.153.148"];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // 获取请求参数中的 targetUrl
    const targetUrl = url.searchParams.get("url");
    if (!targetUrl) {
      return makeRes("Please provide a URL to proxy.", 400);
    }

    const newUrlObj = newUrl(targetUrl);
    if (!newUrlObj) {
      return makeRes("Invalid URL provided.", 400);
    }

    // 增加 IP 白名单
    const addr = request.headers.get("X-Real-IP");
    if (addr) {
      if (!IP_WHITELIST.includes(addr)) {
        return makeRes("Forbidden", 403);
      }
    }

    // 复制原始请求的标头
    const headers = new Headers(request.headers);

    // 确保 Host 头部被替换为目标 URL 的主机名
    headers.set("Host", newUrlObj.hostname);

    const newRequest = new Request(newUrlObj, {
      method: request.method,
      headers: headers,
      body: request.method !== "GET" && request.method !== "HEAD" ? await request.blob() : null,
      redirect: "follow",
    });

    return fetch(newRequest);
  },
};

function httpHandler(req, pathname) {
  const reqHdrRaw = req.headers;

  if (req.method === "OPTIONS" && reqHdrRaw.has("access-control-request-headers")) {
    return new Response(null, PREFLIGHT_INIT);
  }

  const reqHdrNew = new Headers(reqHdrRaw);

  const urlStr = pathname;

  const urlObj = newUrl(urlStr);

  const reqInit = {
    method: req.method,
    headers: reqHdrNew,
    redirect: "follow",
    body: req.body,
  };
  return proxy(urlObj, reqInit);
}

async function proxy(urlObj, reqInit) {
  const res = await fetch(urlObj.href, reqInit);
  const resHdrOld = res.headers;
  const resHdrNew = new Headers(resHdrOld);

  const status = res.status;
  resHdrNew.set("access-control-expose-headers", "*");
  resHdrNew.set("access-control-allow-origin", "*");
  resHdrNew.set("Cache-Control", "max-age=1500");

  resHdrNew.delete("content-security-policy");
  resHdrNew.delete("content-security-policy-report-only");
  resHdrNew.delete("clear-site-data");

  return new Response(res.body, {
    status,
    headers: resHdrNew,
  });
}
