// 运行时网络钩子 v2 —— 请求+响应成对捕获
// 注入方式: playwright evaluate / 浏览器控制台粘贴 / CDP Page.addScriptToEvaluateOnNewDocument（可捕获加载期调用）
// 注意: 跨域全页刷新后 hook 失效需重注入；SSR 注水数据不走网络，另行读 __NUXT__
(function () {
  if (window.__capInstalled) return 'already installed';
  window.__cap = [];
  var log = function (type, data) { window.__cap.push(Object.assign({ t: Date.now(), type: type }, data)); };

  // fetch: 请求 + 响应成对
  var _fetch = window.fetch;
  window.fetch = function (input, init) {
    var url;
    try { url = typeof input === 'string' ? input : (input && input.url); } catch (e) {}
    log('fetch', { url: url, method: (init && init.method) || 'GET',
                   body: init && init.body ? String(init.body).slice(0, 600) : null });
    var p = _fetch.apply(this, arguments);
    p.then(async function (resp) {
      try {
        var txt = await resp.clone().text();
        log('fetch_resp', { url: url, status: resp.status, resp: txt.slice(0, 1200) });
      } catch (e) {}
    }).catch(function () {});
    return p;
  };

  // XHR: open 记方法路径, setRequestHeader 收头, send 记 body + load 收响应
  var _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__m = method; this.__u = url; this.__h = {};
    return _open.apply(this, arguments);
  };
  var _srh = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.setRequestHeader = function (k, v) {
    if (this.__h) this.__h[k] = v;
    return _srh.apply(this, arguments);
  };
  var _send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (body) {
    var xhr = this;
    if (xhr.__u) {
      log('xhr', { url: xhr.__u, method: xhr.__m || 'GET', headers: xhr.__h || {},
                   body: body ? String(body).slice(0, 600) : null });
      xhr.addEventListener('load', function () {
        try {
          log('xhr_resp', { url: xhr.__u, status: xhr.status,
                            resp: String(xhr.responseText || '').slice(0, 1200) });
        } catch (e) {}
      });
    }
    return _send.apply(this, arguments);
  };

  // sendBeacon: 埋点上报
  var _sb = navigator.sendBeacon && navigator.sendBeacon.bind(navigator);
  if (_sb) navigator.sendBeacon = function (url, data) {
    log('beacon', { url: url, body: data ? String(data).slice(0, 600) : null });
    return _sb(url, data);
  };

  window.__capInstalled = true;
  return 'hooks installed: fetch/xhr/beacon (req+resp)';
})();

// ---- 配套收割/导航片段（页面控制台或 evaluate 里用）----
// 收割并清空:  JSON.stringify((window.__cap||[]).filter(c=>!/telemetry|beacon|collect|analytics/i.test(c.url||'')))
// SPA 导航(Nuxt2): window.$nuxt.$router.push('/target-route')
// 路由表:       window.$nuxt.$router.options.routes
// 性能清单:     [...new Set(performance.getEntriesByType('resource').map(e=>e.name))]
