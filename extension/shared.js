'use strict';

/* ---------------------------------------------------------------------------
 * 共享逻辑：站点访问、验证码选择、站点匹配
 * - 弹窗（popup）和后台（background）都会加载本文件
 * - Chrome 后台通过 importScripts 加载；Firefox 通过 background.scripts 加载
 * ------------------------------------------------------------------------- */

(() => {
  const ext = globalThis.browser ?? globalThis.chrome;

  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.name = 'ApiError';
      this.status = status;
    }
  }

  /* -------------------------------------------------------------------------
   * 站点访问
   * ----------------------------------------------------------------------- */

  function normalizeHost(raw) {
    let value = String(raw || '').trim();
    if (!value) return '';

    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
      value = 'https://' + value;
    }

    let url;
    try {
      url = new URL(value);
    } catch {
      return '';
    }

    if (url.protocol !== 'http:' && url.protocol !== 'https:') return '';

    let path = url.pathname.replace(/\/+$/, '');
    path = path.replace(/\/api\/v1$/i, '');
    path = path.replace(/\/+$/, '');

    return (url.origin + path).replace(/\/+$/, '');
  }

  function tabPattern(host) {
    try {
      const url = new URL(host);
      const path = url.pathname.replace(/\/+$/, '');
      return `${url.protocol}//${url.host}${path}/*`;
    } catch {
      return host + '/*';
    }
  }

  function siteOrigin(host) {
    try {
      return new URL(host).origin;
    } catch {
      return '';
    }
  }

  function waitForTabComplete(tabId, timeout = 20000) {
    return new Promise((resolve, reject) => {
      let settled = false;

      const finish = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try {
          ext.tabs.onUpdated.removeListener(listener);
        } catch {
          /* ignore */
        }
        if (error) reject(error);
        else resolve();
      };

      const listener = (id, info) => {
        if (id === tabId && info && info.status === 'complete') finish();
      };

      const timer = setTimeout(() => finish(new Error('页面加载超时')), timeout);

      try {
        ext.tabs.onUpdated.addListener(listener);
      } catch {
        /* ignore */
      }

      ext.tabs
        .get(tabId)
        .then((tab) => {
          if (tab && tab.status === 'complete') finish();
        })
        .catch(() => {
          /* ignore */
        });
    });
  }

  /**
   * 在已登录的站点页面里读取 /api/vault，并在页面内生成验证码。
   * 该函数会被 chrome.scripting.executeScript 序列化，不能引用外部变量。
   */
  async function injectedFetchVault(limit) {
    function readCookie(name) {
      if (!document.cookie) return '';
      const pattern = new RegExp(
        '(?:^|;\\s*)' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)'
      );
      const match = document.cookie.match(pattern);
      return match ? decodeURIComponent(match[1]) : '';
    }

    function hashName(algorithm) {
      const value = String(algorithm || 'SHA1').toUpperCase().replace(/[-_]/g, '');
      if (value === 'SHA256') return 'SHA-256';
      if (value === 'SHA512') return 'SHA-512';
      return 'SHA-1';
    }

    function base32(secret) {
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      const clean = String(secret || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
      let bits = 0;
      let value = 0;
      const out = [];
      for (let index = 0; index < clean.length; index += 1) {
        const position = alphabet.indexOf(clean[index]);
        if (position < 0) continue;
        value = (value << 5) | position;
        bits += 5;
        if (bits >= 8) {
          out.push((value >>> (bits - 8)) & 0xff);
          bits -= 8;
        }
      }
      return new Uint8Array(out);
    }

    async function totp(secret, counter, digits, algorithm) {
      const keyBytes = base32(secret);
      if (keyBytes.length === 0) return '';

      const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'HMAC', hash: hashName(algorithm) },
        false,
        ['sign']
      );

      const buffer = new ArrayBuffer(8);
      new DataView(buffer).setBigUint64(0, BigInt(counter));
      const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, buffer));
      const offset = signature[signature.length - 1] & 0x0f;
      const binary =
        ((signature[offset] & 0x7f) << 24) |
        ((signature[offset + 1] & 0xff) << 16) |
        ((signature[offset + 2] & 0xff) << 8) |
        (signature[offset + 3] & 0xff);

      return String(binary % Math.pow(10, digits)).padStart(digits, '0');
    }

    try {
      const csrf = readCookie('csrf_token');
      const headers = csrf ? { 'X-CSRF-Token': csrf } : {};

      const items = [];
      let page = 1;
      let totalPages = 1;

      do {
        const response = await fetch('/api/vault?page=' + page + '&limit=' + limit, {
          method: 'GET',
          headers,
          credentials: 'same-origin',
          cache: 'no-store',
        });

        if (response.status === 401 || response.status === 403) {
          return { error: 'unauthorized' };
        }
        if (!response.ok) return { error: 'http_' + response.status };

        const body = await response.json();
        if (!body || body.success !== true || !Array.isArray(body.vault)) {
          return { error: 'invalid_response' };
        }

        for (let index = 0; index < body.vault.length; index += 1) {
          items.push(body.vault[index]);
        }

        totalPages =
          body.pagination && Number(body.pagination.totalPages)
            ? Number(body.pagination.totalPages)
            : 1;
        page += 1;
      } while (page <= totalPages && page <= 50);

      const now = Math.floor(Date.now() / 1000);
      const accounts = [];

      for (let index = 0; index < items.length; index += 1) {
        const item = items[index];
        if (!item || !item.id) continue;

        const period = Math.max(1, Number(item.period) || 30);
        const digits = Number(item.digits) || 6;
        const counter = Math.floor(now / period);
        let code = '';
        let nextCode = '';

        if (item.secret) {
          try {
            code = await totp(item.secret, counter, digits, item.algorithm);
            nextCode = await totp(item.secret, counter + 1, digits, item.algorithm);
          } catch {
            code = '';
            nextCode = '';
          }
        }

        accounts.push({
          id: item.id,
          service: item.service,
          account: item.account,
          category: item.category || '',
          period,
          digits,
          generated_at: now,
          code,
          next_code: nextCode,
        });
      }

      return { accounts };
    } catch (error) {
      return {
        error: 'network',
        message: String(error && error.message ? error.message : error),
      };
    }
  }

  async function fetchViaTab(host) {
    let tab = null;
    let created = false;

    try {
      let candidates = [];
      try {
        candidates = await ext.tabs.query({ url: tabPattern(host) });
      } catch {
        candidates = [];
      }

      tab = (candidates || []).find((item) => item && item.id != null && !item.discarded);

      if (!tab) {
        tab = await ext.tabs.create({ url: host, active: false });
        created = true;
      }

      await waitForTabComplete(tab.id);

      const current = await ext.tabs.get(tab.id).catch(() => null);
      const origin = siteOrigin(host);
      if (current && current.url && origin && !current.url.startsWith(origin)) {
        throw new ApiError('站点跳转到了其它页面，请先登录后再试', 401);
      }

      const injections = await ext.scripting.executeScript({
        target: { tabId: tab.id },
        func: injectedFetchVault,
        args: [200],
      });

      const result = injections && injections[0] ? injections[0].result : null;
      if (!result) throw new ApiError('读取站点数据失败', 0);
      if (result.error === 'unauthorized') throw new ApiError('unauthorized', 401);
      if (result.error === 'invalid_response') {
        throw new ApiError('站点返回了非预期的响应，请先打开站点完成登录或验证', 401);
      }
      if (result.error) {
        const message =
          result.error === 'network'
            ? result.message || '无法访问站点'
            : `站点返回错误 (${result.error})`;
        throw new ApiError(message, result.error === 'network' ? 0 : 500);
      }

      return { accounts: Array.isArray(result.accounts) ? result.accounts : [] };
    } finally {
      if (created && tab && tab.id != null) {
        try {
          await ext.tabs.remove(tab.id);
        } catch {
          /* ignore */
        }
      }
    }
  }

  async function fetchPreview(host) {
    const response = await fetch(host + '/api/vault?page=1&limit=500', { cache: 'no-store' });

    if (response.status === 401 || response.status === 403) {
      throw new ApiError('unauthorized', 401);
    }
    if (!response.ok) {
      throw new ApiError(`HTTP ${response.status}`, response.status);
    }

    const body = await response.json();
    // 显式丢弃 secret：弹窗只消费验证码与元数据，密钥不得进入扩展缓存
    const accounts = (body && Array.isArray(body.vault) ? body.vault : []).map((item) => {
      const { secret, ...rest } = item || {};
      return {
        ...rest,
        code: item.code || '',
        next_code: item.next_code || '',
      };
    });

    return { accounts };
  }

  const hasScripting = Boolean(
    ext &&
      ext.scripting &&
      typeof ext.scripting.executeScript === 'function' &&
      ext.tabs &&
      typeof ext.tabs.create === 'function'
  );

  /* -------------------------------------------------------------------------
   * 设备令牌模式（无需站点标签页）
   * ----------------------------------------------------------------------- */

  const TOKEN_PREFIX = 'fw_';

  function isTokenShape(value) {
    return typeof value === 'string' && /^fw_[A-Za-z0-9_-]{20,}$/.test(value.trim());
  }

  function tokenSupported(host) {
    try {
      const url = new URL(host);
      if (url.protocol === 'https:') return true;
      return url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
    } catch {
      return false;
    }
  }

  /**
   * 用设备令牌直接向站点取码。
   * - 必须 omit cookies：站点会话与令牌是两套独立凭据
   * - 响应里只有验证码，没有 secret
   */
  async function fetchCodesViaToken(host, token) {
    const url = siteOrigin(host) + '/api/ext/codes';

    let response;
    try {
      response = await fetch(url, {
        method: 'GET',
        headers: { Authorization: 'Bearer ' + token },
        credentials: 'omit',
        cache: 'no-store',
      });
    } catch (error) {
      throw new ApiError(
        '无法访问站点：' + String(error && error.message ? error.message : error),
        0
      );
    }

    if (response.status === 401 || response.status === 403) {
      throw new ApiError('token_invalid', 401);
    }
    if (response.status === 404) {
      throw new ApiError('站点未启用扩展接口，请更新站点版本', 404);
    }
    if (response.status === 429) {
      throw new ApiError('请求过于频繁，请稍后重试', 429);
    }
    if (!response.ok) {
      throw new ApiError('站点返回错误 (HTTP ' + response.status + ')', response.status);
    }

    const body = await response.json();
    if (!body || body.success !== true || !Array.isArray(body.accounts)) {
      throw new ApiError('站点返回了非预期的响应', 500);
    }

    const accounts = body.accounts
      .filter((item) => item && item.id)
      .map((item) => ({
        id: item.id,
        service: item.service || '',
        account: item.account || '',
        category: item.category || '',
        period: Math.max(1, Number(item.period) || 30),
        digits: Number(item.digits) || 6,
        algorithm: item.algorithm || 'SHA1',
        generated_at: Number(item.generated_at) || Math.floor(Date.now() / 1000),
        code: item.code || '',
        next_code: item.next_code || '',
      }));

    return {
      accounts,
      token: body.token || null,
    };
  }

  async function fetchFromSite(host, options) {
    const token = options && options.token ? String(options.token).trim() : '';
    if (token && tokenSupported(host)) {
      return await fetchCodesViaToken(host, token);
    }
    if (!hasScripting) return await fetchPreview(host);
    return await fetchViaTab(host);
  }

  /* -------------------------------------------------------------------------
   * 验证码选择
   * ----------------------------------------------------------------------- */

  function selectCode(account, offsetMs = 0) {
    const period = Math.max(1, Number(account.period) || 30);
    const generatedAt = Number(account.generated_at || 0);

    const now = Math.floor((Date.now() + offsetMs) / 1000);
    let elapsed = now - generatedAt;
    if (!Number.isFinite(elapsed) || elapsed < 0) elapsed = 0;

    const cycle = Math.floor(elapsed / period);

    if (cycle === 0) {
      return {
        code: account.code || '',
        remaining: Math.max(0, period - (elapsed % period)),
        period,
        stale: false,
      };
    }

    if (cycle === 1 && account.next_code) {
      return {
        code: account.next_code,
        remaining: Math.max(0, period * 2 - elapsed),
        period,
        stale: false,
      };
    }

    return {
      code: account.next_code || account.code || '',
      remaining: 0,
      period,
      stale: true,
    };
  }

  /* -------------------------------------------------------------------------
   * 站点匹配
   * ----------------------------------------------------------------------- */

  const ALIASES = {
    阿里云: ['aliyun'],
    腾讯云: ['tencentcloud', 'qcloud'],
    腾讯: ['tencent', 'qq'],
    百度: ['baidu'],
    微博: ['weibo'],
    知乎: ['zhihu'],
    淘宝: ['taobao'],
    天猫: ['tmall'],
    京东: ['jd'],
    小米: ['xiaomi'],
    华为: ['huawei'],
    网易: ['netease', '163'],
    字节跳动: ['bytedance'],
    抖音: ['douyin'],
    飞书: ['feishu', 'lark'],
    钉钉: ['dingtalk'],
    支付宝: ['alipay'],
    微信: ['wechat', 'weixin'],
    金山: ['wps', 'kingsoft'],
    aws: ['aws', 'amazon'],
    amazon: ['amazon', 'aws'],
    azure: ['azure', 'microsoft'],
    microsoft: ['microsoft', 'live', 'office'],
    x: ['twitter', 'x'],
    twitter: ['twitter', 'x'],
    steam: ['steam', 'steampowered'],
    cloudflare: ['cloudflare'],
    github: ['github'],
    gitlab: ['gitlab'],
    gitee: ['gitee'],
    npm: ['npmjs'],
    docker: ['docker'],
    vercel: ['vercel'],
    netlify: ['netlify'],
    auth0: ['auth0'],
    okta: ['okta'],
    dropbox: ['dropbox'],
    notion: ['notion'],
    figma: ['figma'],
    slack: ['slack'],
    discord: ['discord'],
    telegram: ['telegram', 't'],
    google: ['google'],
    apple: ['apple', 'icloud'],
  };

  function normalizeText(value) {
    return String(value || '')
      .toLowerCase()
      .normalize('NFKD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-z0-9\u4e00-\u9fa5]/g, '');
  }

  const ALIAS_MAP = new Map(
    Object.entries(ALIASES).map(([key, values]) => [
      normalizeText(key),
      values.map(normalizeText),
    ])
  );

  const SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac']);

  function registrableDomain(hostname) {
    const host = String(hostname || '').toLowerCase();

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) {
      return host;
    }

    const labels = host.split('.').filter(Boolean);

    if (labels.length <= 2) return labels.join('.');

    const last = labels[labels.length - 1];
    const second = labels[labels.length - 2];

    if (last.length === 2 && SECOND_LEVEL.has(second) && labels.length >= 3) {
      return labels.slice(-3).join('.');
    }

    return labels.slice(-2).join('.');
  }

  function hostCandidates(hostname) {
    const labels = String(hostname || '')
      .toLowerCase()
      .split('.')
      .filter(Boolean);

    const candidates = new Set();

    for (const label of labels) {
      const normalized = normalizeText(label);
      if (normalized.length >= 3) candidates.add(normalized);
    }

    const domain = registrableDomain(hostname);
    if (domain) {
      const base = normalizeText(domain.split('.')[0]);
      if (base.length >= 3) candidates.add(base);
    }

    return [...candidates];
  }

  function serviceAliases(service) {
    return ALIAS_MAP.get(normalizeText(service)) || [];
  }

  function matchScore(account, candidates) {
    const service = normalizeText(account && account.service);
    if (!service) return 0;

    const aliases = serviceAliases(account.service);
    let best = 0;

    for (const candidate of candidates) {
      if (!candidate) continue;

      if (service === candidate) {
        best = Math.max(best, 4);
        continue;
      }

      if (aliases.includes(candidate)) {
        best = Math.max(best, 3);
        continue;
      }

      if (service.length >= 4 && candidate.length >= 4) {
        if (service.includes(candidate) || candidate.includes(service)) {
          best = Math.max(best, 2);
        }
      }
    }

    for (const alias of aliases) {
      if (alias.length < 4) continue;
      for (const candidate of candidates) {
        if (candidate.length < 4) continue;
        if (alias === candidate) best = Math.max(best, 3);
        else if (alias.includes(candidate) || candidate.includes(alias)) {
          best = Math.max(best, 2);
        }
      }
    }

    return best;
  }

  function boundIds(hostname, bindings) {
    const host = String(hostname || '').toLowerCase();
    const ids = new Set();

    for (const [key, values] of Object.entries(bindings || {})) {
      const normalizedKey = String(key || '').toLowerCase();
      if (!normalizedKey) continue;
      if (host === normalizedKey || host.endsWith('.' + normalizedKey)) {
        for (const id of values || []) ids.add(String(id));
      }
    }

    return ids;
  }

  function matchAccounts(accounts, hostname, bindings) {
    if (!hostname || !Array.isArray(accounts)) return [];

    const candidates = hostCandidates(hostname);

    const heuristic = accounts
      .map((account, index) => ({
        account,
        index,
        score: matchScore(account, candidates),
      }))
      .filter((entry) => entry.score > 0)
      .sort((left, right) => right.score - left.score || left.index - right.index)
      .map((entry) => entry.account);

    const bound = boundIds(hostname, bindings);
    if (bound.size === 0) return heuristic;

    // 手动绑定的账户优先展示，同时保留按域名自动匹配到的账户
    const boundAccounts = accounts.filter((account) => bound.has(String(account.id)));
    const boundSet = new Set(boundAccounts.map((account) => String(account.id)));

    return [
      ...boundAccounts,
      ...heuristic.filter((account) => !boundSet.has(String(account.id))),
    ];
  }

  globalThis.FWShared = {
    ApiError,
    normalizeHost,
    tabPattern,
    siteOrigin,
    waitForTabComplete,
    injectedFetchVault,
    fetchViaTab,
    fetchPreview,
    fetchCodesViaToken,
    fetchFromSite,
    isTokenShape,
    tokenSupported,
    selectCode,
    normalizeText,
    registrableDomain,
    matchAccounts,
  };
})();
