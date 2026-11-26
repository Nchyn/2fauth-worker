'use strict';

/* ---------------------------------------------------------------------------
 * 后台：为内容脚本提供「当前站点 → 对应验证码」
 * - 优先使用设备令牌直连站点（无需站点标签页）
 * - 未配置令牌时回退到「站点会话 + 标签页注入」
 * - 只按需拉取/缓存验证码，不缓存账户密钥
 * ------------------------------------------------------------------------- */

if (typeof importScripts === 'function' && typeof FWShared === 'undefined') {
  importScripts('shared.js');
}

const api = globalThis.browser ?? globalThis.chrome;

const HOST_KEY = 'fw_host';
const TOKEN_KEY = 'fw_token';
const TOKEN_META_KEY = 'fw_token_meta';
const PENDING_BIND_KEY = 'fw_pending_bind';
const BINDINGS_KEY = 'fw_bindings';
const CACHE_KEY = 'fw_cache';
const ERROR_THROTTLE = 5000;
const CACHE_MAX_AGE = 5 * 60 * 1000;

let inFlight = null;
let lastError = null;
let lastErrorAt = 0;

function offsetOf(cache) {
  const sample = (cache.accounts || []).find(
    (account) => typeof account.generated_at === 'number'
  );
  return sample ? sample.generated_at * 1000 - Date.now() : 0;
}

function cacheUsable(cache) {
  if (!cache || !Array.isArray(cache.accounts)) return false;
  if (Date.now() - (cache.fetchedAt || 0) > CACHE_MAX_AGE) return false;

  const offset = offsetOf(cache);
  return cache.accounts.every((account) => !FWShared.selectCode(account, offset).stale);
}

async function readConfig() {
  const stored = await api.storage.local.get([HOST_KEY, TOKEN_KEY, TOKEN_META_KEY]);
  return {
    host: (stored && stored[HOST_KEY]) || '',
    token: (stored && stored[TOKEN_KEY]) || '',
    meta: (stored && stored[TOKEN_META_KEY]) || null,
  };
}

async function readCache(host) {
  try {
    const stored = await api.storage.session.get(CACHE_KEY);
    const cache = stored ? stored[CACHE_KEY] : null;
    if (!cache || cache.host !== host || !Array.isArray(cache.accounts)) return null;
    return cache;
  } catch {
    return null;
  }
}

async function fetchAndCache(host, token) {
  if (inFlight) return inFlight;

  inFlight = (async () => {
    try {
      const data = await FWShared.fetchFromSite(host, { token });
      const cache = {
        host,
        mode: token ? 'token' : 'session',
        fetchedAt: Date.now(),
        accounts: data.accounts,
      };

      try {
        await api.storage.session.set({ [CACHE_KEY]: cache });
      } catch {
        /* 会话存储不可用时仍然返回本次结果 */
      }

      // 令牌模式：服务端会回传滑动续期后的到期时间，写回本地供弹窗展示
      if (token && data.token && data.token.expiresAt) {
        try {
          const previous = await api.storage.local.get(TOKEN_META_KEY);
          const meta = (previous && previous[TOKEN_META_KEY]) || {};
          await api.storage.local.set({
            [TOKEN_META_KEY]: {
              ...meta,
              label: data.token.label || meta.label || '',
              expiresAt: data.token.expiresAt,
              lastVerifiedAt: Date.now(),
            },
          });
        } catch {
          /* ignore */
        }
      }

      lastError = null;
      return cache;
    } catch (error) {
      lastError = error;
      lastErrorAt = Date.now();
      throw error;
    } finally {
      inFlight = null;
    }
  })();

  return inFlight;
}

async function ensureCache(host, token) {
  const cached = await readCache(host);
  if (cacheUsable(cached)) return cached;

  if (lastError && Date.now() - lastErrorAt < ERROR_THROTTLE) {
    throw lastError;
  }

  return await fetchAndCache(host, token);
}

function hostnameOf(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
    return parsed.hostname;
  } catch {
    return '';
  }
}

async function handleLookup(message, sender) {
  const sourceUrl = (sender.tab && sender.tab.url) || sender.url || '';
  const hostname = hostnameOf(sourceUrl);
  if (!hostname) return { ok: false, error: 'no_host' };

  const config = await readConfig();
  if (!config.host) {
    // 有待确认的绑定时，绝不向页面提供任何验证码（防投毒）
    const pending = await readPendingBind();
    if (pending) return { ok: false, error: 'pending_bind', host: pending.host };
    return { ok: false, error: 'not_configured' };
  }

  let cache;
  try {
    cache = await ensureCache(config.host, config.token);
  } catch (error) {
    const unauthorized = error instanceof FWShared.ApiError && error.status === 401;
    return {
      ok: false,
      error: unauthorized ? 'unauthorized' : 'fetch_failed',
      mode: config.token ? 'token' : 'session',
      message: String((error && error.message) || ''),
    };
  }

  let isSite = false;
  try {
    isSite = new URL(config.host).hostname === hostname;
  } catch {
    isSite = false;
  }

  if (isSite && !message.all) {
    return {
      ok: true,
      hostname,
      mode: cache.mode,
      total: cache.accounts.length,
      accounts: [],
    };
  }

  const stored = await api.storage.local.get(BINDINGS_KEY);
  const bindings = stored[BINDINGS_KEY] || {};

  const selected = message.all
    ? cache.accounts
    : FWShared.matchAccounts(cache.accounts, hostname, bindings);

  const offset = offsetOf(cache);

  return {
    ok: true,
    hostname,
    mode: cache.mode,
    total: cache.accounts.length,
    accounts: selected.map((account) => {
      const status = FWShared.selectCode(account, offset);
      return {
        id: account.id,
        service: account.service,
        account: account.account,
        code: status.code,
        remaining: status.remaining,
        period: status.period,
        digits: account.digits || 6,
      };
    }),
  };
}

async function handleOpenSite(options) {
  const config = await readConfig();
  if (!config.host) {
    const pending = await readPendingBind();
    if (!pending) return { ok: false, error: 'not_configured' };
    await api.tabs.create({ url: pending.host });
    return { ok: true };
  }

  // 令牌模式下「去站点授权」直达安全设置页；会话模式打开站点首页登录
  if (options && options.authorize && config.token) {
    let target = config.host;
    try {
      target = new URL(config.host).origin + '/?tab=security';
    } catch {
      /* fall back to raw host */
    }
    await api.tabs.create({ url: target });
    return { ok: true };
  }

  await api.tabs.create({ url: config.host });
  return { ok: true };
}

/**
 * 接收站点「发送到扩展」的令牌
 * - 已配置过站点且域名一致：直接更新配置（同站重新授权）
 * - 尚未配置站点：不直接落盘，写入 pending_bind 等用户在弹窗里确认，
 *   防止任意网页抢先把自己绑定为扩展的站点
 * - 写入前实测一次 /api/ext/codes，避免保存无效令牌
 */
async function handleAdoptToken(message) {
  const token = String((message && message.token) || '').trim();
  const host = message && message.host ? FWShared.normalizeHost(message.host) : '';

  if (!FWShared.isTokenShape(token)) {
    return { ok: false, error: 'invalid_token' };
  }
  if (!host) {
    return { ok: false, error: 'invalid_host' };
  }

  const config = await readConfig();
  if (config.host && config.host !== host) {
    return { ok: false, error: 'host_mismatch' };
  }

  let data;
  try {
    data = await FWShared.fetchCodesViaToken(host, token);
  } catch (error) {
    const unauthorized = error instanceof FWShared.ApiError && error.status === 401;
    return {
      ok: false,
      error: unauthorized ? 'invalid_token' : 'fetch_failed',
      message: String((error && error.message) || ''),
    };
  }

  const expiresAt =
    (data.token && data.token.expiresAt) ||
    Number(message.expiresAt) ||
    Date.now() + 30 * 24 * 60 * 60 * 1000;

  const meta = {
    label: (data.token && data.token.label) || String(message.label || ''),
    expiresAt,
    lastVerifiedAt: Date.now(),
  };

  if (!config.host) {
    // 首次绑定：只入待确认区，等用户在弹窗里看清楚域名后确认
    await api.storage.local.set({
      [PENDING_BIND_KEY]: { host, token, meta, total: data.accounts.length },
    });
    return { ok: true, pending: true, host, total: data.accounts.length };
  }

  await commitBind(host, token, meta);
  return {
    ok: true,
    host,
    total: data.accounts.length,
    label: meta.label,
    expiresAt,
  };
}

async function readPendingBind() {
  try {
    const stored = await api.storage.local.get(PENDING_BIND_KEY);
    const pending = stored ? stored[PENDING_BIND_KEY] : null;
    if (!pending || !pending.host || !FWShared.isTokenShape(pending.token)) return null;
    return pending;
  } catch {
    return null;
  }
}

async function clearPendingBind() {
  try {
    await api.storage.local.remove(PENDING_BIND_KEY);
  } catch {
    /* ignore */
  }
}

/** 把令牌提交为正式配置并作废旧缓存 */
async function commitBind(host, token, meta) {
  await api.storage.local.set({
    [HOST_KEY]: host,
    [TOKEN_KEY]: token,
    [TOKEN_META_KEY]: meta,
  });

  try {
    await api.storage.session.remove(CACHE_KEY);
  } catch {
    /* ignore */
  }

  lastError = null;
  lastErrorAt = 0;
}

async function handleConfirmBind() {
  const pending = await readPendingBind();
  if (!pending) return { ok: false, error: 'no_pending_bind' };

  await commitBind(pending.host, pending.token, pending.meta);
  await clearPendingBind();

  return {
    ok: true,
    host: pending.host,
    label: (pending.meta && pending.meta.label) || '',
    expiresAt: (pending.meta && pending.meta.expiresAt) || 0,
  };
}

async function handleRejectBind() {
  await clearPendingBind();
  return { ok: true };
}

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== 'string') return false;

  if (message.type === 'fw:lookup') {
    handleLookup(message, sender)
      .then(sendResponse)
      .catch((error) => {
        sendResponse({
          ok: false,
          error: 'fetch_failed',
          message: String((error && error.message) || error),
        });
      });
    return true;
  }

  if (message.type === 'fw:open-site') {
    handleOpenSite(message)
      .then(sendResponse)
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message.type === 'fw:adopt-token') {
    handleAdoptToken(message)
      .then(sendResponse)
      .catch((error) =>
        sendResponse({
          ok: false,
          error: 'fetch_failed',
          message: String((error && error.message) || error),
        })
      );
    return true;
  }

  if (message.type === 'fw:confirm-bind') {
    handleConfirmBind()
      .then(sendResponse)
      .catch(() => sendResponse({ ok: false, error: 'fetch_failed' }));
    return true;
  }

  if (message.type === 'fw:reject-bind') {
    handleRejectBind()
      .then(sendResponse)
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  return false;
});
