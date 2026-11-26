'use strict';

/* ---------------------------------------------------------------------------
 * 2FAuth Worker 验证码扩展（站点会话模式）
 *
 * - 复用浏览器中已登录的 2fauth-worker 会话（Cookie + CSRF）
 * - 在站点页面内调用现有 /api/vault，读取账户并在页面内生成 TOTP
 * - 扩展只接收/缓存当前验证码，不保存账户密钥
 * - 读取当前标签页域名，自动展示匹配的账户
 * - 支持用图钉把账户手动绑定到当前站点
 * ------------------------------------------------------------------------- */

const ext = globalThis.browser ?? globalThis.chrome;
const hasLocalStorage = Boolean(ext && ext.storage && ext.storage.local);
const hasSessionStorage = Boolean(ext && ext.storage && ext.storage.session);

const {
  ApiError,
  normalizeHost,
  fetchFromSite,
  fetchCodesViaToken,
  isTokenShape,
  matchAccounts,
  registrableDomain,
  selectCode,
  siteOrigin,
} = globalThis.FWShared;

const HOST_KEY = 'fw_host';
const TOKEN_KEY = 'fw_token';
const TOKEN_META_KEY = 'fw_token_meta';
const CACHE_KEY = 'fw_cache';
const BINDINGS_KEY = 'fw_bindings';

const memorySession = {};

const localStore = {
  async get(keys) {
    if (hasLocalStorage) return await ext.storage.local.get(keys);
    const result = {};
    for (const key of keys) {
      const value = localStorage.getItem(key);
      if (value === null) continue;
      try {
        result[key] = JSON.parse(value);
      } catch {
        result[key] = value;
      }
    }
    return result;
  },
  async set(values) {
    if (hasLocalStorage) {
      await ext.storage.local.set(values);
      return;
    }
    for (const [key, value] of Object.entries(values)) {
      localStorage.setItem(key, JSON.stringify(value));
    }
  },
  async remove(keys) {
    if (hasLocalStorage) {
      await ext.storage.local.remove(keys);
      return;
    }
    for (const key of keys) localStorage.removeItem(key);
  },
};

const sessionStore = {
  async get(key) {
    if (hasSessionStorage) {
      const values = await ext.storage.session.get(key);
      return values ? values[key] ?? null : null;
    }
    return memorySession[key] ?? null;
  },
  async set(values) {
    if (hasSessionStorage) {
      await ext.storage.session.set(values);
      return;
    }
    Object.assign(memorySession, values);
  },
  async remove(keys) {
    if (hasSessionStorage) {
      await ext.storage.session.remove(keys);
      return;
    }
    for (const key of keys) delete memorySession[key];
  },
};

const els = {
  bindConfirmView: document.getElementById('bind-confirm-view'),
  bindHostText: document.getElementById('bind-host-text'),
  bindConfirmBtn: document.getElementById('bind-confirm-btn'),
  bindRejectBtn: document.getElementById('bind-reject-btn'),
  setupView: document.getElementById('setup-view'),
  accountsView: document.getElementById('accounts-view'),
  setupForm: document.getElementById('setup-form'),
  hostInput: document.getElementById('host-input'),
  tokenInput: document.getElementById('token-input'),
  tokenState: document.getElementById('token-state'),
  connectBtn: document.getElementById('connect-btn'),
  connectLabel: document.querySelector('#connect-btn .btn-label'),
  connectSpinner: document.querySelector('#connect-btn .spinner'),
  setupError: document.getElementById('setup-error'),
  openLoginBtn: document.getElementById('open-login-btn'),
  authorizeBtn: document.getElementById('authorize-btn'),
  cancelBtn: document.getElementById('cancel-btn'),
  disconnectBtn: document.getElementById('disconnect-btn'),
  headerHost: document.getElementById('header-host'),
  headerUser: document.getElementById('header-user'),
  modeBadge: document.getElementById('mode-badge'),
  refreshBtn: document.getElementById('refresh-btn'),
  settingsBtn: document.getElementById('settings-btn'),
  errorBanner: document.getElementById('error-banner'),
  errorText: document.getElementById('error-text'),
  retryBtn: document.getElementById('retry-btn'),
  searchInput: document.getElementById('search-input'),
  clearSearch: document.getElementById('clear-search'),
  siteHint: document.getElementById('site-hint'),
  groups: document.getElementById('groups'),
  listLoading: document.getElementById('list-loading'),
  accountList: document.getElementById('account-list'),
  emptyState: document.getElementById('empty-state'),
  emptyTitle: document.getElementById('empty-title'),
  emptyDesc: document.getElementById('empty-desc'),
  footerCount: document.getElementById('footer-count'),
  openWebBtn: document.getElementById('open-web-btn'),
  toast: document.getElementById('toast'),
};

const state = {
  host: '',
  token: '',
  tokenMeta: null,
  pendingBind: null,
  pendingHost: '',
  pendingToken: '',
  accounts: [],
  fetchedAt: 0,
  offsetMs: 0,
  activeGroup: '__all__',
  search: '',
  currentHost: '',
  bindings: {},
  siteMatches: [],
  siteMatchIds: new Set(),
  siteInitialized: false,
  refreshing: false,
  staleNotified: false,
  autoRefreshAt: 0,
  ticker: null,
  refs: new Map(),
  toastTimer: null,
  bannerAction: null,
};

/* ---------------------------------------------------------------------------
 * 当前标签页与绑定
 * ------------------------------------------------------------------------- */

async function getActiveHostname() {
  let host = '';

  if (ext && ext.tabs && typeof ext.tabs.query === 'function') {
    try {
      const tabs = await ext.tabs.query({ active: true, currentWindow: true });
      const url = tabs && tabs[0] && tabs[0].url;
      if (url) {
        const parsed = new URL(url);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
          host = parsed.hostname;
        }
      }
    } catch {
      host = '';
    }
  } else {
    const dev = new URLSearchParams(location.search).get('site');
    if (dev) host = dev.trim().toLowerCase();
  }

  if (host && state.host) {
    try {
      if (new URL(state.host).hostname === host) host = '';
    } catch {
      /* ignore */
    }
  }

  return host;
}

function recomputeSiteMatches() {
  state.siteMatches = state.currentHost
    ? matchAccounts(state.accounts, state.currentHost, state.bindings)
    : [];
  state.siteMatchIds = new Set(state.siteMatches.map((account) => String(account.id)));
}

async function toggleBinding(account) {
  const key = registrableDomain(state.currentHost);
  if (!key) return;

  const map = { ...state.bindings };
  const list = new Set((map[key] || []).map(String));
  const id = String(account.id);
  const willBind = !list.has(id);

  if (willBind) list.add(id);
  else list.delete(id);

  if (list.size > 0) map[key] = [...list];
  else delete map[key];

  state.bindings = map;
  await localStore.set({ [BINDINGS_KEY]: map });

  recomputeSiteMatches();

  if (state.activeGroup === '__current__' && state.siteMatchIds.size === 0) {
    state.activeGroup = '__all__';
  }

  renderGroups();
  renderAccounts();
  showToast(willBind ? '已绑定到当前站点' : '已取消绑定');
}

function updateSiteHint() {
  const show =
    Boolean(state.currentHost) &&
    state.accounts.length > 0 &&
    state.siteMatches.length === 0;

  els.siteHint.hidden = !show;
  if (show) {
    els.siteHint.textContent = `当前站点 ${state.currentHost} 没有匹配账户，可点击账户右侧图钉绑定`;
  }
}

/* ---------------------------------------------------------------------------
 * 通用工具
 * ------------------------------------------------------------------------- */

function describeError(error) {
  if (error instanceof ApiError) {
    if (error.status === 401) {
      return state.token
        ? '设备令牌已过期或被吊销。请到站点的「安全设置 → 浏览器扩展授权」重新授权。'
        : '未登录站点或登录已过期。请打开站点登录后重试。';
    }
    if (error.status === 404) return '站点接口不匹配：未找到 /api/vault 或 /api/ext/codes，请确认站点版本。';
    if (error.status === 429) return '请求过于频繁，请稍后再试。';
    return error.message || '读取站点数据失败。';
  }
  if (error && error.name === 'AbortError') return '请求超时，请检查网络。';
  if (error instanceof TypeError) return '无法访问站点，请检查地址、证书或登录状态。';
  return (error && error.message) || '读取站点数据失败。';
}

function authorizeUrl(host) {
  const base = host || state.host || state.pendingHost;
  if (!base) return '';
  return siteOrigin(base) ? siteOrigin(base) + '/?tab=security' : base;
}

function sendMessage(message) {
  return new Promise((resolve, reject) => {
    if (!ext || !ext.runtime || typeof ext.runtime.sendMessage !== 'function') {
      reject(new Error('runtime_unavailable'));
      return;
    }

    const maybePromise = ext.runtime.sendMessage(message, (response) => {
      const lastError = ext.runtime.lastError;
      if (lastError) {
        reject(new Error(String(lastError.message || lastError)));
        return;
      }
      resolve(response);
    });

    // Firefox: browser.runtime.sendMessage 返回 Promise
    if (maybePromise && typeof maybePromise.then === 'function') {
      maybePromise.then(resolve, reject);
    }
  });
}

function openSite(target) {
  const url = target || state.host || state.pendingHost;
  if (!url) return;

  if (ext && ext.tabs && typeof ext.tabs.create === 'function') {
    ext.tabs.create({ url });
  } else {
    window.open(url, '_blank', 'noopener,noreferrer');
  }
}

function formatTime(timestamp) {
  if (!timestamp) return '';
  const date = new Date(timestamp);
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  return `${hours}:${minutes}`;
}

/* ---------------------------------------------------------------------------
 * 渲染
 * ------------------------------------------------------------------------- */

function showBindConfirm(pending) {
  state.pendingBind = pending;
  els.bindHostText.textContent = pending.host;
  els.bindConfirmView.hidden = false;
  els.setupView.hidden = true;
  els.accountsView.hidden = true;
  stopTicker();
  hideToast();
}

function hideBindConfirm() {
  state.pendingBind = null;
  els.bindConfirmView.hidden = true;
}

async function handleBindConfirm() {
  const pending = state.pendingBind;
  if (!pending) {
    hideBindConfirm();
    return;
  }

  els.bindConfirmBtn.disabled = true;

  try {
    const response = await sendMessage({ type: 'fw:confirm-bind' });
    if (!response || response.ok !== true) {
      showToast('确认失败，请重试', true);
      return;
    }

    hideBindConfirm();
    state.host = response.host;
    state.token = (pending && pending.token) || '';
    state.tokenMeta = {
      label: response.label || '',
      expiresAt: response.expiresAt || 0,
      lastVerifiedAt: Date.now(),
    };
    state.pendingHost = '';
    state.pendingToken = '';
    state.siteInitialized = false;
    state.currentHost = await getActiveHostname();

    els.hostInput.value = state.host;
    els.cancelBtn.hidden = true;
    els.disconnectBtn.hidden = false;

    await localStore.set({ [TOKEN_KEY]: state.token });
    await localStore.set({ [TOKEN_META_KEY]: state.tokenMeta });

    renderTokenState();
    setBanner('', null);
    setLoading(true, '正在通过设备令牌读取验证码…');
    await refreshAll({ initial: true });
  } finally {
    els.bindConfirmBtn.disabled = false;
  }
}

async function handleBindReject() {
  try {
    await sendMessage({ type: 'fw:reject-bind' });
  } catch {
    /* ignore */
  }

  hideBindConfirm();
  showToast('已拒绝该站点授权');
  await init();
}

function showView(name) {
  const isSetup = name === 'setup';
  hideBindConfirm();
  els.setupView.hidden = !isSetup;
  els.accountsView.hidden = isSetup;

  if (isSetup) {
    stopTicker();
    hideToast();
  } else if (state.accounts.length > 0) {
    startTicker();
  }
}

function updateHeader() {
  if (state.host) {
    try {
      const url = new URL(state.host);
      const path = url.pathname && url.pathname !== '/' ? url.pathname.replace(/\/+$/, '') : '';
      els.headerHost.textContent = url.host + path;
      els.headerHost.title = state.host;
    } catch {
      els.headerHost.textContent = state.host;
    }
  }

  const usingToken = Boolean(state.token);

  if (els.modeBadge) {
    els.modeBadge.hidden = false;
    els.modeBadge.textContent = usingToken ? '设备令牌' : '站点会话';
    els.modeBadge.classList.toggle('is-token', usingToken);
    els.modeBadge.title = usingToken
      ? '无需打开站点标签页，30 天内滑动有效'
      : '复用站点登录会话，需要站点保持登录';
  }

  if (usingToken) {
    const expires = state.tokenMeta && state.tokenMeta.expiresAt;
    const label = state.tokenMeta && state.tokenMeta.label;
    const syncText = state.fetchedAt ? `同步于 ${formatTime(state.fetchedAt)}` : '设备令牌';
    els.headerUser.textContent = expires
      ? `${label ? label + ' · ' : ''}有效至 ${formatDate(expires)}`
      : syncText;
    els.headerUser.title = state.token;
  } else {
    els.headerUser.textContent = state.fetchedAt
      ? `同步于 ${formatTime(state.fetchedAt)}`
      : '站点会话';
    els.headerUser.title = '';
  }
}

function formatDate(timestamp) {
  if (!timestamp) return '';
  const date = new Date(timestamp);
  const Y = date.getFullYear();
  const M = String(date.getMonth() + 1).padStart(2, '0');
  const D = String(date.getDate()).padStart(2, '0');
  return `${Y}-${M}-${D}`;
}

function setLoading(visible, text) {
  els.listLoading.hidden = !visible;
  if (text) {
    const label = els.listLoading.querySelector('span:last-child');
    if (label) label.textContent = text;
  }
}

function setSetupError(message) {
  els.setupError.textContent = message || '';
  els.setupError.hidden = !message;
}

function setBanner(message, action, actionLabel) {
  els.errorText.textContent = message || '';
  els.errorBanner.hidden = !message;
  state.bannerAction = action || null;
  els.retryBtn.hidden = !action;
  els.retryBtn.textContent = actionLabel || '重试';
}

function setEmpty(title, description) {
  els.emptyTitle.textContent = title;
  els.emptyDesc.textContent = description || '';
  els.emptyState.hidden = false;
  els.accountList.hidden = true;
}

function hashHue(text) {
  const value = String(text || '');
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) % 360;
}

function initialOf(text) {
  const value = String(text || '').trim();
  return value ? Array.from(value)[0].toUpperCase() : '?';
}

function formatCode(code) {
  const compact = String(code == null ? '' : code).replace(/\s+/g, '');
  if (!compact) return '— — — — — —';
  if (compact.length <= 4) return compact;
  const middle = Math.ceil(compact.length / 2);
  return compact.slice(0, middle) + ' ' + compact.slice(middle);
}

function groupCount(key) {
  if (key === '__all__') return state.accounts.length;
  if (key === '__current__') return state.siteMatches.length;
  if (key === '__none__') {
    return state.accounts.filter((account) => !account.category).length;
  }
  return state.accounts.filter((account) => (account.category || '') === key).length;
}

function renderGroups() {
  if (!state.siteInitialized) {
    state.siteInitialized = true;
    if (state.siteMatches.length > 0) state.activeGroup = '__current__';
  }

  const definitions = [{ key: '__all__', name: '全部' }];

  if (state.siteMatches.length > 0) {
    definitions.push({ key: '__current__', name: '当前站点' });
  }

  const categories = new Set(
    state.accounts.map((account) => account.category || '').filter(Boolean)
  );

  if (state.accounts.some((account) => !account.category)) {
    definitions.push({ key: '__none__', name: '未分类' });
  }

  for (const category of [...categories].sort((left, right) =>
    left.localeCompare(right, 'zh-CN')
  )) {
    definitions.push({ key: category, name: category });
  }

  if (!definitions.some((definition) => definition.key === state.activeGroup)) {
    state.activeGroup = '__all__';
  }

  els.groups.replaceChildren();

  const hasRealGroups = definitions.length > 1;
  els.groups.hidden = !hasRealGroups;
  if (!hasRealGroups) return;

  for (const definition of definitions) {
    const chip = document.createElement('button');
    chip.type = 'button';
    chip.className = 'chip' + (definition.key === state.activeGroup ? ' active' : '');

    const name = document.createElement('span');
    name.textContent = definition.name;

    const count = document.createElement('span');
    count.className = 'count';
    count.textContent = String(groupCount(definition.key));

    chip.append(name, count);
    chip.addEventListener('click', () => {
      state.activeGroup = definition.key;
      renderGroups();
      renderAccounts();
    });
    els.groups.append(chip);
  }
}

function filteredAccounts() {
  const query = state.search.trim().toLowerCase();

  return state.accounts.filter((account) => {
    if (state.activeGroup === '__current__') {
      if (!state.siteMatchIds.has(String(account.id))) return false;
    } else if (state.activeGroup === '__none__') {
      if (account.category) return false;
    } else if (state.activeGroup !== '__all__') {
      if ((account.category || '') !== state.activeGroup) return false;
    }

    if (!query) return true;
    const haystack = `${account.service || ''} ${account.account || ''}`.toLowerCase();
    return haystack.includes(query);
  });
}

function createPinIcon() {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', '11');
  svg.setAttribute('height', '11');
  svg.setAttribute('aria-hidden', 'true');

  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', 'M9 3h6l-1 5 3 3H7l3-3-1-5Zm3 8v8');
  path.setAttribute('fill', 'none');
  path.setAttribute('stroke', 'currentColor');
  path.setAttribute('stroke-width', '2');
  path.setAttribute('stroke-linecap', 'round');
  path.setAttribute('stroke-linejoin', 'round');
  svg.append(path);

  return svg;
}

function createRow(account) {
  const row = document.createElement('div');
  row.className = 'account';
  row.dataset.id = String(account.id);
  row.setAttribute('role', 'button');
  row.tabIndex = 0;
  row.setAttribute(
    'aria-label',
    `复制 ${account.service || ''} ${account.account || ''} 的验证码`
  );

  const avatar = document.createElement('span');
  avatar.className = 'avatar';
  avatar.textContent = initialOf(account.service || account.account);
  avatar.style.setProperty(
    '--av-h',
    String(hashHue(account.service || account.account || ''))
  );

  const meta = document.createElement('span');
  meta.className = 'meta';

  const serviceLine = document.createElement('span');
  serviceLine.className = 'service-line';

  const service = document.createElement('span');
  service.className = 'service';
  service.textContent = account.service || '未命名服务';
  serviceLine.append(service);

  const bindingKey = state.currentHost ? registrableDomain(state.currentHost) : '';
  if (bindingKey) {
    const bound = (state.bindings[bindingKey] || [])
      .map(String)
      .includes(String(account.id));

    const pin = document.createElement('button');
    pin.type = 'button';
    pin.className = 'pin' + (bound ? ' bound' : '');
    pin.title = bound ? '取消绑定到当前站点' : '绑定到当前站点';
    pin.setAttribute('aria-label', pin.title);
    pin.append(createPinIcon());

    pin.addEventListener('click', (event) => {
      event.stopPropagation();
      toggleBinding(account);
    });
    pin.addEventListener('keydown', (event) => event.stopPropagation());

    serviceLine.append(pin);
  }

  const accountName = document.createElement('span');
  accountName.className = 'account-name';
  accountName.textContent = account.account || '';

  meta.append(serviceLine, accountName);

  const otp = document.createElement('span');
  otp.className = 'otp';

  const code = document.createElement('span');
  code.className = 'code';

  const timer = document.createElement('span');
  timer.className = 'timer';

  const bar = document.createElement('span');
  bar.className = 'bar';
  const fill = document.createElement('i');
  bar.append(fill);

  const seconds = document.createElement('span');
  seconds.className = 'sec';

  timer.append(bar, seconds);
  otp.append(code, timer);
  row.append(avatar, meta, otp);

  row.addEventListener('keydown', (event) => {
    if (event.target !== row) return;
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      copyAccountCode(account.id, row);
    }
  });

  state.refs.set(account.id, { row, code, fill, seconds });
  updateRow(account.id, codeState(account));

  return row;
}

function renderAccounts() {
  const visible = filteredAccounts();

  els.accountList.replaceChildren();
  state.refs.clear();

  if (state.accounts.length === 0) {
    setEmpty('站点还没有账户', '请先在网页版添加 TOTP 账户');
    els.footerCount.textContent = '';
    updateSiteHint();
    return;
  }

  if (visible.length === 0) {
    setEmpty('没有匹配的账户', '换个关键词或分类试试');
    els.footerCount.textContent = `0 / ${state.accounts.length} 个账户`;
    updateSiteHint();
    return;
  }

  els.emptyState.hidden = true;
  els.accountList.hidden = false;

  const fragment = document.createDocumentFragment();
  for (const account of visible) fragment.append(createRow(account));
  els.accountList.append(fragment);

  const base =
    visible.length === state.accounts.length
      ? `共 ${state.accounts.length} 个账户`
      : `${visible.length} / ${state.accounts.length} 个账户`;
  els.footerCount.textContent = state.fetchedAt
    ? `${base} · ${formatTime(state.fetchedAt)} 同步`
    : base;

  updateSiteHint();
}

/* ---------------------------------------------------------------------------
 * 验证码倒计时
 * ------------------------------------------------------------------------- */

function codeState(account) {
  return selectCode(account, state.offsetMs);
}

function updateRow(id, status) {
  const ref = state.refs.get(id);
  if (!ref) return;

  const text = formatCode(status.code);
  if (ref.code.textContent !== text) ref.code.textContent = text;

  const ratio = Math.max(0, Math.min(1, status.remaining / status.period));
  ref.fill.style.width = `${(ratio * 100).toFixed(1)}%`;
  ref.fill.classList.toggle('warn', status.remaining <= 5);

  const secondsText = `${Math.ceil(status.remaining)}s`;
  if (ref.seconds.textContent !== secondsText) ref.seconds.textContent = secondsText;

  ref.row.classList.toggle('stale', status.stale);
}

function tick() {
  let stale = false;

  for (const account of state.accounts) {
    const status = codeState(account);
    updateRow(account.id, status);
    if (status.stale) stale = true;
  }

  if (!stale) {
    state.staleNotified = false;
    return;
  }

  if (state.staleNotified) return;
  state.staleNotified = true;

  if (Date.now() - state.autoRefreshAt < 5000) return;
  state.autoRefreshAt = Date.now();
  maybeAutoRefresh();
}

function startTicker() {
  if (state.ticker) return;
  state.ticker = setInterval(tick, 1000);
  tick();
}

function stopTicker() {
  if (!state.ticker) return;
  clearInterval(state.ticker);
  state.ticker = null;
}

function showStaleBanner() {
  setBanner('验证码已过期，请刷新重新读取', 'refresh', '刷新');
}

async function maybeAutoRefresh() {
  if (state.refreshing) return;

  // 令牌模式不依赖站点标签页，直接静默刷新即可
  if (state.token) {
    refreshAll({ silent: true });
    return;
  }

  if (!ext || !ext.tabs || typeof ext.tabs.query !== 'function') {
    showStaleBanner();
    return;
  }

  try {
    const tabs = await ext.tabs.query({
      url: globalThis.FWShared.tabPattern(state.host),
    });
    if ((tabs || []).some((tab) => tab && !tab.discarded)) {
      refreshAll({ silent: true });
    } else {
      showStaleBanner();
    }
  } catch {
    showStaleBanner();
  }
}

/* ---------------------------------------------------------------------------
 * 数据加载
 * ------------------------------------------------------------------------- */

function applyCache(cache) {
  state.accounts = (cache.accounts || []).filter((account) => account && account.id != null);
  state.fetchedAt = cache.fetchedAt || Date.now();

  const sample = state.accounts.find(
    (account) => typeof account.generated_at === 'number'
  );
  state.offsetMs = sample ? sample.generated_at * 1000 - Date.now() : 0;

  state.staleNotified = false;
  recomputeSiteMatches();
  setBanner('', null);
  setLoading(false);
  updateHeader();
  renderGroups();
  renderAccounts();
  startTicker();
}

function handleFetchError(error) {
  const message = describeError(error);

  if (error instanceof ApiError && error.status === 401) {
    if (state.token) {
      setBanner('设备令牌已过期或被吊销', 'authorize', '重新授权');
    } else {
      setBanner('未登录站点或登录已过期', 'login', '打开站点登录');
    }
  } else {
    setBanner(message, 'retry', '重试');
  }

  if (state.accounts.length === 0) {
    setEmpty('无法读取验证码', message);
    els.footerCount.textContent = '';
  }
}

async function refreshAll(options = {}) {
  if (!state.host || state.refreshing) return;

  const initial = Boolean(options.initial);
  const silent = Boolean(options.silent);

  state.refreshing = true;
  els.refreshBtn.classList.add('spinning');

  if (!silent) setBanner('', null);
  if (initial || state.accounts.length === 0) {
    setLoading(true, state.token ? '正在通过设备令牌读取验证码…' : '正在通过站点读取验证码…');
  }

  try {
    const data = await fetchFromSite(state.host, { token: state.token });
    const cache = {
      host: state.host,
      mode: state.token ? 'token' : 'session',
      fetchedAt: Date.now(),
      accounts: data.accounts,
    };

    await sessionStore.set({ [CACHE_KEY]: cache });

    // 令牌模式下服务端会回传滑动续期后的有效期
    if (state.token && data.token && data.token.expiresAt) {
      state.tokenMeta = {
        ...(state.tokenMeta || {}),
        label: data.token.label || (state.tokenMeta && state.tokenMeta.label) || '',
        expiresAt: data.token.expiresAt,
        lastVerifiedAt: Date.now(),
      };
      await localStore.set({ [TOKEN_META_KEY]: state.tokenMeta });
    }

    // 账户元数据落到 local，浏览器重启后可先渲染骨架
    await localStore.set({
      fw_accounts_meta: data.accounts.map((account) => ({
        id: account.id,
        service: account.service,
        account: account.account,
        category: account.category || '',
        period: account.period,
        digits: account.digits,
      })),
    });

    applyCache(cache);

    if (state.accounts.length === 0) {
      setEmpty('站点还没有账户', '请先在网页版添加 TOTP 账户');
    }
  } catch (error) {
    handleFetchError(error);
  } finally {
    state.refreshing = false;
    els.refreshBtn.classList.remove('spinning');
    setLoading(false);
  }
}

/* ---------------------------------------------------------------------------
 * 交互
 * ------------------------------------------------------------------------- */

function setConnecting(connecting) {
  els.connectBtn.disabled = connecting;
  els.connectLabel.textContent = connecting ? '正在连接…' : '连接';
  els.connectSpinner.hidden = !connecting;
}

function renderTokenState() {
  if (!els.tokenState) return;

  const token = state.token || '';

  if (!token) {
    els.tokenState.hidden = true;
    els.tokenState.textContent = '';
    return;
  }

  const meta = state.tokenMeta || {};
  const parts = ['已配置设备令牌'];

  if (meta.label) parts.push(meta.label);
  if (meta.expiresAt) {
    const days = Math.max(0, Math.ceil((meta.expiresAt - Date.now()) / (24 * 60 * 60 * 1000)));
    parts.push(`有效至 ${formatDate(meta.expiresAt)}（约 ${days} 天）`);
  }

  els.tokenState.textContent = parts.join(' · ');
  els.tokenState.hidden = false;
  els.tokenState.classList.remove('is-error');
}

function setTokenStateError(message) {
  if (!els.tokenState) return;
  els.tokenState.textContent = message || '';
  els.tokenState.hidden = !message;
  els.tokenState.classList.toggle('is-error', Boolean(message));
}

async function handleConnect() {
  const host = normalizeHost(els.hostInput.value);
  const rawToken = String(els.tokenInput.value || '').trim();

  if (!host) {
    setSetupError('请输入有效的站点地址，例如 https://2fa.example.com');
    return;
  }

  if (rawToken && !isTokenShape(rawToken)) {
    setSetupError('设备令牌格式不正确，应以 fw_ 开头');
    return;
  }

  // 令牌依赖 Bearer 直连，非 HTTPS（且非 localhost）时明确拒绝，避免静默回退
  if (rawToken && !globalThis.FWShared.tokenSupported(host)) {
    setSetupError(
      '该站点不是 HTTPS（也非 localhost），设备令牌不可用。请为站点启用 HTTPS，或清空令牌改用站点会话模式。'
    );
    return;
  }

  setSetupError('');
  els.openLoginBtn.hidden = true;
  els.authorizeBtn.hidden = true;
  setTokenStateError('');
  setConnecting(true);

  try {
    // 先用待保存的配置实测一次，成功后才落盘，避免写入无效令牌
    const data = await fetchFromSite(host, { token: rawToken });

    state.host = host;
    state.token = rawToken;
    state.pendingHost = '';
    state.pendingToken = '';
    state.siteInitialized = false;
    state.currentHost = await getActiveHostname();

    if (rawToken) {
      const tokenInfo = data.token || {};
      state.tokenMeta = {
        label: tokenInfo.label || '',
        expiresAt: tokenInfo.expiresAt || Date.now() + 30 * 24 * 60 * 60 * 1000,
        lastVerifiedAt: Date.now(),
      };
    } else {
      state.tokenMeta = null;
    }

    await localStore.set({ [HOST_KEY]: host, [TOKEN_KEY]: rawToken });
    if (state.tokenMeta) await localStore.set({ [TOKEN_META_KEY]: state.tokenMeta });
    else await localStore.remove([TOKEN_META_KEY]);

    await localStore.set({
      fw_accounts_meta: data.accounts.map((account) => ({
        id: account.id,
        service: account.service,
        account: account.account,
        category: account.category || '',
        period: account.period,
        digits: account.digits,
      })),
    });

    els.tokenInput.value = rawToken;
    renderTokenState();

    const cache = {
      host,
      mode: rawToken ? 'token' : 'session',
      fetchedAt: Date.now(),
      accounts: data.accounts,
    };
    await sessionStore.set({ [CACHE_KEY]: cache });

    applyCache(cache);
    showView('accounts');

    els.cancelBtn.hidden = false;
    els.disconnectBtn.hidden = false;

    if (state.accounts.length === 0) {
      setEmpty('站点还没有账户', '请先在网页版添加 TOTP 账户');
    }
  } catch (error) {
    state.pendingHost = host;
    state.pendingToken = rawToken;
    setSetupError(describeError(error));

    const unauthorized = error instanceof ApiError && error.status === 401;
    const notFound = error instanceof ApiError && error.status === 404;

    if (unauthorized && rawToken) {
      setTokenStateError('令牌无效或已吊销，请到站点重新授权');
      els.authorizeBtn.hidden = false;
    } else if (unauthorized) {
      els.openLoginBtn.hidden = false;
      els.authorizeBtn.hidden = false;
    } else if (notFound && rawToken) {
      setTokenStateError('站点尚未启用扩展接口，请先更新站点');
    } else {
      els.openLoginBtn.hidden = !unauthorized;
    }

    els.cancelBtn.hidden = !state.host;
    els.disconnectBtn.hidden = !state.host;
  } finally {
    setConnecting(false);
  }
}

async function handleDisconnect() {
  await localStore.remove([
    HOST_KEY,
    TOKEN_KEY,
    TOKEN_META_KEY,
    'fw_pending_bind',
    'fw_accounts_meta',
  ]);
  await sessionStore.remove([CACHE_KEY]);

  hideBindConfirm();

  state.host = '';
  state.token = '';
  state.tokenMeta = null;
  state.pendingBind = null;
  state.pendingHost = '';
  state.pendingToken = '';
  state.accounts = [];
  state.fetchedAt = 0;
  state.offsetMs = 0;
  state.activeGroup = '__all__';
  state.search = '';
  state.currentHost = '';
  state.siteMatches = [];
  state.siteMatchIds = new Set();
  state.siteInitialized = false;
  state.refs.clear();
  state.bannerAction = null;

  els.hostInput.value = '';
  els.tokenInput.value = '';
  els.searchInput.value = '';
  els.clearSearch.hidden = true;
  els.cancelBtn.hidden = true;
  els.disconnectBtn.hidden = true;
  els.openLoginBtn.hidden = true;
  els.authorizeBtn.hidden = true;
  setSetupError('');
  setTokenStateError('');
  setBanner('', null);
  showView('setup');
  showToast('已清除本地配置与验证码缓存');
}

function openSettings() {
  els.hostInput.value = state.host;
  els.tokenInput.value = state.token;
  state.pendingHost = '';
  state.pendingToken = '';
  els.openLoginBtn.hidden = true;
  els.authorizeBtn.hidden = Boolean(state.token);
  els.cancelBtn.hidden = !state.host;
  els.disconnectBtn.hidden = !state.host;
  setSetupError('');
  renderTokenState();
  showView('setup');
}

function openWeb() {
  if (state.host) openSite(state.host);
}

function showToast(message, isError) {
  els.toast.textContent = message;
  els.toast.classList.toggle('error', Boolean(isError));
  els.toast.hidden = false;
  requestAnimationFrame(() => els.toast.classList.add('show'));

  if (state.toastTimer) clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(hideToast, 1800);
}

function hideToast() {
  if (state.toastTimer) {
    clearTimeout(state.toastTimer);
    state.toastTimer = null;
  }
  els.toast.classList.remove('show');
  setTimeout(() => {
    if (!els.toast.classList.contains('show')) els.toast.hidden = true;
  }, 200);
}

async function copyText(text) {
  if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      /* 某些环境会拒绝 Clipboard API，继续使用回退方案 */
    }
  }

  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.top = '0';
  area.style.left = '0';
  area.style.opacity = '0';
  document.body.append(area);
  area.focus();
  area.select();
  area.setSelectionRange(0, area.value.length);

  let ok = false;
  try {
    ok = document.execCommand('copy');
  } finally {
    area.remove();
  }
  if (!ok) throw new Error('copy_failed');
}

async function copyAccountCode(id, row) {
  const account = state.accounts.find((item) => String(item.id) === String(id));
  if (!account) return;

  const status = codeState(account);
  if (!status.code) {
    showToast('验证码尚未就绪', true);
    return;
  }

  try {
    await copyText(String(status.code).replace(/\s+/g, ''));
    showToast('已复制验证码');
    row.classList.add('copied');
    setTimeout(() => row.classList.remove('copied'), 650);
  } catch {
    showToast('复制失败，请手动选择', true);
  }
}

/* ---------------------------------------------------------------------------
 * 事件绑定与启动
 * ------------------------------------------------------------------------- */

function bindEvents() {
  els.bindConfirmBtn.addEventListener('click', handleBindConfirm);
  els.bindRejectBtn.addEventListener('click', handleBindReject);

  els.setupForm.addEventListener('submit', (event) => {
    event.preventDefault();
    handleConnect();
  });

  els.openLoginBtn.addEventListener('click', () => {
    openSite(state.pendingHost || state.host);
  });

  els.authorizeBtn.addEventListener('click', () => {
    const target = authorizeUrl(state.pendingHost || state.host);
    if (target) openSite(target);
  });

  els.cancelBtn.addEventListener('click', () => {
    if (state.host) {
      showView('accounts');
      setSetupError('');
      els.openLoginBtn.hidden = true;
      els.authorizeBtn.hidden = true;
    }
  });

  els.disconnectBtn.addEventListener('click', handleDisconnect);

  els.refreshBtn.addEventListener('click', () => {
    refreshAll({ initial: state.accounts.length === 0 });
  });

  els.settingsBtn.addEventListener('click', openSettings);

  els.retryBtn.addEventListener('click', () => {
    if (state.bannerAction === 'login') openSite(state.host);
    else if (state.bannerAction === 'authorize') openSite(authorizeUrl(state.host));
    else refreshAll({ initial: state.accounts.length === 0 });
  });

  els.searchInput.addEventListener('input', () => {
    state.search = els.searchInput.value;
    els.clearSearch.hidden = state.search.length === 0;
    renderAccounts();
  });

  els.clearSearch.addEventListener('click', () => {
    els.searchInput.value = '';
    state.search = '';
    els.clearSearch.hidden = true;
    els.searchInput.focus();
    renderAccounts();
  });

  els.accountList.addEventListener('click', (event) => {
    const row = event.target.closest('.account');
    if (!row) return;
    copyAccountCode(row.dataset.id, row);
  });

  els.openWebBtn.addEventListener('click', openWeb);

  document.addEventListener('keydown', (event) => {
    if (
      event.key === 'Escape' &&
      !els.accountsView.hidden &&
      document.activeElement === els.searchInput &&
      els.searchInput.value
    ) {
      els.searchInput.value = '';
      state.search = '';
      els.clearSearch.hidden = true;
      renderAccounts();
    }

    if (
      event.key === '/' &&
      !els.accountsView.hidden &&
      document.activeElement !== els.searchInput
    ) {
      event.preventDefault();
      els.searchInput.focus();
    }
  });
}

async function init() {
  bindEvents();

  // 注意：fw_token 在 1.3.0 起改用于设备令牌，不再作为旧版 PAT 清理
  try {
    await localStore.remove(['fw_pat', 'fw_api_token']);
  } catch {
    /* ignore */
  }

  // 站点页面发来的待确认绑定优先展示，用户确认域名后才生效
  const pendingStored = await localStore.get(['fw_pending_bind']);
  const pending = pendingStored && pendingStored.fw_pending_bind;

  if (pending && pending.host) {
    showBindConfirm(pending);
    return;
  }

  hideBindConfirm();

  const stored = await localStore.get([
    HOST_KEY,
    TOKEN_KEY,
    TOKEN_META_KEY,
    BINDINGS_KEY,
    'fw_accounts_meta',
  ]);
  state.bindings = stored[BINDINGS_KEY] || {};

  const host = normalizeHost(stored[HOST_KEY] || '');

  if (!host) {
    showView('setup');
    return;
  }

  state.host = host;
  state.token = stored[TOKEN_KEY] || '';
  state.tokenMeta = stored[TOKEN_META_KEY] || null;
  state.currentHost = await getActiveHostname();
  state.siteInitialized = false;

  // 浏览器重启后 session 缓存已清空：先用本地账户元数据渲染骨架，再静默刷码
  const meta = stored.fw_accounts_meta;

  const cache = await sessionStore.get(CACHE_KEY);

  if (cache && cache.host === host && Array.isArray(cache.accounts)) {
    showView('accounts');
    applyCache(cache);
    return;
  }

  showView('accounts');

  if (Array.isArray(meta) && meta.length > 0 && state.token) {
    // 令牌模式可以立即取码，先渲染已知账户避免空白
    const skeleton = meta.map((item) => ({
      ...item,
      generated_at: Math.floor(Date.now() / 1000),
      code: '',
      next_code: '',
    }));

    state.accounts = skeleton;
    state.fetchedAt = 0;
    state.offsetMs = 0;
    recomputeSiteMatches();
    updateHeader();
    renderGroups();
    renderAccounts();

    await refreshAll({ initial: false, silent: true });
    return;
  }

  setLoading(true, state.token ? '正在通过设备令牌读取验证码…' : '正在通过站点读取验证码…');
  await refreshAll({ initial: true });
}

init();
