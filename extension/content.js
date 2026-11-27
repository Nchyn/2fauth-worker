'use strict';

/* ---------------------------------------------------------------------------
 * 内容脚本：在 OTP 输入框聚焦时显示 2FAuth 验证码面板
 * - 识别 OTP 字段（autocomplete=one-time-code / 关键词 / 数字输入框 + 标签）
 * - 向后台请求当前站点匹配的验证码
 * - 用户点击后才填入，不会自动填写
 * - 使用 Shadow DOM 隔离页面样式
 * ------------------------------------------------------------------------- */

(() => {
  if (window.top !== window) return;

  const runtime = globalThis.browser?.runtime ?? globalThis.chrome?.runtime;
  if (!runtime || typeof runtime.sendMessage !== 'function') return;

  const isFirefox = Boolean(globalThis.browser && globalThis.browser.runtime);

  const HOST_ID = 'fw-otp-panel-host';
  const PANEL_WIDTH = 300;

  const FIELD_PATTERN =
    /(otp|totp|one[\s_-]?time|two[\s_-]?factor|2fa|mfa|verification[\s_-]?code|verif(y|ication)[\s_-]?code|security[\s_-]?code|auth(entication)?[\s_-]?code|验证码|动态码|安全码|双重验证|两步验证)/i;

  let host = null;
  let shadow = null;
  let panel = null;
  let hostLabel = null;
  let activeInput = null;
  let showAll = false;
  let requestToken = 0;
  let countdownTimer = null;
  let countdowns = [];
  let lastRefreshAt = 0;

  /* -------------------------------------------------------------------------
   * 样式
   * ----------------------------------------------------------------------- */

  const STYLES = `
    :host { all: initial; }
    * { box-sizing: border-box; }

    .panel {
      width: ${PANEL_WIDTH}px;
      max-width: calc(100vw - 16px);
      background: #ffffff;
      color: #1b1f27;
      border: 1px solid rgba(17, 24, 39, 0.1);
      border-radius: 12px;
      box-shadow: 0 12px 32px rgba(15, 23, 42, 0.18);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
        "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
      font-size: 12px;
      line-height: 1.4;
      overflow: hidden;
      position: relative;
    }

    .head {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 8px 10px;
      border-bottom: 1px solid rgba(17, 24, 39, 0.07);
    }

    .logo {
      width: 18px;
      height: 18px;
      border-radius: 5px;
      background: #4f6ef7;
      color: #fff;
      font-size: 9px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
      flex: 0 0 auto;
    }

    .title {
      font-size: 11.5px;
      font-weight: 650;
      flex: 0 0 auto;
    }

    .host {
      flex: 1 1 auto;
      min-width: 0;
      font-size: 10px;
      color: #6b7280;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      text-align: right;
    }

    .close {
      flex: 0 0 auto;
      width: 20px;
      height: 20px;
      border: 0;
      border-radius: 5px;
      background: transparent;
      color: #9aa1ad;
      font-size: 15px;
      line-height: 1;
      cursor: pointer;
      padding: 0;
    }

    .close:hover { background: #eef1f8; color: #1b1f27; }

    .body { max-height: 232px; overflow-y: auto; }

    .body::-webkit-scrollbar { width: 7px; }
    .body::-webkit-scrollbar-thumb {
      background: rgba(17, 24, 39, 0.15);
      border-radius: 6px;
    }

    .row {
      display: flex;
      align-items: center;
      gap: 8px;
      width: 100%;
      padding: 8px 10px;
      border: 0;
      border-bottom: 1px solid rgba(17, 24, 39, 0.05);
      background: transparent;
      color: inherit;
      text-align: left;
      font: inherit;
      cursor: pointer;
    }

    .row:last-child { border-bottom: 0; }
    .row:hover { background: #f4f6fb; }
    .row:focus-visible { outline: 2px solid #4f6ef7; outline-offset: -2px; }

    .avatar {
      width: 26px;
      height: 26px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 11px;
      font-weight: 700;
      flex: 0 0 auto;
      background: hsl(var(--h, 220) 70% 52% / 0.14);
      color: hsl(var(--h, 220) 62% 42%);
    }

    .meta {
      flex: 1 1 auto;
      min-width: 0;
      display: flex;
      flex-direction: column;
    }

    .service {
      font-size: 12px;
      font-weight: 600;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .account {
      margin-top: 1px;
      font-size: 10px;
      color: #6b7280;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .otp {
      flex: 0 0 auto;
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 2px;
    }

    .code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 14px;
      font-weight: 700;
      letter-spacing: 0.5px;
      font-variant-numeric: tabular-nums;
    }

    .sec {
      font-size: 9px;
      color: #9aa1ad;
      font-variant-numeric: tabular-nums;
    }

    .empty {
      padding: 14px 12px;
      text-align: center;
      color: #6b7280;
      font-size: 11.5px;
      line-height: 1.55;
    }

    .empty-text { margin-bottom: 2px; }

    .actions {
      display: flex;
      justify-content: center;
      gap: 6px;
      margin-top: 9px;
    }

    .btn {
      border: 1px solid rgba(17, 24, 39, 0.14);
      border-radius: 7px;
      background: #fff;
      color: #1b1f27;
      padding: 5px 10px;
      font-size: 11px;
      cursor: pointer;
    }

    .btn:hover { background: #eef1f8; }

    .btn.primary {
      background: #4f6ef7;
      border-color: #4f6ef7;
      color: #fff;
    }

    .btn.primary:hover { background: #3f5ce0; }

    .spinner {
      display: inline-block;
      width: 12px;
      height: 12px;
      margin-right: 6px;
      vertical-align: -2px;
      border: 2px solid rgba(79, 110, 247, 0.2);
      border-top-color: #4f6ef7;
      border-radius: 50%;
      animation: fwspin 0.8s linear infinite;
    }

    @keyframes fwspin { to { transform: rotate(360deg); } }

    .foot {
      padding: 6px 10px;
      border-top: 1px solid rgba(17, 24, 39, 0.06);
      color: #9aa1ad;
      font-size: 9.5px;
      text-align: center;
    }

    .filled {
      position: absolute;
      inset: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(255, 255, 255, 0.94);
      color: #16a34a;
      font-size: 13px;
      font-weight: 650;
      letter-spacing: 0.2px;
    }

    @media (prefers-color-scheme: dark) {
      .panel {
        background: #1d2027;
        color: #e9ecf2;
        border-color: rgba(255, 255, 255, 0.1);
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45);
      }
      .head { border-bottom-color: rgba(255, 255, 255, 0.08); }
      .host, .account, .sec, .empty { color: #9aa1ad; }
      .close { color: #767e8b; }
      .close:hover { background: #262a33; color: #e9ecf2; }
      .row { border-bottom-color: rgba(255, 255, 255, 0.06); }
      .row:hover { background: #262a33; }
      .avatar {
        background: hsl(var(--h, 220) 70% 60% / 0.18);
        color: hsl(var(--h, 220) 80% 74%);
      }
      .btn {
        background: #262a33;
        border-color: rgba(255, 255, 255, 0.14);
        color: #e9ecf2;
      }
      .btn:hover { background: #2f3440; }
      .btn.primary { background: #6b86ff; border-color: #6b86ff; color: #fff; }
      .btn.primary:hover { background: #7d94ff; }
      .foot { border-top-color: rgba(255, 255, 255, 0.07); }
      .filled { background: rgba(29, 32, 39, 0.95); color: #4ade80; }
    }

    @media (prefers-reduced-motion: reduce) {
      .spinner { animation-duration: 0.01ms; }
    }
  `;

  /* -------------------------------------------------------------------------
   * 工具
   * ----------------------------------------------------------------------- */

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function formatCode(code) {
    const compact = String(code == null ? '' : code).replace(/\s+/g, '');
    if (!compact) return '— — —';
    if (compact.length <= 4) return compact;
    const middle = Math.ceil(compact.length / 2);
    return compact.slice(0, middle) + ' ' + compact.slice(middle);
  }

  function initialOf(text) {
    const value = String(text || '').trim();
    return value ? Array.from(value)[0].toUpperCase() : '?';
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

  function isVisible(element) {
    if (!element || !element.isConnected) return false;
    const rect = element.getBoundingClientRect();
    if (rect.width < 8 || rect.height < 6) return false;
    const style = getComputedStyle(element);
    return style.visibility !== 'hidden' && style.display !== 'none';
  }

  function nearbyText(input) {
    let text = '';

    const label = input.closest('label');
    if (label) text += ' ' + label.innerText;

    const labelledBy = input.getAttribute('aria-labelledby');
    if (labelledBy) {
      for (const id of labelledBy.split(/\s+/)) {
        const node = document.getElementById(id);
        if (node) text += ' ' + node.innerText;
      }
    }

    if (!text && input.parentElement) {
      text = input.parentElement.innerText || '';
    }

    return text.slice(0, 160);
  }

  function isOtpField(input) {
    if (!(input instanceof HTMLInputElement)) return false;
    if (input.disabled || input.readOnly) return false;

    const type = (input.type || 'text').toLowerCase();
    if (['hidden', 'email', 'number', 'range', 'color', 'date', 'file'].includes(type)) {
      return false;
    }

    const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
    if (autocomplete.includes('one-time-code')) return true;

    const attrs = [
      input.name,
      input.id,
      input.placeholder,
      input.getAttribute('aria-label'),
      input.getAttribute('data-testid'),
      input.getAttribute('data-test'),
      input.className,
    ]
      .filter(Boolean)
      .join(' ');

    if (FIELD_PATTERN.test(attrs)) return true;

    const inputMode = (input.getAttribute('inputmode') || '').toLowerCase();
    const maxLength = Number(input.maxLength) || 0;

    if ((inputMode === 'numeric' || type === 'tel') && maxLength >= 6 && maxLength <= 8) {
      return FIELD_PATTERN.test(nearbyText(input));
    }

    return false;
  }

  /* -------------------------------------------------------------------------
   * 面板
   * ----------------------------------------------------------------------- */

  function ensureHost() {
    if (host && host.isConnected) return;

    host = document.createElement('div');
    host.id = HOST_ID;
    host.style.cssText =
      'all:initial;position:fixed;top:0;left:0;width:0;height:0;z-index:2147483647;';

    shadow = host.attachShadow({ mode: 'closed' });

    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(STYLES);
      shadow.adoptedStyleSheets = [sheet];
    } catch {
      const style = document.createElement('style');
      style.textContent = STYLES;
      shadow.append(style);
    }

    panel = el('div', 'panel');

    const head = el('div', 'head');
    const logo = el('span', 'logo', '2F');
    const title = el('span', 'title', '2FAuth');
    hostLabel = el('span', 'host', location.hostname);
    const close = el('button', 'close', '×');
    close.type = 'button';
    close.title = '关闭';
    close.setAttribute('aria-label', '关闭验证码面板');
    close.addEventListener('click', closePanel);

    head.append(logo, title, hostLabel, close);
    panel.append(head);

    const body = el('div', 'body');
    body.dataset.role = 'body';
    panel.append(body);

    panel.append(el('div', 'foot', '点击验证码填入 · 不会自动填写'));

    panel.addEventListener('mousedown', (event) => event.preventDefault(), true);

    shadow.append(panel);
    document.documentElement.append(host);
  }

  function bodyElement() {
    return panel ? panel.querySelector('[data-role="body"]') : null;
  }

  function setBody(node) {
    const body = bodyElement();
    if (!body) return;
    body.replaceChildren(node);
    schedulePosition();
  }

  function positionPanel() {
    if (!host || !panel || !activeInput || !activeInput.isConnected) return;

    const rect = activeInput.getBoundingClientRect();
    if (rect.bottom < 0 || rect.top > window.innerHeight) {
      closePanel();
      return;
    }

    panel.style.width = `${Math.min(PANEL_WIDTH, window.innerWidth - 16)}px`;

    const height = Math.min(panel.getBoundingClientRect().height || 240, 340);
    const margin = 8;

    let left = Math.min(
      Math.max(margin, rect.left),
      Math.max(margin, window.innerWidth - Math.min(PANEL_WIDTH, window.innerWidth - 16) - margin)
    );

    let top = rect.bottom + margin;
    if (top + height > window.innerHeight - margin) {
      top = Math.max(margin, rect.top - height - margin);
    }

    host.style.left = `${Math.round(left)}px`;
    host.style.top = `${Math.round(top)}px`;
  }

  let positionFrame = 0;
  function schedulePosition() {
    if (positionFrame) return;
    positionFrame = requestAnimationFrame(() => {
      positionFrame = 0;
      positionPanel();
    });
  }

  function renderLoading() {
    hostLabel.textContent = location.hostname;
    const box = el('div', 'empty');
    const spinner = el('span', 'spinner');
    box.append(spinner, document.createTextNode('读取验证码…'));
    setBody(box);
  }

  function renderError(code, mode) {
    hostLabel.textContent = location.hostname;

    const box = el('div', 'empty');
    let message = '无法读取验证码，请稍后重试';
    let action = null;

    if (code === 'not_configured') {
      message = '尚未配置 2FAuth 站点，请点击工具栏的扩展图标完成设置。';
    } else if (code === 'pending_bind') {
      message = '扩展有待确认的站点授权，请点击工具栏图标完成确认。';
    } else if (code === 'locked') {
      // 不带操作按钮：任何页面都可能触发本面板，避免钓鱼页面借「验证」诱导
      message = '扩展已锁定，请点击工具栏图标完成系统验证后取码。';
    } else if (code === 'unauthorized' && mode === 'token') {
      message = '扩展授权已过期或被吊销，请到站点重新授权。';
      action = { label: '去站点授权', run: () => sendOpenSite(true) };
    } else if (code === 'unauthorized') {
      message = '2FAuth 登录已过期，请打开站点重新登录。';
      action = { label: '打开站点登录', run: () => sendOpenSite() };
    } else if (code === 'no_host') {
      message = '无法识别当前站点。';
    } else {
      action = { label: '重试', run: () => loadCodes(showAll) };
    }

    box.append(el('div', 'empty-text', message));

    if (action) {
      const actions = el('div', 'actions');
      const button = el('button', 'btn primary', action.label);
      button.type = 'button';
      button.addEventListener('click', action.run);
      actions.append(button);
      box.append(actions);
    }

    setBody(box);
  }

  function renderNoMatches(total) {
    hostLabel.textContent = location.hostname;

    const box = el('div', 'empty');
    const message =
      showAll || total === 0
        ? '2FAuth 中还没有账户。'
        : '没有匹配当前站点的账户。';

    box.append(el('div', 'empty-text', message));

    if (total > 0 && !showAll) {
      const actions = el('div', 'actions');
      const button = el('button', 'btn primary', '显示全部账户');
      button.type = 'button';
      button.addEventListener('click', () => loadCodes(true));
      actions.append(button);
      box.append(actions);
    }

    setBody(box);
  }

  function renderAccounts(accounts) {
    hostLabel.textContent = showAll ? '全部账户' : location.hostname;

    const body = el('div', 'body');
    countdowns = [];

    for (const account of accounts) {
      const row = el('button', 'row');
      row.type = 'button';

      const avatar = el('span', 'avatar', initialOf(account.service || account.account));
      avatar.style.setProperty('--h', String(hashHue(account.service || account.account || '')));

      const meta = el('span', 'meta');
      meta.append(
        el('span', 'service', account.service || '未命名服务'),
        el('span', 'account', account.account || '')
      );

      const otp = el('span', 'otp');
      const code = el('span', 'code', formatCode(account.code));
      const sec = el('span', 'sec', `${Math.max(0, Number(account.remaining) || 0)}s`);
      otp.append(code, sec);

      row.append(avatar, meta, otp);

      row.addEventListener('click', () => fillField(activeInput, account.code));

      body.append(row);
      countdowns.push({
        element: sec,
        expiresAt: Date.now() + Math.max(0, Number(account.remaining) || 0) * 1000,
      });
    }

    setBody(body);

    if (countdownTimer) clearInterval(countdownTimer);
    countdownTimer = setInterval(() => {
      let expired = false;

      for (const item of countdowns) {
        const left = Math.max(0, Math.ceil((item.expiresAt - Date.now()) / 1000));
        item.element.textContent = `${left}s`;
        if (left <= 0) expired = true;
      }

      if (expired) {
        clearInterval(countdownTimer);
        countdownTimer = null;

        if (Date.now() - lastRefreshAt > 3000) {
          lastRefreshAt = Date.now();
          loadCodes(showAll, { silent: true });
        }
      }
    }, 1000);
  }

  async function loadCodes(all = false, options = {}) {
    if (!panel) return;

    const token = ++requestToken;
    showAll = Boolean(all);

    if (!options.silent) renderLoading();

    let response;
    try {
      response = await runtime.sendMessage({ type: 'fw:lookup', all: showAll });
    } catch {
      if (token === requestToken && panel) renderError('fetch_failed');
      return;
    }

    if (token !== requestToken || !panel) return;

    if (!response || response.ok !== true) {
      if (response && response.error === 'not_configured') {
        closePanel();
        return;
      }
      renderError(
        response ? response.error : 'fetch_failed',
        response ? response.mode : undefined
      );
      return;
    }

    if (!Array.isArray(response.accounts) || response.accounts.length === 0) {
      renderNoMatches(Number(response.total) || 0);
      return;
    }

    renderAccounts(response.accounts);
  }

  async function sendOpenSite(authorize) {
    try {
      await runtime.sendMessage({
        type: 'fw:open-site',
        ...(authorize ? { authorize: true } : {}),
      });
    } catch {
      /* ignore */
    }
  }

  function openFor(input) {
    if (!input || !input.isConnected) return;

    if (panel && activeInput === input) {
      schedulePosition();
      return;
    }

    activeInput = input;
    ensureHost();
    hostLabel.textContent = location.hostname;
    renderLoading();
    positionPanel();
    loadCodes(false);
  }

  function closePanel() {
    requestToken += 1;

    if (countdownTimer) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }

    countdowns = [];

    if (host) {
      host.remove();
    }

    host = null;
    shadow = null;
    panel = null;
    hostLabel = null;
    activeInput = null;
    showAll = false;
  }

  /* -------------------------------------------------------------------------
   * 填入
   * ----------------------------------------------------------------------- */

  function setInputValue(input, value) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function findOtpBoxes(input) {
    const scopes = [input.parentElement, input.parentElement?.parentElement].filter(Boolean);

    for (const scope of scopes) {
      const boxes = Array.from(scope.querySelectorAll('input')).filter(
        (element) =>
          element.maxLength === 1 && !element.disabled && !element.readOnly
      );

      if (boxes.length >= 4 && boxes.includes(input)) return boxes;
    }

    return [];
  }

  function fillField(input, code) {
    if (!input || !input.isConnected) {
      closePanel();
      return;
    }

    const value = String(code || '').replace(/\s+/g, '');
    if (!value) return;

    const boxes = findOtpBoxes(input);

    if (boxes.length >= 4 && boxes.length === value.length) {
      boxes.forEach((box, index) => setInputValue(box, value[index]));
      boxes[boxes.length - 1].focus();
    } else {
      setInputValue(input, value);
      input.focus();
    }

    if (panel) {
      const overlay = el('div', 'filled', '已填入 ✓');
      panel.append(overlay);
      setTimeout(closePanel, 650);
    }
  }

  /* -------------------------------------------------------------------------
   * 事件
   * ----------------------------------------------------------------------- */

  document.addEventListener(
    'focusin',
    (event) => {
      const path = event.composedPath();
      const target = path[0];

      if (
        target instanceof HTMLInputElement &&
        isOtpField(target) &&
        isVisible(target)
      ) {
        openFor(target);
        return;
      }

      if (host && !path.includes(host)) closePanel();
    },
    true
  );

  document.addEventListener(
    'mousedown',
    (event) => {
      if (!host) return;

      const path = event.composedPath();
      if (path.includes(host)) return;
      if (activeInput && path.includes(activeInput)) return;

      closePanel();
    },
    true
  );

  document.addEventListener(
    'keydown',
    (event) => {
      if (event.key === 'Escape' && host) {
        event.stopPropagation();
        closePanel();
      }
    },
    true
  );

  window.addEventListener('scroll', () => {
    if (host) schedulePosition();
  }, true);

  window.addEventListener('resize', () => {
    if (host) schedulePosition();
  });

  /* -------------------------------------------------------------------------
   * 站点授权桥：接收「发送到扩展」的设备令牌
   * - 只接受同源页面自身发出的消息（event.source === window）
   * - 交给后台校验并落盘，再把结果回传给页面
   * ----------------------------------------------------------------------- */
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;

    const data = event.data;
    if (!data || data.source !== 'fw-site' || data.type !== 'fw:token') return;

    const reply = (payload) => {
      window.postMessage(
        { source: 'fw-extension', type: 'fw:token-ack', ...payload },
        window.location.origin
      );
    };

    try {
      const payload = {
        type: 'fw:adopt-token',
        host: data.host || window.location.origin,
        token: data.token,
        expiresAt: data.expiresAt,
        label: data.label,
      };

      if (isFirefox) {
        // Firefox 的 browser.runtime 只支持 Promise 形式
        runtime
          .sendMessage(payload)
          .then((response) => reply(response || { ok: false, error: 'empty_response' }))
          .catch((error) => reply({ ok: false, error: String((error && error.message) || error) }));
        return;
      }

      runtime.sendMessage(payload, (response) => {
        if (runtime.lastError) {
          reply({ ok: false, error: String(runtime.lastError.message || '') });
          return;
        }
        reply(response || { ok: false, error: 'empty_response' });
      });
    } catch (error) {
      reply({ ok: false, error: String((error && error.message) || error) });
    }
  });
})();
