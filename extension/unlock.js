'use strict';

/* ---------------------------------------------------------------------------
 * 系统安全锁（WebAuthn 平台认证器）
 *
 * - 验证宿主必须是独立标签页：popup 失焦即自毁，而系统弹窗必然抢焦点
 * - rpId = chrome.runtime.id（Chrome 对扩展 origin 的特殊处理），凭证
 *   绑定在扩展自身，与站点无关
 * - 解锁状态写 chrome.storage.session（浏览器重启自动回锁）
 * - assertion 用注册时保存的 ES256 公钥做真实签名校验，不做形式校验
 * ------------------------------------------------------------------------- */

const ext = globalThis.browser ?? globalThis.chrome;

const CRED_KEY = 'fw_lock_cred';
const UNLOCK_KEY = 'fw_unlock';
const LOCK_ENABLED_KEY = 'fw_lock_enabled';

const els = {
  title: document.getElementById('title'),
  desc: document.getElementById('desc'),
  action: document.getElementById('action-btn'),
  status: document.getElementById('status'),
};

function setStatus(message, kind) {
  els.status.textContent = message || '';
  els.status.className = 'unlock-status' + (kind ? ` is-${kind}` : '');
}

function randomBytes(length) {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

function b64encode(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
  return btoa(binary);
}

function b64decode(text) {
  const binary = atob(String(text || ''));
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) out[index] = binary.charCodeAt(index);
  return out;
}

/** COSE ES256 公钥（authenticator 输出格式）转可 importKey 的 JWK */
function coseToJwk(cosePublicKey) {
  // COSE key: [kty(3), alg(-7), crv(1), x(-2), y(-3)]
  const kty = cosePublicKey.get(3);
  if (kty !== 2) throw new Error('unsupported_cose_kty');

  const x = cosePublicKey.get(-2);
  const y = cosePublicKey.get(-3);

  const toB64 = (u8) => {
    let binary = '';
    for (let i = 0; i < u8.length; i += 1) binary += String.fromCharCode(u8[i]);
    return btoa(binary);
  };

  return {
    kty: 'EC',
    crv: 'P-256',
    x: toB64(x),
    y: toB64(y),
  };
}

/**
 * 校验 assertion 签名：ES256 对 authenticatorData + SHA-256(clientDataJSON)
 * - 检查 clientData 的 challenge 与本次随机数一致、type 正确
 * - 检查 authenticatorData 的 UV（用户已验证）标志位
 * - 用注册时保存的公钥验签
 */
async function verifyAssertion(assertion, stored, challenge) {
  const response = assertion.response;
  if (!response || !assertion.id) return false;

  // 1. clientData：type + challenge + origin 必须匹配
  let clientData;
  try {
    clientData = JSON.parse(new TextDecoder().decode(response.clientDataJSON));
  } catch {
    return false;
  }

  if (clientData.type !== 'webauthn.get') return false;
  // 浏览器把 challenge 编码为 base64url；比较时统一格式
  const expectedChallenge = b64encode(challenge)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  if (clientData.challenge !== expectedChallenge) return false;
  if (String(clientData.origin || '') !== globalThis.location.origin) return false;

  // 2. allowCredentials 与注册凭证一致（rawId 在 assertion 顶层，response 里没有）
  const credId = b64encode(assertion.rawId || new Uint8Array(0));
  if (credId !== stored.credIdB64) return false;

  // 3. authenticatorData：UP + UV 标志
  const authData = new Uint8Array(response.authenticatorData);
  if (authData.length < 37) return false;
  const flags = authData[32];
  const userPresent = (flags & 0x01) !== 0;
  const userVerified = (flags & 0x04) !== 0;
  if (!userPresent || !userVerified) return false;

  // 4. 验签
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new Uint8Array(response.clientDataJSON))
  );

  const signed = new Uint8Array(authData.length + clientDataHash.length);
  signed.set(authData, 0);
  signed.set(clientDataHash, authData.length);

  const key = await crypto.subtle.importKey(
    'jwk',
    stored.jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );

  return await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new Uint8Array(response.signature),
    signed
  );
}

async function readStoredCredential() {
  try {
    const stored = await ext.storage.local.get(CRED_KEY);
    const cred = stored ? stored[CRED_KEY] : null;
    if (!cred || !cred.credIdB64 || !cred.jwk) return null;
    return cred;
  } catch {
    return null;
  }
}

/** 注册平台凭证；返回 {ok, reason?} */
async function enroll() {
  const userId = randomBytes(16);

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      // rp.id 省略 → 默认当前 origin（chrome-extension://<id>），
      // Firefox 兼容这种写法（其验证走站点标准路径，能力不可用则根本进不来）
      rp: { name: '2FAuth Worker' },
      user: {
        id: userId,
        name: '2fauth-user',
        displayName: '2FAuth Worker 扩展锁',
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'preferred',
      },
      timeout: 60000,
      attestation: 'none',
    },
  });

  if (!credential) return { ok: false, reason: 'no_credential' };

  const response = credential.response;
  const attObj = new Uint8Array(response.attestationObject);

  // attestationObject 是 CBOR：{fmt, attStmt, authData}；定位 authData（bytes）
  const authData = parseAuthDataFromAttestation(attObj);
  if (!authData) return { ok: false, reason: 'bad_attestation' };

  const coseStart = findCoseKey(authData);
  if (!coseStart) return { ok: false, reason: 'no_public_key' };

  // 最小 COSE map 解析（ES256: {1:2, 3:-7, 1:6(P-256), -2:x, -3:y}）
  const cose = parseCoseMap(authData.subarray(coseStart));
  if (!cose) return { ok: false, reason: 'bad_cose' };

  const jwk = coseToJwk(cose);

  await ext.storage.local.set({
    [CRED_KEY]: {
      // rawId 在 credential 顶层（与 assertion 相同），getBoundingClientRect
      // 类接口不存在于 response 上
      credIdB64: b64encode(credential.rawId),
      jwk,
      createdAt: Date.now(),
    },
    [LOCK_ENABLED_KEY]: true,
  });

  // 注册即通过了一次系统验证，本次会话直接视为已解锁
  await ext.storage.session.set({ [UNLOCK_KEY]: { at: Date.now() } });

  return { ok: true };
}

/**
 * 从 attestationObject CBOR 中定位 authData（bytes）。
 * 顶层 map(5)：跳过 fmt/attStmt 的复杂结构，直接搜 "authData" 文本键
 * 后面的 bytes 头（0x58/0x59/0x5a）。这是对该固定格式的务实解析。
 */
function parseAuthDataFromAttestation(attObj) {
  return findAuthDataBytes(attObj);
}

function findAuthDataBytes(attObj) {
  // "authData" = 0x68 + "authData" 8 字节；其值是 bytes(bstr)：0x58/0x59/0x5a
  const marker = [0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61]; // "authData"
  for (let i = 0; i < attObj.length - marker.length - 1; i += 1) {
    let match = true;
    for (let j = 0; j < marker.length; j += 1) {
      if (attObj[i + j] !== marker[j]) { match = false; break; }
    }
    if (!match) continue;

    let p = i + marker.length;
    const head = attObj[p];
    if (head === 0x58) {
      const len = attObj[p + 1];
      return attObj.subarray(p + 2, p + 2 + len);
    }
    if (head === 0x59) {
      const len = (attObj[p + 1] << 8) | attObj[p + 2];
      return attObj.subarray(p + 3, p + 3 + len);
    }
    if (head === 0x5a) {
      const len =
        (attObj[p + 1] * 16777216) + ((attObj[p + 2] << 16) | (attObj[p + 3] << 8)) + attObj[p + 4];
      return attObj.subarray(p + 5, p + 5 + len);
    }
  }
  return null;
}

/** 在 authenticatorData 末段定位 COSE 公钥（AT 标志位的 attestedCredentialData） */
function findCoseKey(authData) {
  if (authData.length < 37) return null;
  const flags = authData[32];
  if ((flags & 0x40) === 0) return null; // 无 attested credential data

  // rpIdHash(32) + flags(1) + signCount(4) = 37
  // AAGUID(16) + credIdLen(2) + credId + COSE
  let pos = 37 + 16;
  if (pos + 2 > authData.length) return null;
  const credIdLen = (authData[pos] << 8) | authData[pos + 1];
  pos += 2 + credIdLen;
  if (pos >= authData.length) return null;
  return pos;
}

/** 解析 COSE 限定为 Map(5)，ES256 固定布局 */
function parseCoseMap(bytes) {
  // {1:2, 3:-7, -1:6, -2:x(32), -3:y(32)}
  // 编码：0xa5 | 01 02 | 03 26 | 20 06 | 21 58 20 <x> | 22 58 20 <y>
  if (bytes[0] !== 0xa5) return null;
  let pos = 1;
  const map = new Map();

  for (let pair = 0; pair < 5; pair += 1) {
    if (pos >= bytes.length) return null;

    // key：小的正整数 0x01/0x03 或负整数 0x20+n
    let key;
    const kHead = bytes[pos];
    if (kHead <= 0x17) { key = kHead; pos += 1; }
    else if (kHead >= 0x20 && kHead <= 0x37) { key = -(kHead - 0x20) - 1; pos += 1; }
    else return null;

    // value
    const vHead = bytes[pos];
    if (vHead <= 0x17) { map.set(key, vHead); pos += 1; }
    else if (vHead === 0x58) {
      const len = bytes[pos + 1];
      map.set(key, bytes.subarray(pos + 2, pos + 2 + len));
      pos += 2 + len;
    } else if (vHead >= 0x20 && vHead <= 0x37) {
      map.set(key, -(vHead - 0x20) - 1);
      pos += 1;
    } else return null;
  }

  // ES256 必需字段
  if (map.get(1) !== 2) return null;        // kty: EC2
  if (map.get(3) !== -7) return null;       // alg: ES256
  if (map.get(-1) !== 6) return null;       // crv: P-256
  if (!map.get(-2) || !map.get(-3)) return null;

  return map;
}

/** 验证：challenge 随机 → get() → 签名校验 → session 标记解锁 */
async function unlock(stored) {
  const challenge = randomBytes(32);

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      // rpId 省略 → 默认当前 origin；扩展 origin 下 Chrome 会改写为扩展 ID
      allowCredentials: [{ type: 'public-key', id: b64decode(stored.credIdB64) }],
      userVerification: 'required',
      timeout: 60000,
    },
  });

  if (!assertion) return { ok: false, reason: 'cancelled' };

  const valid = await verifyAssertion(assertion, stored, challenge);
  if (!valid) return { ok: false, reason: 'bad_signature' };

  await ext.storage.session.set({ [UNLOCK_KEY]: { at: Date.now() } });
  return { ok: true };
}

async function closeTab() {
  try {
    const tab = await ext.tabs.getCurrent();
    if (tab && tab.id != null) {
      await ext.tabs.remove(tab.id);
      return;
    }
  } catch {
    /* 非 tab 环境忽略 */
  }
  globalThis.close();
}

async function run() {
  const mode = new URLSearchParams(globalThis.location.search).get('mode');

  if (mode === 'enroll') {
    els.title.textContent = '设置系统安全锁';
    els.desc.textContent = '请在系统弹窗中完成 Windows Hello / Touch ID 注册。';
    setStatus('等待系统验证…', '');

    const result = await enroll();
    if (result.ok) {
      setStatus('安全锁已启用', 'ok');
      setTimeout(closeTab, 900);
    } else {
      setStatus(`注册失败（${result.reason}），可重试`, 'error');
      els.action.hidden = false;
      els.action.textContent = '重试注册';
      els.action.addEventListener('click', () => globalThis.location.reload(), { once: true });
    }
    return;
  }

  // 解锁模式
  const stored = await readStoredCredential();
  if (!stored) {
    // 无凭证：视为未启用锁，直接放行并关闭
    await ext.storage.session.set({ [UNLOCK_KEY]: { at: Date.now() } });
    setStatus('安全锁未配置', 'ok');
    setTimeout(closeTab, 600);
    return;
  }

  setStatus('等待系统验证…', '');

  let result;
  try {
    result = await unlock(stored);
  } catch (error) {
    const name = error && error.name ? error.name : '';
    if (name === 'NotAllowedError') {
      // 用户取消，或 unpacked 扩展换目录导致凭证失效（ID 变了）
      setStatus('验证被取消或凭证已失效', 'error');
      els.action.hidden = false;
      els.action.textContent = '重新验证';
      els.action.addEventListener('click', () => globalThis.location.reload(), { once: true });
      els.action.focus();
      return;
    }
    setStatus(`验证失败：${name || (error && error.message) || 'unknown'}`, 'error');
    els.action.hidden = false;
    els.action.textContent = '重试';
    els.action.addEventListener('click', () => globalThis.location.reload(), { once: true });
    return;
  }

  if (result.ok) {
    setStatus('已解锁，正在关闭…', 'ok');
    setTimeout(closeTab, 400);
  } else if (result.reason === 'bad_signature') {
    // 签名不通过：凭证被替换/环境异常，视为不通过
    setStatus('验证未通过', 'error');
    els.action.hidden = false;
    els.action.textContent = '重试';
    els.action.addEventListener('click', () => globalThis.location.reload(), { once: true });
  } else {
    setStatus('已取消验证', 'error');
    els.action.hidden = false;
    els.action.textContent = '重试';
    els.action.addEventListener('click', () => globalThis.location.reload(), { once: true });
  }
}

run();
