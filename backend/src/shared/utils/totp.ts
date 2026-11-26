import { sanitizeInput } from '@/shared/utils/common';

export function validateBase32Secret(secret: any): boolean {
    if (!secret || typeof secret !== 'string') return false;
    const cleaned = secret.replace(/\s/g, '').toUpperCase();
    return /^[A-Z2-7]+=*$/.test(cleaned) && cleaned.length >= 16;
}

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(encoded: string): Uint8Array {
    const cleanInput = encoded.toUpperCase().replace(/[^A-Z2-7]/g, '');
    const buffer = new Uint8Array(Math.floor(cleanInput.length * 5 / 8));
    let bits = 0, value = 0, index = 0;

    for (let i = 0; i < cleanInput.length; i++) {
        const charValue = BASE32_CHARS.indexOf(cleanInput[i]);
        if (charValue === -1) continue;
        value = (value << 5) | charValue;
        bits += 5;
        if (bits >= 8) {
            buffer[index++] = (value >>> (bits - 8)) & 255;
            bits -= 8;
        }
    }
    return buffer;
}

export async function hmacSHA1(key: Uint8Array | string, data: number): Promise<Uint8Array> {
    return await hmac(key, data, 'SHA-1');
}

/** 归一化 OTP 算法名到 WebCrypto 哈希名 */
function hashName(algorithm?: string): 'SHA-1' | 'SHA-256' | 'SHA-512' {
    const value = String(algorithm || 'SHA1').toUpperCase().replace(/[-_]/g, '');
    if (value === 'SHA256') return 'SHA-256';
    if (value === 'SHA512') return 'SHA-512';
    return 'SHA-1';
}

export async function hmac(
    key: Uint8Array | string,
    data: number,
    algorithm?: string
): Promise<Uint8Array> {
    const keyBuffer = typeof key === 'string' ? new TextEncoder().encode(key) : key;
    const dataBuffer = new ArrayBuffer(8);
    new DataView(dataBuffer).setBigUint64(0, BigInt(data), false);

    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyBuffer as any,
        { name: 'HMAC', hash: hashName(algorithm) },
        false,
        ['sign']
    );
    // @ts-ignore Cloudflare WebCrypto types mismatch with standard BufferSource
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, dataBuffer as any as ArrayBuffer);
    return new Uint8Array(signature);
}

/**
 * 生成 TOTP 验证码
 * @param counter 可选的时间步（默认按当前时间推算），用于计算下一个周期的验证码
 */
export async function generateTOTP(
    secret: string | Uint8Array,
    timeStep = 30,
    digits = 6,
    algorithm = 'SHA1',
    counter?: number
): Promise<string> {
    const step = Math.max(1, Number(timeStep) || 30);
    const length = Math.min(10, Math.max(4, Number(digits) || 6));
    const time = counter !== undefined ? counter : Math.floor(Date.now() / 1000 / step);
    const secretBytes = typeof secret === 'string' ? base32Decode(secret) : secret;

    const digest = await hmac(secretBytes, time, algorithm);
    const offset = digest[digest.length - 1] & 0xf;

    const code = (((digest[offset] & 0x7f) << 24) |
        ((digest[offset + 1] & 0xff) << 16) |
        ((digest[offset + 2] & 0xff) << 8) |
        (digest[offset + 3] & 0xff)) % Math.pow(10, length);

    return code.toString().padStart(length, '0');
}

/**
 * 一次性生成当前验证码 + 下一个验证码 + 剩余秒数
 * 供 /api/ext/codes 使用，避免每条账户重复取时间
 */
export async function generateCodeSet(
    secret: string,
    options: { period?: number; digits?: number; algorithm?: string } = {},
    nowSec?: number
): Promise<{ code: string; next_code: string; remaining: number; generated_at: number; period: number; digits: number }> {
    const period = Math.max(1, Number(options.period) || 30);
    const digits = Math.min(10, Math.max(4, Number(options.digits) || 6));
    const algorithm = options.algorithm || 'SHA1';
    const now = nowSec !== undefined ? nowSec : Math.floor(Date.now() / 1000);
    const counter = Math.floor(now / period);

    const code = await generateTOTP(secret, period, digits, algorithm, counter);
    const nextCode = await generateTOTP(secret, period, digits, algorithm, counter + 1);

    return {
        code,
        next_code: nextCode,
        remaining: Math.max(0, period - (now % period)),
        generated_at: now,
        period,
        digits,
    };
}

export function parseOTPAuthURI(uri: string) {
    try {
        if (!uri || typeof uri !== 'string' || uri.length > 1000) return null;
        const url = new URL(uri);
        if (url.protocol !== 'otpauth:') return null;

        const type = url.hostname;
        if (type !== 'totp' && type !== 'hotp') return null;

        const label = decodeURIComponent(url.pathname.substring(1));
        const params = new URLSearchParams(url.search);

        const secret = params.get('secret');
        if (!validateBase32Secret(secret)) return null;

        const [issuer, account] = label.includes(':') ? label.split(':', 2) : ['', label];
        const digits = parseInt(params.get('digits') || '6');
        const period = parseInt(params.get('period') || '30');

        if (digits < 6 || digits > 8 || period < 15 || period > 300) return null;

        return {
            type,
            label: sanitizeInput(label, 100),
            issuer: sanitizeInput(params.get('issuer') || issuer, 50),
            account: sanitizeInput(account || label, 100),
            secret: secret!,
            algorithm: (params.get('algorithm') || 'SHA1').toUpperCase(),
            digits,
            period
        };
    } catch {
        return null;
    }
}
