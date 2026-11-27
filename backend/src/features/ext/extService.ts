import { and, desc, eq, gt, isNull, lt } from 'drizzle-orm';
import { AppError, EnvBindings, SECURITY_CONFIG } from '@/app/config';
import { extTokens, type ExtToken } from '@/shared/db/schema';
import { sanitizeInput } from '@/shared/utils/common';
import { generateCodeSet } from '@/shared/utils/totp';
import { VaultRepository } from '@/shared/db/repositories/vaultRepository';
import { VaultService } from '@/features/vault/vaultService';

const TOKEN_PREFIX = 'fw_';
const TTL_MS = SECURITY_CONFIG.EXT_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000;

export type ExtTokenUser = {
    id: string;
    username?: string;
    email?: string;
};

function toBase64Url(bytes: Uint8Array): string {
    let binary = '';
    for (let index = 0; index < bytes.length; index += 1) {
        binary += String.fromCharCode(bytes[index]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256Hex(value: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
    return Array.from(new Uint8Array(digest))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
}

function userIdOf(user: ExtTokenUser): string {
    // 与 deviceKey 保持一致：统一使用 email 作为账号标识，缺失时回退 id
    return String((user && (user.email || user.id)) || '');
}

export class ExtService {
    private env: EnvBindings;

    constructor(env: EnvBindings) {
        this.env = env;
    }

    private get db(): any {
        const db = this.env.DB;
        if (!db) throw new AppError('missing_db_binding', 500);
        return db;
    }

    /**
     * 确保 ext_tokens 表存在。
     * worker.ts 的自愈迁移走 ctx.waitUntil（异步、且 D1 exec 对多语句有限制），
     * 不能保证在首个请求前完成；这里同步兜底，缺表时直接建表。
     */
    private async ensureTable(): Promise<void> {
        const probe = await this.db
            .select({ id: extTokens.id })
            .from(extTokens)
            .limit(1)
            .catch(() => null);

        if (probe === null) {
            // Drizzle 之上拿不到原始 D1；用 raw sql 模板建表（幂等）
            const { sql } = await import('drizzle-orm');
            await this.db.run(sql`
                CREATE TABLE IF NOT EXISTS ext_tokens (
                    id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    user_id TEXT NOT NULL,
                    label TEXT,
                    created_at INTEGER NOT NULL,
                    last_used_at INTEGER,
                    last_renewed_at INTEGER,
                    expires_at INTEGER NOT NULL,
                    revoked_at INTEGER
                )
            `);
            await this.db.run(sql`CREATE INDEX IF NOT EXISTS idx_ext_tokens_hash ON ext_tokens(token_hash)`);
            await this.db.run(sql`CREATE INDEX IF NOT EXISTS idx_ext_tokens_user ON ext_tokens(user_id)`);
        }
    }

    /**
     * 签发设备令牌。明文只在此处返回一次，库中仅保留 SHA-256 摘要。
     */
    async issueToken(user: ExtTokenUser, label?: string): Promise<{
        id: string;
        token: string;
        expiresAt: number;
        label: string;
        createdAt: number;
    }> {
        const userId = userIdOf(user);
        if (!userId) throw new AppError('missing_user', 401);

        await this.ensureTable();

        // 先清理该用户已失效的记录，避免无限累积
        await this.pruneExpired(userId);

        const active = await this.countActive(userId);
        if (active >= SECURITY_CONFIG.EXT_TOKEN_MAX_PER_USER) {
            throw new AppError('ext_token_limit_reached', 409);
        }

        const raw = new Uint8Array(32);
        crypto.getRandomValues(raw);
        const token = TOKEN_PREFIX + toBase64Url(raw);

        const now = Date.now();
        const expiresAt = now + TTL_MS;
        const record = {
            id: crypto.randomUUID(),
            tokenHash: await sha256Hex(token),
            userId,
            label: sanitizeInput(label || '', 40) || '浏览器扩展',
            createdAt: now,
            lastUsedAt: null,
            lastRenewedAt: now,
            expiresAt,
            revokedAt: null,
        };

        await this.db.insert(extTokens).values(record).run();

        return {
            id: record.id,
            token,
            expiresAt,
            label: record.label,
            createdAt: now,
        };
    }

    /**
     * 校验 Bearer 令牌，并按需滑动续期。
     * 返回 null 表示未命中；抛出 AppError 表示令牌存在但不可用。
     */
    async verifyToken(plain: string): Promise<{
        id: string;
        userId: string;
        expiresAt: number;
        label: string;
    } | null> {
        const token = String(plain || '').trim();
        if (!token.startsWith(TOKEN_PREFIX) || token.length < 20) return null;

        await this.ensureTable();

        const tokenHash = await sha256Hex(token);
        const rows = await this.db
            .select()
            .from(extTokens)
            .where(eq(extTokens.tokenHash, tokenHash))
            .limit(1);

        const record: ExtToken | undefined = rows && rows[0];
        if (!record) return null;

        const now = Date.now();

        if (record.revokedAt) throw new AppError('token_revoked', 401);
        if (record.expiresAt <= now) throw new AppError('token_expired', 401);

        // 滑动续期：只有当续期窗口推进足够久才写库
        const renewedAt = record.lastRenewedAt || record.createdAt || 0;
        if (now - renewedAt > SECURITY_CONFIG.EXT_TOKEN_RENEW_INTERVAL) {
            const expiresAt = now + TTL_MS;
            await this.db
                .update(extTokens)
                .set({ expiresAt, lastRenewedAt: now, lastUsedAt: now })
                .where(eq(extTokens.id, record.id))
                .run();
            record.expiresAt = expiresAt;
        } else if (!record.lastUsedAt || now - record.lastUsedAt > 60 * 1000) {
            // 使用时间最多每分钟回写一次，足够展示，也避免频繁写 D1
            await this.db
                .update(extTokens)
                .set({ lastUsedAt: now })
                .where(eq(extTokens.id, record.id))
                .run();
        }

        return {
            id: record.id,
            userId: record.userId,
            expiresAt: record.expiresAt,
            label: record.label || '',
        };
    }

    /**
     * 读取当前用户的全部令牌（不含明文）
     */
    async listTokens(user: ExtTokenUser): Promise<Array<{
        id: string;
        label: string;
        createdAt: number;
        lastUsedAt: number | null;
        expiresAt: number;
        revokedAt: number | null;
        active: boolean;
    }>> {
        const userId = userIdOf(user);
        if (!userId) throw new AppError('missing_user', 401);

        await this.ensureTable();

        const rows: ExtToken[] = await this.db
            .select()
            .from(extTokens)
            .where(eq(extTokens.userId, userId))
            .orderBy(desc(extTokens.createdAt));

        const now = Date.now();
        return (rows || []).map((row) => ({
            id: row.id,
            label: row.label || '',
            createdAt: row.createdAt,
            lastUsedAt: row.lastUsedAt ?? null,
            expiresAt: row.expiresAt,
            revokedAt: row.revokedAt ?? null,
            active: !row.revokedAt && row.expiresAt > now,
        }));
    }

    /**
     * 吊销单个令牌（只能吊销自己的）
     */
    async revokeToken(user: ExtTokenUser, id: string): Promise<boolean> {
        const userId = userIdOf(user);
        if (!userId) throw new AppError('missing_user', 401);
        if (!id) throw new AppError('missing_token_id', 400);

        await this.ensureTable();

        const rows = await this.db
            .select()
            .from(extTokens)
            .where(and(eq(extTokens.id, id), eq(extTokens.userId, userId)))
            .limit(1);

        const record: ExtToken | undefined = rows && rows[0];
        if (!record) throw new AppError('token_not_found', 404);

        if (!record.revokedAt) {
            await this.db
                .update(extTokens)
                .set({ revokedAt: Date.now() })
                .where(eq(extTokens.id, id))
                .run();
        }

        return true;
    }

    /**
     * 取码：解密账户并在服务端计算 TOTP，绝不返回 secret
     * 说明：本应用为白名单单账号部署，金库不按用户分表，故与 /api/vault 行为一致
     */
    async getCodes(): Promise<Array<{
        id: string;
        service: string;
        account: string;
        category: string;
        period: number;
        digits: number;
        algorithm: string;
        code: string;
        next_code: string;
        generated_at: number;
        remaining: number;
    }>> {
        if (!this.env.ENCRYPTION_KEY) throw new AppError('missing_encryption_key', 500);

        const repo = new VaultRepository(this.db);
        const service = new VaultService(this.env, repo);

        // 复用现有分页查询（单页上限 500，足以覆盖个人金库）
        const result = await service.getAccountsPaginated(1, 500, '', '');
        const now = Math.floor(Date.now() / 1000);

        const accounts = [];
        for (const item of result.items || []) {
            if (!item || !item.id) continue;

            // secret 解密失败（例如 ENCRYPTION_KEY 变更）时仍返回账户，
            // 只是验证码为空，便于扩展展示而不是静默丢条目
            const secret = String((item as any).secret || '');

            const period = Math.max(1, Number((item as any).period) || 30);
            const digits = Number((item as any).digits) || 6;
            const algorithm = String((item as any).algorithm || 'SHA1');

            let code = '';
            let nextCode = '';
            let remaining = Math.max(0, period - (now % period));

            if (secret) {
                try {
                    const generated = await generateCodeSet(
                        secret,
                        { period, digits, algorithm },
                        now
                    );
                    code = generated.code;
                    nextCode = generated.next_code;
                    remaining = generated.remaining;
                } catch {
                    code = '';
                    nextCode = '';
                }
            }

            accounts.push({
                id: String(item.id),
                service: String((item as any).service || ''),
                account: String((item as any).account || ''),
                category: String((item as any).category || ''),
                period,
                digits,
                algorithm,
                code,
                next_code: nextCode,
                generated_at: now,
                remaining,
            });
        }

        return accounts;
    }

    private async countActive(userId: string): Promise<number> {
        const now = Date.now();
        const rows: ExtToken[] = await this.db
            .select()
            .from(extTokens)
            .where(
                and(
                    eq(extTokens.userId, userId),
                    isNull(extTokens.revokedAt),
                    gt(extTokens.expiresAt, now)
                )
            );
        return (rows || []).length;
    }

    private async pruneExpired(userId: string): Promise<void> {
        const now = Date.now();
        try {
            await this.db
                .delete(extTokens)
                .where(and(eq(extTokens.userId, userId), lt(extTokens.expiresAt, now)))
                .run();
        } catch {
            /* 清理失败不影响签发 */
        }
    }
}
