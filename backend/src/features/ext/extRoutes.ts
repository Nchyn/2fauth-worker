import { Hono } from 'hono';
import { EnvBindings, SECURITY_CONFIG } from '@/app/config';
import { authMiddleware } from '@/shared/middleware/auth';
import { extAuthMiddleware } from '@/shared/middleware/extAuth';
import { rateLimit } from '@/shared/middleware/rateLimitMiddleware';
import { ExtService } from '@/features/ext/extService';

const ext = new Hono<{ Bindings: EnvBindings, Variables: { user: any, extToken: any } }>();

/**
 * 站点内授权：需要已登录的站点会话（Cookie + CSRF）
 * 返回的明文令牌只出现这一次，扩展应立刻保存
 */
ext.post('/authorize', authMiddleware, async (c) => {
    const user = c.get('user');
    const body = await c.req.json().catch(() => ({}));

    const service = new ExtService(c.env);
    const issued = await service.issueToken(user, body && body.label);

    c.header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    c.header('Pragma', 'no-cache');

    return c.json({
        success: true,
        item: {
            id: issued.id,
            label: issued.label,
            token: issued.token,
            createdAt: issued.createdAt,
            expiresAt: issued.expiresAt,
        },
    });
});

/**
 * 取码：Bearer 令牌鉴权，服务端计算 TOTP，只返回验证码
 */
ext.get(
    '/codes',
    extAuthMiddleware,
    rateLimit({
        windowMs: 60 * 1000,
        max: SECURITY_CONFIG.EXT_CODES_RATE_MAX,
        keyBuilder: (c: any) => {
            const token = c.get('extToken');
            return `rl:ext:${(token && token.id) || 'unknown'}`;
        },
    }),
    async (c) => {
        const token = c.get('extToken');
        const service = new ExtService(c.env);

        const accounts = await service.getCodes();

        c.header('Cache-Control', 'no-store');

        return c.json({
            success: true,
            now: Math.floor(Date.now() / 1000),
            accounts,
            token: {
                id: token.id,
                label: token.label,
                expiresAt: token.expiresAt,
            },
        });
    }
);

/**
 * 令牌列表：站点会话可见，用于展示与吊销
 */
ext.get('/tokens', authMiddleware, async (c) => {
    const user = c.get('user');
    const service = new ExtService(c.env);
    const tokens = await service.listTokens(user);

    c.header('Cache-Control', 'no-store');
    return c.json({ success: true, tokens });
});

/**
 * 吊销令牌：只能吊销自己的
 */
ext.delete('/tokens/:id', authMiddleware, async (c) => {
    const user = c.get('user');
    const id = c.req.param('id') || '';

    const service = new ExtService(c.env);
    await service.revokeToken(user, id);

    return c.json({ success: true });
});

export default ext;
