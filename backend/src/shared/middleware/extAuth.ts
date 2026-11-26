import { Context, Next } from 'hono';
import { AppError, EnvBindings } from '@/app/config';
import { ExtService } from '@/features/ext/extService';

/**
 * 浏览器扩展的 Bearer 鉴权中间件
 * - 与站点会话完全独立：不读取 Cookie，也不要求 CSRF
 * - 失败统一返回 401，前端据此提示重新授权
 */
export async function extAuthMiddleware(
    c: Context<{ Bindings: EnvBindings, Variables: { user: any, extToken: any } }>,
    next: Next
) {
    const header = c.req.header('Authorization') || '';
    const match = header.match(/^Bearer\s+(.+)$/i);
    if (!match) {
        throw new AppError('token_missing', 401);
    }

    const service = new ExtService(c.env);

    let verified;
    try {
        verified = await service.verifyToken(match[1].trim());
    } catch (error) {
        // 令牌存在但被吊销/过期：保留细分错误码，方便扩展区分提示
        if (error instanceof AppError) throw error;
        throw new AppError('token_invalid', 401);
    }

    if (!verified) {
        throw new AppError('token_invalid', 401);
    }

    c.set('extToken', verified);
    await next();
}
