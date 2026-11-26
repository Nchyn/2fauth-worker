import { request } from '@/shared/utils/request'

/**
 * @typedef {Object} ExtTokenItem
 * @property {string} id
 * @property {string} label
 * @property {number} createdAt
 * @property {number|null} lastUsedAt
 * @property {number} expiresAt
 * @property {number|null} revokedAt
 * @property {boolean} active
 */

/**
 * 浏览器扩展授权令牌服务
 * - 签发接口返回的明文 token 只会出现一次，前端需立即展示给用户保存
 */
export const extTokenService = {
    /**
     * 签发新的设备令牌
     * @param {string} [label] 设备别名
     * @returns {Promise<{success: boolean, item: {id: string, label: string, token: string, createdAt: number, expiresAt: number}}>}
     */
    async authorize(label) {
        return await request('/api/ext/authorize', {
            method: 'POST',
            body: JSON.stringify({ label: label || '' })
        })
    },

    /**
     * 获取当前账号下的令牌列表
     * @returns {Promise<{success: boolean, tokens: ExtTokenItem[]}>}
     */
    async list() {
        return await request(`/api/ext/tokens?_t=${Date.now()}`)
    },

    /**
     * 吊销指定令牌
     * @param {string} id
     */
    async revoke(id) {
        return await request(`/api/ext/tokens/${id}`, { method: 'DELETE' })
    }
}
