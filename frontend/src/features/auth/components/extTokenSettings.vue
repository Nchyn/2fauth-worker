<template>
  <div class="ext-token-wrapper">
    <div class="tab-card-wrapper">
      <div class="ext-header">
        <div>
          <h3>{{ $t('security.ext_title') }}</h3>
          <p class="text-secondary ext-desc">{{ $t('security.ext_desc') }}</p>
        </div>
        <el-button type="primary" @click="openAuthorizeDialog">
          <el-icon><Plus /></el-icon> {{ $t('security.ext_authorize') }}
        </el-button>
      </div>

      <div v-if="loading && tokens.length === 0" class="flex-column flex-center min-h-200 text-secondary">
        <el-icon class="is-loading mb-20 text-primary" :size="48"><Loading /></el-icon>
        <p class="text-16 ls-1">{{ $t('common.loading_data') }}</p>
      </div>

      <div v-else-if="tokens.length === 0" class="empty-state mt-40">
        <el-empty :description="$t('security.ext_empty')" />
      </div>

      <div v-else class="mt-20">
        <el-table :data="tokens" style="width: 100%">
          <el-table-column :label="$t('security.ext_device')" min-width="150">
            <template #default="{ row }">
              <div class="ext-device-cell">
                <span>{{ row.label || $t('security.ext_unnamed') }}</span>
                <el-tag
                  size="small"
                  :type="row.active ? 'success' : 'info'"
                  effect="light"
                >
                  {{ row.active ? $t('security.ext_active') : $t('security.ext_inactive') }}
                </el-tag>
              </div>
            </template>
          </el-table-column>
          <el-table-column :label="$t('security.created_at')" min-width="150">
            <template #default="{ row }">{{ formatDate(row.createdAt) }}</template>
          </el-table-column>
          <el-table-column :label="$t('security.last_used')" min-width="150">
            <template #default="{ row }">
              {{ row.lastUsedAt ? formatDate(row.lastUsedAt) : '-' }}
            </template>
          </el-table-column>
          <el-table-column :label="$t('security.ext_expires')" min-width="150">
            <template #default="{ row }">{{ formatDate(row.expiresAt) }}</template>
          </el-table-column>
          <el-table-column align="right" width="100">
            <template #default="{ row }">
              <el-button
                type="danger"
                link
                :icon="Delete"
                :disabled="!row.active"
                @click="handleRevoke(row)"
              />
            </template>
          </el-table-column>
        </el-table>
      </div>

      <!-- 授权新设备 -->
      <el-dialog
        v-model="showAuthDialog"
        :title="$t('security.ext_authorize_title')"
        :width="layoutStore.isMobile ? '90%' : '460px'"
        append-to-body
      >
        <el-form :model="authForm" @submit.prevent="handleAuthorize">
          <el-form-item :label="$t('security.ext_device')">
            <el-input
              v-model="authForm.label"
              :placeholder="$t('security.ext_device_placeholder')"
              clearable
              maxlength="40"
            />
          </el-form-item>
        </el-form>
        <p class="text-secondary text-12">{{ $t('security.ext_authorize_tip') }}</p>
        <template #footer>
          <span class="dialog-footer">
            <el-button @click="showAuthDialog = false">{{ $t('common.cancel') }}</el-button>
            <el-button type="primary" :loading="authorizing" @click="handleAuthorize">
              {{ $t('common.confirm') }}
            </el-button>
          </span>
        </template>
      </el-dialog>

      <!-- 一次性令牌展示 -->
      <el-dialog
        v-model="showTokenDialog"
        :title="$t('security.ext_issued_title')"
        :width="layoutStore.isMobile ? '92%' : '520px'"
        :close-on-click-modal="false"
        append-to-body
      >
        <el-alert :title="$t('security.ext_issued_warning')" type="warning" show-icon :closable="false" />

        <div class="ext-token-box">
          <code class="ext-token-value">{{ issued.token }}</code>
        </div>

        <p class="text-secondary text-12">
          {{ $t('security.ext_issued_expires', { date: formatDate(issued.expiresAt) }) }}
        </p>

        <div class="ext-token-actions">
          <el-button @click="copyToken">
            <el-icon><CopyDocument /></el-icon> {{ $t('security.ext_copy') }}
          </el-button>
          <el-button type="primary" :loading="sending" @click="sendToExtension">
            <el-icon><Promotion /></el-icon> {{ $t('security.ext_send') }}
          </el-button>
        </div>

        <p v-if="ackMessage" class="ext-ack" :class="{ 'is-error': ackError }">{{ ackMessage }}</p>

        <template #footer>
          <span class="dialog-footer">
            <el-button type="primary" @click="closeTokenDialog">{{ $t('common.close') }}</el-button>
          </span>
        </template>
      </el-dialog>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onBeforeUnmount } from 'vue'
import { Plus, Delete, Loading, CopyDocument, Promotion } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useI18n } from 'vue-i18n'
import { useLayoutStore } from '@/shared/stores/layoutStore'
import { extTokenService } from '@/features/auth/service/extTokenService'

const { t } = useI18n()
const layoutStore = useLayoutStore()

const loading = ref(true)
const authorizing = ref(false)
const sending = ref(false)
const tokens = ref([])

const showAuthDialog = ref(false)
const showTokenDialog = ref(false)

const authForm = reactive({ label: '' })
const issued = ref({ token: '', expiresAt: 0, label: '' })

const ackMessage = ref('')
const ackError = ref(false)

let ackTimer = null

function guessDeviceLabel() {
  const ua = navigator.userAgent || ''
  if (/Edg\//.test(ua)) return 'Edge 浏览器扩展'
  if (/Firefox\//.test(ua)) return 'Firefox 浏览器扩展'
  if (/Chrome\//.test(ua)) return 'Chrome 浏览器扩展'
  if (/Safari\//.test(ua)) return 'Safari 浏览器扩展'
  return ''
}

function openAuthorizeDialog() {
  authForm.label = authForm.label || guessDeviceLabel()
  showAuthDialog.value = true
}

async function fetchTokens() {
  loading.value = true
  try {
    const res = await extTokenService.list()
    if (res && res.success) tokens.value = res.tokens || []
  } catch (error) {
    console.error('Failed to fetch extension tokens:', error)
  } finally {
    loading.value = false
  }
}

async function handleAuthorize() {
  authorizing.value = true
  try {
    const label = authForm.label.trim()
    const res = await extTokenService.authorize(label)

    if (res && res.success && res.item) {
      issued.value = {
        token: res.item.token,
        expiresAt: res.item.expiresAt,
        label: res.item.label,
      }
      ackMessage.value = ''
      ackError.value = false
      showAuthDialog.value = false
      showTokenDialog.value = true
      await fetchTokens()
    }
  } catch (error) {
    console.error('Authorize failed:', error)
  } finally {
    authorizing.value = false
  }
}

async function copyToken() {
  try {
    await navigator.clipboard.writeText(issued.value.token)
    ElMessage.success(t('security.ext_copy_success'))
  } catch {
    ElMessage.error(t('security.ext_copy_failed'))
  }
}

/**
 * 通过 postMessage 交给扩展内容脚本
 * 内容脚本校验 event.source 后转发给后台，并回传 fw:token-ack
 */
function sendToExtension() {
  if (!issued.value.token) return

  sending.value = true
  ackMessage.value = ''
  ackError.value = false

  window.postMessage(
    {
      source: 'fw-site',
      type: 'fw:token',
      host: window.location.origin,
      token: issued.value.token,
      expiresAt: issued.value.expiresAt,
      label: issued.value.label,
    },
    window.location.origin
  )

  // 3 秒内没收到回执，提示用户改用复制粘贴
  if (ackTimer) clearTimeout(ackTimer)
  ackTimer = setTimeout(() => {
    if (sending.value) {
      sending.value = false
      ackError.value = true
      ackMessage.value = t('security.ext_send_timeout')
    }
  }, 3000)
}

function onWindowMessage(event) {
  if (event.source !== window) return

  const data = event.data
  if (!data || data.source !== 'fw-extension' || data.type !== 'fw:token-ack') return

  if (ackTimer) {
    clearTimeout(ackTimer)
    ackTimer = null
  }

  sending.value = false
  ackError.value = !data.ok
  ackMessage.value = data.ok
    ? t('security.ext_send_success')
    : t('security.ext_send_failed')
}

function closeTokenDialog() {
  showTokenDialog.value = false
  issued.value = { token: '', expiresAt: 0, label: '' }
  ackMessage.value = ''
  ackError.value = false
}

async function handleRevoke(row) {
  try {
    await ElMessageBox.confirm(
      t('security.ext_revoke_confirm', { name: row.label || t('security.ext_unnamed') }),
      t('common.warning'),
      {
        confirmButtonText: t('common.confirm'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )

    const res = await extTokenService.revoke(row.id)
    if (res && res.success) {
      ElMessage.success(t('common.success'))
      await fetchTokens()
    }
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Revoke failed:', error)
    }
  }
}

function formatDate(timestamp) {
  if (!timestamp) return '-'
  const date = new Date(timestamp)
  const Y = date.getFullYear()
  const M = String(date.getMonth() + 1).padStart(2, '0')
  const D = String(date.getDate()).padStart(2, '0')
  const h = String(date.getHours()).padStart(2, '0')
  const m = String(date.getMinutes()).padStart(2, '0')
  return `${Y}-${M}-${D} ${h}:${m}`
}

onMounted(() => {
  window.addEventListener('message', onWindowMessage)
  fetchTokens()
})

onBeforeUnmount(() => {
  window.removeEventListener('message', onWindowMessage)
  if (ackTimer) clearTimeout(ackTimer)
})
</script>

<style scoped>
.ext-token-wrapper {
  margin-top: 32px;
}

.ext-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
}

.ext-desc {
  margin-top: 6px;
  font-size: 13px;
  line-height: 1.6;
}

.ext-device-cell {
  display: flex;
  align-items: center;
  gap: 8px;
}

.ext-token-box {
  margin: 16px 0 8px;
  padding: 12px;
  border-radius: 8px;
  background: var(--el-fill-color-light, #f5f7fa);
  border: 1px dashed var(--el-border-color, #dcdfe6);
  word-break: break-all;
}

.ext-token-value {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12.5px;
  line-height: 1.7;
  user-select: all;
}

.ext-token-actions {
  display: flex;
  gap: 8px;
  margin-top: 16px;
  flex-wrap: wrap;
}

.ext-ack {
  margin-top: 10px;
  font-size: 12.5px;
  color: #16a34a;
}

.ext-ack.is-error {
  color: #dc2626;
}
</style>
