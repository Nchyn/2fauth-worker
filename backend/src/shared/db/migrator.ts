/**
 * 数据库执行器抽象接口
 */
export interface DbExecutor {
    exec(sql: string): void | Promise<void>;
    prepare(sql: string): {
        get(): any | Promise<any>;
        run(...params: any[]): any | Promise<any>;
    };
    // 兼容 D1 的事务处理
    batch?(sqls: string[]): Promise<void>;
}

/**
 * 迁移条目
 */
interface Migration {
    version: number;
    name: string;
    sql: string;
}

const MIGRATIONS: Migration[] = [
    {
        version: 1,
        name: 'add_sort_order_to_vault',
        sql: `ALTER TABLE vault ADD COLUMN sort_order INTEGER DEFAULT 0;`
    },
    {
        version: 2,
        name: 'add_category_column_to_vault',
        sql: `ALTER TABLE vault ADD COLUMN category TEXT;`
    },
    {
        version: 3,
        name: 'create_vault_category_sort_index',
        sql: `CREATE INDEX IF NOT EXISTS idx_vault_category_sort ON vault (category, sort_order);`
    },
    {
        version: 4,
        name: 'initialize_baseline_indexes',
        sql: `
            CREATE INDEX IF NOT EXISTS idx_vault_created_at ON vault(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_vault_service_created_at ON vault(service, created_at DESC);
            CREATE UNIQUE INDEX IF NOT EXISTS vault_service_account_uq ON vault(lower(service), lower(account));
            CREATE INDEX IF NOT EXISTS idx_backup_providers_type ON backup_providers(type);
            CREATE INDEX IF NOT EXISTS idx_backup_telegram_history_provider_id ON backup_telegram_history(provider_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_backup_email_history_provider_id ON backup_email_history(provider_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON auth_passkeys(user_id);
            CREATE INDEX IF NOT EXISTS idx_rate_limits_expires ON rate_limits(expires_at);
        `
    },
    {
        version: 5,
        name: 'create_ext_tokens',
        sql: `
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
            );
            CREATE INDEX IF NOT EXISTS idx_ext_tokens_hash ON ext_tokens(token_hash);
            CREATE INDEX IF NOT EXISTS idx_ext_tokens_user ON ext_tokens(user_id);
        `
    }
];

/**
 * 统一迁移入口：支持本地与远程
 */
export async function migrateDatabase(db: DbExecutor) {
    // 1. 确保元数据表存在
    await db.exec(`CREATE TABLE IF NOT EXISTS _schema_metadata (key TEXT PRIMARY KEY, value TEXT)`);

    // 2. 获取当前版本
    const row = await db.prepare("SELECT value FROM _schema_metadata WHERE key = 'version'").get();
    const currentVersion = row ? parseInt(row.value, 10) : 0;

    const pending = MIGRATIONS.filter(m => m.version > currentVersion).sort((a, b) => a.version - b.version);

    if (pending.length === 0) return;

    console.log(`[Database] Current version: ${currentVersion}. Migrating to v${pending[pending.length - 1].version}...`);

    for (const m of pending) {
        console.log(`[Database] Applying v${m.version}: ${m.name}`);
        try {
            // 注意：SQLite 的 ALTER TABLE 不支持 IF NOT EXISTS，需捕获错误以防重复执行。
            // D1 的 exec() 走批量协议，对多语句支持有限；逐条执行保证每条 DDL 独立成功。
            for (const statement of splitStatements(m.sql)) {
                if (!statement) continue;
                try {
                    await db.exec(statement);
                } catch (e: any) {
                    if (e.message?.includes('duplicate column name') || e.message?.includes('already exists')) continue;
                    throw e;
                }
            }
            await db.prepare("INSERT OR REPLACE INTO _schema_metadata (key, value) VALUES ('version', ?)").run(m.version.toString());
        } catch (e: any) {
            if (e.message?.includes('duplicate column name') || e.message?.includes('already exists')) {
                console.log(`[Database] Skip existing change in v${m.version}`);
                await db.prepare("INSERT OR REPLACE INTO _schema_metadata (key, value) VALUES ('version', ?)").run(m.version.toString());
                continue;
            }
            throw e;
        }
    }
}

/**
 * 把多语句 SQL 按分号拆成单条（忽略字符串字面量里的分号——本项目的迁移没有这种字面量，
 * 简单 split 即可覆盖现有全部条目）。
 */
function splitStatements(sql: string): string[] {
    return sql
        .split(';')
        .map((s) => s.trim())
        .filter(Boolean);
}
