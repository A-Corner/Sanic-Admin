from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        PRAGMA foreign_keys=OFF;
        ALTER TABLE "orders" RENAME TO "orders_old";
        CREATE TABLE IF NOT EXISTS "orders" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "title" VARCHAR(128) NOT NULL  /* 标题 */,
    "amount" INT NOT NULL  /* 金额（分） */,
    "quantity" INT NOT NULL  DEFAULT 1 /* 数量 */,
    "status" VARCHAR(16) NOT NULL  DEFAULT 'pending' /* 状态 */,
    "customer_id" INT NOT NULL REFERENCES "customer" ("id") ON DELETE RESTRICT
) /* 订单。客户订单 */;
        INSERT INTO "orders" ("id", "created_at", "updated_at", "deleted", "title", "amount", "quantity", "status", "customer_id")
        SELECT
            "id", "created_at", "updated_at", "deleted", "title",
            -- 金额精确换算（公司裁定：不准四舍五入、不准截断）：
            --   已是整数（分） → 等值（幂等防呆：防「已按新模型建过的库」二次 ×100）
            --   浮点且 ×100 后在 1e-3 容差内是整数 → 精确换算（如 12.34 → 1234）
            --   否则 → NULL，违反 NOT NULL，整条 INSERT 原子失败，迁移中止、0 行写入
            -- 违例行定位（人工）：SELECT "id","amount" FROM "orders_old"
            --   WHERE ABS("amount"*100 - ROUND("amount"*100)) > 1e-3;
            -- **断言右侧必须用 ROUND，不能用 CAST**：CAST 是向零截断，
            -- 1.14*100=113.99999999999999 会被截成 113，产生 1.0 的假残差，
            -- 把合法金额判成「不精确」（实测：1.14/2.28/0.29/0.57/19.99 共 5/8 被判死）。
            -- ROUND 后残差才有意义：精确值残差 ≤1.19e-7，半分尾数残差 =0.5。
            -- 换算侧的 CAST 在断言通过后是无损的（此时 x*100 距整数 <1e-3）。
            CASE
                WHEN typeof("amount") = 'integer' THEN "amount"
                WHEN ABS("amount" * 100 - ROUND("amount" * 100)) <= 1e-3
                    THEN CAST(ROUND("amount" * 100) AS INTEGER)
                ELSE NULL
            END,
            "quantity", "status", "customer_id"
        FROM "orders_old";
        DROP TABLE "orders_old";
        PRAGMA foreign_keys=ON;
"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        PRAGMA foreign_keys=OFF;
        ALTER TABLE "orders" RENAME TO "orders_new";
        CREATE TABLE IF NOT EXISTS "orders" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "title" VARCHAR(128) NOT NULL  /* 标题 */,
    "amount" REAL NOT NULL  /* 金额 */,
    "quantity" INT NOT NULL  DEFAULT 1 /* 数量 */,
    "status" VARCHAR(16) NOT NULL  DEFAULT 'pending' /* 状态 */,
    "customer_id" INT NOT NULL REFERENCES "customer" ("id") ON DELETE RESTRICT
) /* 订单。客户订单 */;
        INSERT INTO "orders" ("id", "created_at", "updated_at", "deleted", "title", "amount", "quantity", "status", "customer_id")
        SELECT
            "id", "created_at", "updated_at", "deleted", "title",
            -- 分 → 元：除以 100；ROUND(x, 2) 保两位小数（元的最小展示单位）。
            -- 这是 downgrade（撤销迁移），只用于回退场景，不涉及以上精确换算裁定。
            CAST(ROUND("amount" / 100.0, 2) AS REAL),
            "quantity", "status", "customer_id"
        FROM "orders_new";
        DROP TABLE "orders_new";
        PRAGMA foreign_keys=ON;
"""
