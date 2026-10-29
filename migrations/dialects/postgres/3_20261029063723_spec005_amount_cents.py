from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        -- 金额改最小单位整数（分）。整表重建：ALTER COLUMN ... TYPE 不被
        -- existing_definitions() 解析，写它 specgen migrate 仍报 unsupported（CPL 实测）。
        --
        -- 精确换算裁定（公司账本 EVT-20261029-008）：不准四舍五入、不准截断。
        -- 容差 1e-3 为 CPL 实测裁定（合法分位残差上界 1.192e-07 / 半分残差 0.5）。
        -- 注意：PG 的 ROUND(double) 是 ties-to-even，ROUND(numeric) 才是 half-away；
        --   断言与换算都用 ROUND(REAL 数值)，语义与另两方言一致（half-away）。
        -- 断言实现：INSERT 的 CASE 里不精确行置 NULL，违反 NOT NULL → 语句原子失败
        -- → 迁移中止、0 行写入。违规行定位（人工）：
        --   SELECT "id","amount" FROM "orders"
        --     WHERE ABS("amount"*100 - ROUND("amount"*100)) > 1e-3;
        -- 幂等防呆：amount 已非 double precision（库已按新模型建过）时等值搬运。
        ALTER TABLE "orders" RENAME TO "orders_old";
        CREATE TABLE IF NOT EXISTS "orders" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
    "title" VARCHAR(128) NOT NULL,
    "amount" INT NOT NULL,
    "quantity" INT NOT NULL  DEFAULT 1,
    "status" VARCHAR(16) NOT NULL  DEFAULT 'pending',
    "customer_id" INT NOT NULL REFERENCES "customer" ("id") ON DELETE RESTRICT
);
        COMMENT ON COLUMN "orders"."created_at" IS '创建时间';
        COMMENT ON COLUMN "orders"."updated_at" IS '更新时间';
        COMMENT ON COLUMN "orders"."deleted" IS '删除标记';
        COMMENT ON COLUMN "orders"."title" IS '标题';
        COMMENT ON COLUMN "orders"."amount" IS '金额（分）';
        COMMENT ON COLUMN "orders"."quantity" IS '数量';
        COMMENT ON COLUMN "orders"."status" IS '状态';
        COMMENT ON TABLE "orders" IS '订单。客户订单';
        INSERT INTO "orders" ("id", "created_at", "updated_at", "deleted", "title", "amount", "quantity", "status", "customer_id")
        SELECT "id", "created_at", "updated_at", "deleted", "title",
            CASE
                -- 幂等防呆：**查源表 orders_old 的列类型**（RENAME 之后 orders 已被新表
                -- 占用，查它得到 integer，守卫恒命中 → 换算分支成死代码。）
                -- 不用值判定：浮点列里 100.00 元也是整数值，会被误判、缩水 100 倍。
                WHEN EXISTS (SELECT 1 FROM information_schema.columns c
                             WHERE c.table_name = 'orders_old' AND c.column_name = 'amount'
                               AND c.data_type <> 'double precision')
                    THEN "amount"
                -- 断言右侧必须 ROUND（PG 这行原本就对）。注意 ROUND(double) 是
                -- ties-to-even，但本场景 x*100 距整数要么 <1.19e-7 要么 =0.5，
                -- 不会落在「恰好 .5 的浮点表示」上，两种舍入方向不触发。
                WHEN ABS("amount" * 100 - ROUND("amount" * 100)) <= 1e-3
                    THEN CAST(ROUND("amount" * 100) AS BIGINT)
                ELSE NULL
            END,
            "quantity", "status", "customer_id"
        FROM "orders_old";
        DROP TABLE "orders_old";
        -- SERIAL 的新序列从 1 开始；显式插入旧 id 后必须同步序列，否则后续 INSERT 主键冲突
        SELECT setval(pg_get_serial_sequence('"orders"', 'id'),
                      COALESCE((SELECT MAX("id") FROM "orders"), 1));
"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "orders" RENAME TO "orders_old";
        CREATE TABLE IF NOT EXISTS "orders" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
    "title" VARCHAR(128) NOT NULL,
    "amount" DOUBLE PRECISION NOT NULL,
    "quantity" INT NOT NULL  DEFAULT 1,
    "status" VARCHAR(16) NOT NULL  DEFAULT 'pending',
    "customer_id" INT NOT NULL REFERENCES "customer" ("id") ON DELETE RESTRICT
);
        COMMENT ON COLUMN "orders"."created_at" IS '创建时间';
        COMMENT ON COLUMN "orders"."updated_at" IS '更新时间';
        COMMENT ON COLUMN "orders"."deleted" IS '删除标记';
        COMMENT ON COLUMN "orders"."title" IS '标题';
        COMMENT ON COLUMN "orders"."amount" IS '金额';
        COMMENT ON COLUMN "orders"."quantity" IS '数量';
        COMMENT ON COLUMN "orders"."status" IS '状态';
        COMMENT ON TABLE "orders" IS '订单。客户订单';
        INSERT INTO "orders" ("id", "created_at", "updated_at", "deleted", "title", "amount", "quantity", "status", "customer_id")
        SELECT "id", "created_at", "updated_at", "deleted", "title",
            ROUND(("amount" / 100.0)::numeric, 2)::DOUBLE PRECISION,
            "quantity", "status", "customer_id"
        FROM "orders_old";
        DROP TABLE "orders_old";
        SELECT setval(pg_get_serial_sequence('"orders"', 'id'),
                      COALESCE((SELECT MAX("id") FROM "orders"), 1));
"""
