from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "customer" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
    "name" VARCHAR(128) NOT NULL,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "status" VARCHAR(16) NOT NULL  DEFAULT 'active',
    "notes" TEXT,
    "birthday" DATE,
    "onboarded_at" TIMESTAMPTZ
);
COMMENT ON COLUMN "customer"."created_at" IS '创建时间';
COMMENT ON COLUMN "customer"."updated_at" IS '更新时间';
COMMENT ON COLUMN "customer"."deleted" IS '删除标记';
COMMENT ON COLUMN "customer"."name" IS '名称';
COMMENT ON COLUMN "customer"."email" IS '邮箱';
COMMENT ON COLUMN "customer"."status" IS '状态';
COMMENT ON COLUMN "customer"."notes" IS '备注';
COMMENT ON COLUMN "customer"."birthday" IS '生日';
COMMENT ON COLUMN "customer"."onboarded_at" IS '建档时间';
COMMENT ON TABLE "customer" IS '客户。客户档案';
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
"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        DROP TABLE IF EXISTS "orders";
        DROP TABLE IF EXISTS "customer";
"""
