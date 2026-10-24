from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "tickets" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
    "title" VARCHAR(128) NOT NULL,
    "status" VARCHAR(16) NOT NULL  DEFAULT 'open',
    "priority" VARCHAR(8) NOT NULL  DEFAULT 'normal',
    "due_date" DATE,
    "customer_id" INT NOT NULL REFERENCES "customer" ("id") ON DELETE RESTRICT
);
COMMENT ON COLUMN "tickets"."created_at" IS '创建时间';
COMMENT ON COLUMN "tickets"."updated_at" IS '更新时间';
COMMENT ON COLUMN "tickets"."deleted" IS '删除标记';
COMMENT ON COLUMN "tickets"."title" IS '标题';
COMMENT ON COLUMN "tickets"."status" IS '状态';
COMMENT ON COLUMN "tickets"."priority" IS '优先级';
COMMENT ON COLUMN "tickets"."due_date" IS '期望完成日';
COMMENT ON TABLE "tickets" IS '工单。客户工单';
"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        DROP TABLE IF EXISTS "tickets";
"""
