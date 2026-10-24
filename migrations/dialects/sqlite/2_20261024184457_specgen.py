from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "tickets" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "title" VARCHAR(128) NOT NULL  /* 标题 */,
    "status" VARCHAR(16) NOT NULL  DEFAULT 'open' /* 状态 */,
    "priority" VARCHAR(8) NOT NULL  DEFAULT 'normal' /* 优先级 */,
    "due_date" DATE   /* 期望完成日 */,
    "customer_id" INT NOT NULL REFERENCES "customer" ("id") ON DELETE RESTRICT
) /* 工单。客户工单 */;
"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        DROP TABLE IF EXISTS "tickets";
"""
