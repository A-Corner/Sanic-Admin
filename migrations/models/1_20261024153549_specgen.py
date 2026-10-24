from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "customer" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "name" VARCHAR(128) NOT NULL  /* 名称 */,
    "email" VARCHAR(255) NOT NULL UNIQUE /* 邮箱 */,
    "status" VARCHAR(16) NOT NULL  DEFAULT 'active' /* 状态 */,
    "notes" TEXT   /* 备注 */,
    "birthday" DATE   /* 生日 */,
    "onboarded_at" TIMESTAMP   /* 建档时间 */
) /* 客户。客户档案 */;
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
"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        DROP TABLE IF EXISTS "orders";
        DROP TABLE IF EXISTS "customer";
"""
