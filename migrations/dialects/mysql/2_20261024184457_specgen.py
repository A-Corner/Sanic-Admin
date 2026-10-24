from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS `tickets` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `title` VARCHAR(128) NOT NULL  COMMENT '标题',
    `status` VARCHAR(16) NOT NULL  COMMENT '状态' DEFAULT 'open',
    `priority` VARCHAR(8) NOT NULL  COMMENT '优先级' DEFAULT 'normal',
    `due_date` DATE   COMMENT '期望完成日',
    `customer_id` INT NOT NULL,
    CONSTRAINT `fk_tickets_customer_a2732270` FOREIGN KEY (`customer_id`) REFERENCES `customer` (`id`) ON DELETE RESTRICT
) CHARACTER SET utf8mb4 COMMENT='工单。客户工单';
"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        DROP TABLE IF EXISTS `tickets`;
"""
