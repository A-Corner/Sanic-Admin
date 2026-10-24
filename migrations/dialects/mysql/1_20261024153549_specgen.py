from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS `customer` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `name` VARCHAR(128) NOT NULL  COMMENT '名称',
    `email` VARCHAR(255) NOT NULL UNIQUE COMMENT '邮箱',
    `status` VARCHAR(16) NOT NULL  COMMENT '状态' DEFAULT 'active',
    `notes` LONGTEXT   COMMENT '备注',
    `birthday` DATE   COMMENT '生日',
    `onboarded_at` DATETIME(6)   COMMENT '建档时间'
) CHARACTER SET utf8mb4 COMMENT='客户。客户档案';
        CREATE TABLE IF NOT EXISTS `orders` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `title` VARCHAR(128) NOT NULL  COMMENT '标题',
    `amount` DOUBLE NOT NULL  COMMENT '金额',
    `quantity` INT NOT NULL  COMMENT '数量' DEFAULT 1,
    `status` VARCHAR(16) NOT NULL  COMMENT '状态' DEFAULT 'pending',
    `customer_id` INT NOT NULL,
    CONSTRAINT `fk_orders_customer_6fed6e80` FOREIGN KEY (`customer_id`) REFERENCES `customer` (`id`) ON DELETE RESTRICT
) CHARACTER SET utf8mb4 COMMENT='订单。客户订单';
"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        DROP TABLE IF EXISTS `orders`;
        DROP TABLE IF EXISTS `customer`;
"""
