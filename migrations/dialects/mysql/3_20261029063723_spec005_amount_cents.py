from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        -- 金额改最小单位整数（分）。整表重建：MODIFY COLUMN 不被 existing_definitions()
        -- 解析，写它 specgen migrate 仍报 unsupported（CPL 实测）。
        --
        -- 精确换算裁定（公司账本 EVT-20261029-008）：不准四舍五入、不准截断。
        -- 容差 1e-3 为 CPL 实测裁定：合法分位金额 *100 后残差最大 1.192e-07，
        -- 半分尾数残差 0.5，1e-3 两侧余量最大（4 / 2.6 个数量级）。
        -- 断言实现：INSERT 的 CASE 里不精确行置 NULL，违反 NOT NULL → 语句原子失败
        -- → 迁移中止、0 行写入。违规行定位（人工）：
        --   SELECT `id`,`amount` FROM `orders`
        --     WHERE ABS(`amount`*100 - CAST(`amount`*100 AS SIGNED)) > 1e-3;
        -- 幂等防呆：amount 已非 DOUBLE（库已按新模型建过，如 CI --existing 分支）
        -- 时等值搬运，不错误 ×100。
        RENAME TABLE `orders` TO `orders_old`;
        CREATE TABLE IF NOT EXISTS `orders` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `title` VARCHAR(128) NOT NULL  COMMENT '标题',
    `amount` INT NOT NULL  COMMENT '金额（分）',
    `quantity` INT NOT NULL  COMMENT '数量' DEFAULT 1,
    `status` VARCHAR(16) NOT NULL  COMMENT '状态' DEFAULT 'pending',
    `customer_id` INT NOT NULL,
    -- FK 约束名在 MySQL 是 schema 级唯一：RENAME 后 orders_old 仍占用原名（1826 实测），
    --   新表必须换名；upgrade/downgrade 各用不同后缀避免互相冲突
    CONSTRAINT `fk_orders_customer_spec005up` FOREIGN KEY (`customer_id`) REFERENCES `customer` (`id`) ON DELETE RESTRICT
) CHARACTER SET utf8mb4 COMMENT='订单。客户订单';
        INSERT INTO `orders` (`id`, `created_at`, `updated_at`, `deleted`, `title`, `amount`, `quantity`, `status`, `customer_id`)
        SELECT `id`, `created_at`, `updated_at`, `deleted`, `title`,
            CASE
                WHEN EXISTS (SELECT 1 FROM information_schema.columns c
                             WHERE c.table_schema = DATABASE() AND c.table_name = 'orders'
                               AND c.column_name = 'amount' AND c.data_type <> 'double')
                    THEN `amount`
                WHEN ABS(`amount` * 100 - CAST(`amount` * 100 AS SIGNED)) <= 1e-3
                    THEN CAST(ROUND(`amount` * 100) AS SIGNED)
                ELSE NULL
            END,
            `quantity`, `status`, `customer_id`
        FROM `orders_old`;
        DROP TABLE `orders_old`;
"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        RENAME TABLE `orders` TO `orders_old`;
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
    CONSTRAINT `fk_orders_customer_spec005dn` FOREIGN KEY (`customer_id`) REFERENCES `customer` (`id`) ON DELETE RESTRICT
) CHARACTER SET utf8mb4 COMMENT='订单。客户订单';
        INSERT INTO `orders` (`id`, `created_at`, `updated_at`, `deleted`, `title`, `amount`, `quantity`, `status`, `customer_id`)
        SELECT `id`, `created_at`, `updated_at`, `deleted`, `title`,
            ROUND(`amount` / 100, 2),
            `quantity`, `status`, `customer_id`
        FROM `orders_old`;
        DROP TABLE `orders_old`;
"""
