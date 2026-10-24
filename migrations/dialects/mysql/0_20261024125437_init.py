from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE `account` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `username` VARCHAR(32) NOT NULL UNIQUE,
    `email` VARCHAR(255) NOT NULL UNIQUE,
    `phone` VARCHAR(14)  UNIQUE,
    `first_name` VARCHAR(64),
    `last_name` VARCHAR(64),
    `password` VARCHAR(255) NOT NULL,
    `disabled` BOOL NOT NULL  DEFAULT 0,
    `verified` BOOL NOT NULL  DEFAULT 0,
    `is_admin` BOOL NOT NULL  DEFAULT 0,
    `must_change_password` BOOL NOT NULL  DEFAULT 0
) CHARACTER SET utf8mb4 COMMENT='用户账户模型，包含所有可识别用户信息';
CREATE TABLE `authentication_session` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `ip` VARCHAR(45) NOT NULL,
    `user_agent` VARCHAR(255),
    `expires` DATETIME(6),
    `disabled` BOOL NOT NULL  DEFAULT 0,
    `requires_second_factor` BOOL NOT NULL  DEFAULT 0,
    `second_factor_verified` BOOL NOT NULL  DEFAULT 0,
    `bearer_id` INT,
    CONSTRAINT `fk_authenti_account_421ea818` FOREIGN KEY (`bearer_id`) REFERENCES `account` (`id`) ON DELETE CASCADE
) CHARACTER SET utf8mb4 COMMENT='认证会话模型，用于用户登录';
CREATE TABLE `captcha_session` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `ip` VARCHAR(45) NOT NULL,
    `user_agent` VARCHAR(255),
    `expires` DATETIME(6),
    `disabled` BOOL NOT NULL  DEFAULT 0,
    `code` VARCHAR(32) NOT NULL,
    `attempts` INT NOT NULL  DEFAULT 0,
    `bearer_id` INT,
    CONSTRAINT `fk_captcha__account_0b8e1ec3` FOREIGN KEY (`bearer_id`) REFERENCES `account` (`id`) ON DELETE CASCADE
) CHARACTER SET utf8mb4 COMMENT='验证码会话模型';
CREATE TABLE `operation_log` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `account_name` VARCHAR(64),
    `operation` VARCHAR(128) NOT NULL,
    `operation_type` VARCHAR(64) NOT NULL,
    `detail` LONGTEXT,
    `status` VARCHAR(16) NOT NULL  DEFAULT 'success',
    `ip_address` VARCHAR(45),
    `user_agent` VARCHAR(255),
    `account_id` INT,
    CONSTRAINT `fk_operatio_account_8f5c3bcb` FOREIGN KEY (`account_id`) REFERENCES `account` (`id`) ON DELETE SET NULL,
    KEY `idx_operation_l_operati_c9393b` (`operation_type`),
    KEY `idx_operation_l_status_46a453` (`status`)
) CHARACTER SET utf8mb4 COMMENT='操作日志';
CREATE TABLE `profile` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `full_name` VARCHAR(64),
    `nickname` VARCHAR(64),
    `avatar` VARCHAR(255),
    `mobile_phone` VARCHAR(32),
    `tel_phone` VARCHAR(32),
    `gender` VARCHAR(16),
    `birth_date` DATE,
    `address` VARCHAR(255),
    `work_start_date` DATE,
    `introduction` LONGTEXT,
    `homepage` VARCHAR(255),
    `account_id` INT NOT NULL UNIQUE,
    CONSTRAINT `fk_profile_account_9824d27b` FOREIGN KEY (`account_id`) REFERENCES `account` (`id`) ON DELETE CASCADE
) CHARACTER SET utf8mb4 COMMENT='用户个人资料，与账户一对一；所有资料字段均可为空';
CREATE TABLE `role` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `name` VARCHAR(64) NOT NULL UNIQUE,
    `description` VARCHAR(255),
    `permissions` JSON NOT NULL
) CHARACTER SET utf8mb4 COMMENT='角色模型，定义用户权限组';
CREATE TABLE `system_setting` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `key` VARCHAR(50) NOT NULL UNIQUE,
    `value` LONGTEXT NOT NULL,
    `value_type` VARCHAR(16) NOT NULL  DEFAULT 'string',
    `description` VARCHAR(255),
    `category` VARCHAR(50) NOT NULL  DEFAULT 'general',
    `is_public` BOOL NOT NULL  DEFAULT 0
) CHARACTER SET utf8mb4 COMMENT='系统参数配置：值统一以字符串存储，``value_type`` 指明如何解释';
CREATE TABLE `two_step_session` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `ip` VARCHAR(45) NOT NULL,
    `user_agent` VARCHAR(255),
    `expires` DATETIME(6),
    `disabled` BOOL NOT NULL  DEFAULT 0,
    `code` VARCHAR(32) NOT NULL,
    `attempts` INT NOT NULL  DEFAULT 0,
    `bearer_id` INT,
    CONSTRAINT `fk_two_step_account_148778ae` FOREIGN KEY (`bearer_id`) REFERENCES `account` (`id`) ON DELETE CASCADE
) CHARACTER SET utf8mb4 COMMENT='两步验证会话模型';
CREATE TABLE `uploaded_file` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `filename` VARCHAR(255) NOT NULL,
    `stored_filename` VARCHAR(255) NOT NULL,
    `file_path` VARCHAR(512) NOT NULL,
    `file_type` VARCHAR(128),
    `file_size` DOUBLE NOT NULL  DEFAULT 0,
    `category` VARCHAR(64),
    `download_count` INT NOT NULL  DEFAULT 0,
    `account_id` INT,
    CONSTRAINT `fk_uploaded_account_51aad114` FOREIGN KEY (`account_id`) REFERENCES `account` (`id`) ON DELETE SET NULL,
    KEY `idx_uploaded_fi_file_pa_28d5b8` (`file_path`)
) CHARACTER SET utf8mb4 COMMENT='上传文件记录';
CREATE TABLE `verification_tokens` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `created_at` DATETIME(6) NOT NULL  COMMENT '创建时间' DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL  COMMENT '更新时间' DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `deleted` BOOL NOT NULL  COMMENT '删除标记' DEFAULT 0,
    `token` VARCHAR(128) NOT NULL UNIQUE COMMENT '验证令牌',
    `token_type` VARCHAR(32) NOT NULL  COMMENT '令牌类型，如 \\'activation\\', \\'password_reset\\', \\'two_factor\\'',
    `expires_at` DATETIME(6) NOT NULL  COMMENT '过期时间',
    `used` BOOL NOT NULL  COMMENT '是否已使用' DEFAULT 0,
    `data` LONGTEXT   COMMENT '附加数据，存储为JSON格式',
    `account_id` INT NOT NULL,
    CONSTRAINT `fk_verifica_account_a65dc5e5` FOREIGN KEY (`account_id`) REFERENCES `account` (`id`) ON DELETE CASCADE
) CHARACTER SET utf8mb4 COMMENT='验证令牌模型';
CREATE TABLE `aerich` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `version` VARCHAR(255) NOT NULL,
    `app` VARCHAR(100) NOT NULL,
    `content` JSON NOT NULL
) CHARACTER SET utf8mb4;
CREATE TABLE `account_role` (
    `account_id` INT NOT NULL,
    `role_id` INT NOT NULL,
    FOREIGN KEY (`account_id`) REFERENCES `account` (`id`) ON DELETE CASCADE,
    FOREIGN KEY (`role_id`) REFERENCES `role` (`id`) ON DELETE CASCADE
) CHARACTER SET utf8mb4;"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        """
