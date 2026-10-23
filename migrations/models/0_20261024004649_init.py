from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE "account" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "username" VARCHAR(32) NOT NULL UNIQUE,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "phone" VARCHAR(14)  UNIQUE,
    "first_name" VARCHAR(64),
    "last_name" VARCHAR(64),
    "password" VARCHAR(255) NOT NULL,
    "disabled" INT NOT NULL  DEFAULT 0,
    "verified" INT NOT NULL  DEFAULT 0,
    "is_admin" INT NOT NULL  DEFAULT 0
) /* 用户账户模型，包含所有可识别用户信息 */;
CREATE TABLE "authentication_session" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "ip" VARCHAR(45) NOT NULL,
    "user_agent" VARCHAR(255),
    "expires" TIMESTAMP,
    "disabled" INT NOT NULL  DEFAULT 0,
    "requires_second_factor" INT NOT NULL  DEFAULT 0,
    "second_factor_verified" INT NOT NULL  DEFAULT 0,
    "bearer_id" INT REFERENCES "account" ("id") ON DELETE CASCADE
) /* 认证会话模型，用于用户登录 */;
CREATE TABLE "captcha_session" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "ip" VARCHAR(45) NOT NULL,
    "user_agent" VARCHAR(255),
    "expires" TIMESTAMP,
    "disabled" INT NOT NULL  DEFAULT 0,
    "code" VARCHAR(32) NOT NULL,
    "attempts" INT NOT NULL  DEFAULT 0,
    "bearer_id" INT REFERENCES "account" ("id") ON DELETE CASCADE
) /* 验证码会话模型 */;
CREATE TABLE "operation_log" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "account_name" VARCHAR(64),
    "operation" VARCHAR(128) NOT NULL,
    "operation_type" VARCHAR(64) NOT NULL,
    "detail" TEXT,
    "status" VARCHAR(16) NOT NULL  DEFAULT 'success',
    "ip_address" VARCHAR(45),
    "user_agent" VARCHAR(255),
    "account_id" INT REFERENCES "account" ("id") ON DELETE SET NULL
) /* 操作日志 */;
CREATE INDEX "idx_operation_l_operati_c9393b" ON "operation_log" ("operation_type");
CREATE INDEX "idx_operation_l_status_46a453" ON "operation_log" ("status");
CREATE TABLE "profile" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "full_name" VARCHAR(64),
    "nickname" VARCHAR(64),
    "avatar" VARCHAR(255),
    "mobile_phone" VARCHAR(32),
    "tel_phone" VARCHAR(32),
    "gender" VARCHAR(16),
    "birth_date" DATE,
    "address" VARCHAR(255),
    "work_start_date" DATE,
    "introduction" TEXT,
    "homepage" VARCHAR(255),
    "account_id" INT NOT NULL UNIQUE REFERENCES "account" ("id") ON DELETE CASCADE
) /* 用户个人资料，与账户一对一；所有资料字段均可为空 */;
CREATE TABLE "role" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "name" VARCHAR(64) NOT NULL UNIQUE,
    "description" VARCHAR(255),
    "permissions" JSON NOT NULL
) /* 角色模型，定义用户权限组 */;
CREATE TABLE "system_setting" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "key" VARCHAR(50) NOT NULL UNIQUE,
    "value" TEXT NOT NULL,
    "value_type" VARCHAR(16) NOT NULL  DEFAULT 'string',
    "description" VARCHAR(255),
    "category" VARCHAR(50) NOT NULL  DEFAULT 'general',
    "is_public" INT NOT NULL  DEFAULT 0
) /* 系统参数配置：值统一以字符串存储，``value_type`` 指明如何解释 */;
CREATE TABLE "two_step_session" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "ip" VARCHAR(45) NOT NULL,
    "user_agent" VARCHAR(255),
    "expires" TIMESTAMP,
    "disabled" INT NOT NULL  DEFAULT 0,
    "code" VARCHAR(32) NOT NULL,
    "attempts" INT NOT NULL  DEFAULT 0,
    "bearer_id" INT REFERENCES "account" ("id") ON DELETE CASCADE
) /* 两步验证会话模型 */;
CREATE TABLE "uploaded_file" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "filename" VARCHAR(255) NOT NULL,
    "stored_filename" VARCHAR(255) NOT NULL,
    "file_path" VARCHAR(512) NOT NULL,
    "file_type" VARCHAR(128),
    "file_size" REAL NOT NULL  DEFAULT 0,
    "category" VARCHAR(64),
    "download_count" INT NOT NULL  DEFAULT 0,
    "account_id" INT REFERENCES "account" ("id") ON DELETE SET NULL
) /* 上传文件记录 */;
CREATE INDEX "idx_uploaded_fi_file_pa_28d5b8" ON "uploaded_file" ("file_path");
CREATE TABLE "verification_tokens" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "deleted" INT NOT NULL  DEFAULT 0 /* 删除标记 */,
    "token" VARCHAR(128) NOT NULL UNIQUE /* 验证令牌 */,
    "token_type" VARCHAR(32) NOT NULL  /* 令牌类型，如 'activation', 'password_reset', 'two_factor' */,
    "expires_at" TIMESTAMP NOT NULL  /* 过期时间 */,
    "used" INT NOT NULL  DEFAULT 0 /* 是否已使用 */,
    "data" TEXT   /* 附加数据，存储为JSON格式 */,
    "account_id" INT NOT NULL REFERENCES "account" ("id") ON DELETE CASCADE
) /* 验证令牌模型 */;
CREATE TABLE "aerich" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "version" VARCHAR(255) NOT NULL,
    "app" VARCHAR(100) NOT NULL,
    "content" JSON NOT NULL
);
CREATE TABLE "account_role" (
    "account_id" INT NOT NULL REFERENCES "account" ("id") ON DELETE CASCADE,
    "role_id" INT NOT NULL REFERENCES "role" ("id") ON DELETE CASCADE
);"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        """
