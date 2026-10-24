from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE "account" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
    "username" VARCHAR(32) NOT NULL UNIQUE,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "phone" VARCHAR(14)  UNIQUE,
    "first_name" VARCHAR(64),
    "last_name" VARCHAR(64),
    "password" VARCHAR(255) NOT NULL,
    "disabled" BOOL NOT NULL  DEFAULT False,
    "verified" BOOL NOT NULL  DEFAULT False,
    "is_admin" BOOL NOT NULL  DEFAULT False,
    "must_change_password" BOOL NOT NULL  DEFAULT False
);
COMMENT ON COLUMN "account"."created_at" IS '创建时间';
COMMENT ON COLUMN "account"."updated_at" IS '更新时间';
COMMENT ON COLUMN "account"."deleted" IS '删除标记';
COMMENT ON TABLE "account" IS '用户账户模型，包含所有可识别用户信息';
CREATE TABLE "authentication_session" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
    "ip" VARCHAR(45) NOT NULL,
    "user_agent" VARCHAR(255),
    "expires" TIMESTAMPTZ,
    "disabled" BOOL NOT NULL  DEFAULT False,
    "requires_second_factor" BOOL NOT NULL  DEFAULT False,
    "second_factor_verified" BOOL NOT NULL  DEFAULT False,
    "bearer_id" INT REFERENCES "account" ("id") ON DELETE CASCADE
);
COMMENT ON COLUMN "authentication_session"."created_at" IS '创建时间';
COMMENT ON COLUMN "authentication_session"."updated_at" IS '更新时间';
COMMENT ON COLUMN "authentication_session"."deleted" IS '删除标记';
COMMENT ON TABLE "authentication_session" IS '认证会话模型，用于用户登录';
CREATE TABLE "captcha_session" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
    "ip" VARCHAR(45) NOT NULL,
    "user_agent" VARCHAR(255),
    "expires" TIMESTAMPTZ,
    "disabled" BOOL NOT NULL  DEFAULT False,
    "code" VARCHAR(32) NOT NULL,
    "attempts" INT NOT NULL  DEFAULT 0,
    "bearer_id" INT REFERENCES "account" ("id") ON DELETE CASCADE
);
COMMENT ON COLUMN "captcha_session"."created_at" IS '创建时间';
COMMENT ON COLUMN "captcha_session"."updated_at" IS '更新时间';
COMMENT ON COLUMN "captcha_session"."deleted" IS '删除标记';
COMMENT ON TABLE "captcha_session" IS '验证码会话模型';
CREATE TABLE "operation_log" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
    "account_name" VARCHAR(64),
    "operation" VARCHAR(128) NOT NULL,
    "operation_type" VARCHAR(64) NOT NULL,
    "detail" TEXT,
    "status" VARCHAR(16) NOT NULL  DEFAULT 'success',
    "ip_address" VARCHAR(45),
    "user_agent" VARCHAR(255),
    "account_id" INT REFERENCES "account" ("id") ON DELETE SET NULL
);
CREATE INDEX "idx_operation_l_operati_c9393b" ON "operation_log" ("operation_type");
CREATE INDEX "idx_operation_l_status_46a453" ON "operation_log" ("status");
COMMENT ON COLUMN "operation_log"."created_at" IS '创建时间';
COMMENT ON COLUMN "operation_log"."updated_at" IS '更新时间';
COMMENT ON COLUMN "operation_log"."deleted" IS '删除标记';
COMMENT ON TABLE "operation_log" IS '操作日志';
CREATE TABLE "profile" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
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
);
COMMENT ON COLUMN "profile"."created_at" IS '创建时间';
COMMENT ON COLUMN "profile"."updated_at" IS '更新时间';
COMMENT ON COLUMN "profile"."deleted" IS '删除标记';
COMMENT ON TABLE "profile" IS '用户个人资料，与账户一对一；所有资料字段均可为空';
CREATE TABLE "role" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
    "name" VARCHAR(64) NOT NULL UNIQUE,
    "description" VARCHAR(255),
    "permissions" JSONB NOT NULL
);
COMMENT ON COLUMN "role"."created_at" IS '创建时间';
COMMENT ON COLUMN "role"."updated_at" IS '更新时间';
COMMENT ON COLUMN "role"."deleted" IS '删除标记';
COMMENT ON TABLE "role" IS '角色模型，定义用户权限组';
CREATE TABLE "system_setting" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
    "key" VARCHAR(50) NOT NULL UNIQUE,
    "value" TEXT NOT NULL,
    "value_type" VARCHAR(16) NOT NULL  DEFAULT 'string',
    "description" VARCHAR(255),
    "category" VARCHAR(50) NOT NULL  DEFAULT 'general',
    "is_public" BOOL NOT NULL  DEFAULT False
);
COMMENT ON COLUMN "system_setting"."created_at" IS '创建时间';
COMMENT ON COLUMN "system_setting"."updated_at" IS '更新时间';
COMMENT ON COLUMN "system_setting"."deleted" IS '删除标记';
COMMENT ON TABLE "system_setting" IS '系统参数配置：值统一以字符串存储，``value_type`` 指明如何解释';
CREATE TABLE "two_step_session" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
    "ip" VARCHAR(45) NOT NULL,
    "user_agent" VARCHAR(255),
    "expires" TIMESTAMPTZ,
    "disabled" BOOL NOT NULL  DEFAULT False,
    "code" VARCHAR(32) NOT NULL,
    "attempts" INT NOT NULL  DEFAULT 0,
    "bearer_id" INT REFERENCES "account" ("id") ON DELETE CASCADE
);
COMMENT ON COLUMN "two_step_session"."created_at" IS '创建时间';
COMMENT ON COLUMN "two_step_session"."updated_at" IS '更新时间';
COMMENT ON COLUMN "two_step_session"."deleted" IS '删除标记';
COMMENT ON TABLE "two_step_session" IS '两步验证会话模型';
CREATE TABLE "uploaded_file" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
    "filename" VARCHAR(255) NOT NULL,
    "stored_filename" VARCHAR(255) NOT NULL,
    "file_path" VARCHAR(512) NOT NULL,
    "file_type" VARCHAR(128),
    "file_size" DOUBLE PRECISION NOT NULL  DEFAULT 0,
    "category" VARCHAR(64),
    "download_count" INT NOT NULL  DEFAULT 0,
    "account_id" INT REFERENCES "account" ("id") ON DELETE SET NULL
);
CREATE INDEX "idx_uploaded_fi_file_pa_28d5b8" ON "uploaded_file" ("file_path");
COMMENT ON COLUMN "uploaded_file"."created_at" IS '创建时间';
COMMENT ON COLUMN "uploaded_file"."updated_at" IS '更新时间';
COMMENT ON COLUMN "uploaded_file"."deleted" IS '删除标记';
COMMENT ON TABLE "uploaded_file" IS '上传文件记录';
CREATE TABLE "verification_tokens" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" BOOL NOT NULL  DEFAULT False,
    "token" VARCHAR(128) NOT NULL UNIQUE,
    "token_type" VARCHAR(32) NOT NULL,
    "expires_at" TIMESTAMPTZ NOT NULL,
    "used" BOOL NOT NULL  DEFAULT False,
    "data" TEXT,
    "account_id" INT NOT NULL REFERENCES "account" ("id") ON DELETE CASCADE
);
COMMENT ON COLUMN "verification_tokens"."created_at" IS '创建时间';
COMMENT ON COLUMN "verification_tokens"."updated_at" IS '更新时间';
COMMENT ON COLUMN "verification_tokens"."deleted" IS '删除标记';
COMMENT ON COLUMN "verification_tokens"."token" IS '验证令牌';
COMMENT ON COLUMN "verification_tokens"."token_type" IS '令牌类型，如 ''activation'', ''password_reset'', ''two_factor''';
COMMENT ON COLUMN "verification_tokens"."expires_at" IS '过期时间';
COMMENT ON COLUMN "verification_tokens"."used" IS '是否已使用';
COMMENT ON COLUMN "verification_tokens"."data" IS '附加数据，存储为JSON格式';
COMMENT ON TABLE "verification_tokens" IS '验证令牌模型';
CREATE TABLE "aerich" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "version" VARCHAR(255) NOT NULL,
    "app" VARCHAR(100) NOT NULL,
    "content" JSONB NOT NULL
);
CREATE TABLE "account_role" (
    "account_id" INT NOT NULL REFERENCES "account" ("id") ON DELETE CASCADE,
    "role_id" INT NOT NULL REFERENCES "role" ("id") ON DELETE CASCADE
);"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        """
