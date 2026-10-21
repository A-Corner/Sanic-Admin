#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
异常处理模块，定义所有应用可能抛出的异常类型
"""

class BaseError(Exception):
    """基础异常类"""
    status_code = 500
    error_code = "INTERNAL_ERROR"
    message = "服务器内部错误"
    
    def __init__(self, message=None, status_code=None, error_code=None):
        if message:
            self.message = message
        if status_code:
            self.status_code = status_code
        if error_code:
            self.error_code = error_code
        super().__init__(self.message)
    
    def to_dict(self):
        """将异常信息转换为字典，用于JSON响应"""
        return {
            "error": self.error_code,
            "message": self.message,
            "status": self.status_code
        }


class SecurityError(BaseError):
    """安全相关错误（认证、授权、会话、账户状态）的公共基类"""
    status_code = 400
    error_code = "SECURITY_ERROR"
    message = "安全校验失败"

    @property
    def json(self) -> dict:
        """JSON 可序列化的错误信息（与 to_dict 等价）"""
        return self.to_dict()


# 认证相关异常
class AuthenticationError(SecurityError):
    """认证错误的基类"""
    status_code = 401
    error_code = "AUTHENTICATION_ERROR"
    message = "认证失败"


class CredentialsError(AuthenticationError):
    """凭据缺失或不正确"""
    error_code = "CREDENTIALS_ERROR"
    message = "凭据无效"


class InvalidCredentialsError(AuthenticationError):
    """无效的凭证"""
    error_code = "INVALID_CREDENTIALS"
    message = "用户名或密码错误"


class AccountInactiveError(AuthenticationError):
    """账户未激活"""
    error_code = "ACCOUNT_INACTIVE"
    message = "账户未激活"


class AccountLockedError(AuthenticationError):
    """账户被锁定"""
    error_code = "ACCOUNT_LOCKED"
    message = "账户已被锁定，请联系管理员"


class AccountError(AuthenticationError):
    """账户状态错误的基类"""
    error_code = "ACCOUNT_ERROR"
    message = "账户状态异常"


class DeletedError(AccountError):
    """账户或资源已被删除"""
    status_code = 410
    error_code = "DELETED"
    message = "已被删除"


class DisabledError(AccountError):
    """账户已被禁用"""
    status_code = 403
    error_code = "ACCOUNT_DISABLED"
    message = "账户已被禁用"


class UnverifiedError(AccountError):
    """账户尚未验证"""
    error_code = "ACCOUNT_UNVERIFIED"
    message = "账户需要验证"


class SessionError(AuthenticationError):
    """会话错误的基类"""
    error_code = "SESSION_ERROR"
    message = "会话无效"


class SessionNotFoundError(SessionError):
    """找不到会话"""
    error_code = "SESSION_NOT_FOUND"
    message = "找不到对应的会话"


class SessionValidationError(SessionError):
    """会话校验失败（已禁用、已删除等）"""
    error_code = "SESSION_INVALID"
    message = "会话校验失败"


class InvalidTokenError(SessionError):
    """令牌无效（签名错误、格式错误等）"""
    error_code = "INVALID_TOKEN"
    message = "无效的令牌"


class SessionExpiredError(SessionError):
    """会话过期"""
    error_code = "SESSION_EXPIRED"
    message = "会话已过期，请重新登录"


class TwoFactorRequiredError(AuthenticationError):
    """需要两步验证"""
    status_code = 403
    error_code = "TWO_FACTOR_REQUIRED"
    message = "需要完成两步验证"


# 授权相关异常
class AuthorizationError(SecurityError):
    """授权错误的基类"""
    status_code = 403
    error_code = "AUTHORIZATION_ERROR"
    message = "没有权限执行此操作"


class RoleRequiredError(AuthorizationError):
    """需要特定角色"""
    error_code = "ROLE_REQUIRED"
    message = "此操作需要特定角色权限"


class InsufficientPermissionsError(AuthorizationError):
    """权限不足"""
    error_code = "INSUFFICIENT_PERMISSIONS"
    message = "权限不足，无法执行此操作"


# 验证相关异常
class VerificationError(SecurityError):
    """验证错误的基类"""
    status_code = 400
    error_code = "VERIFICATION_ERROR"
    message = "验证失败"


class TokenInvalidError(VerificationError):
    """令牌无效"""
    error_code = "TOKEN_INVALID"
    message = "无效的验证令牌"


class TokenExpiredError(VerificationError):
    """令牌过期"""
    error_code = "TOKEN_EXPIRED"
    message = "验证令牌已过期"


class CaptchaError(VerificationError):
    """验证码错误"""
    error_code = "CAPTCHA_ERROR"
    message = "验证码错误或已过期"


# 资源相关异常
class ResourceError(BaseError):
    """资源错误的基类"""
    status_code = 400
    error_code = "RESOURCE_ERROR"
    message = "资源操作错误"


class ResourceNotFoundError(ResourceError):
    """资源不存在"""
    status_code = 404
    error_code = "RESOURCE_NOT_FOUND"
    message = "请求的资源不存在"


class NotFoundError(ResourceNotFoundError):
    """查询不到记录（模型层 get_via_* 等使用）"""
    error_code = "NOT_FOUND"
    message = "找不到请求的记录"


class ResourceAlreadyExistsError(ResourceError):
    """资源已存在"""
    error_code = "RESOURCE_ALREADY_EXISTS"
    message = "资源已存在"


class ResourceConflictError(ResourceError):
    """资源冲突"""
    error_code = "RESOURCE_CONFLICT"
    message = "资源状态冲突，无法执行操作"


# 输入验证异常
class ValidationError(BaseError):
    """输入验证错误"""
    status_code = 400
    error_code = "VALIDATION_ERROR"
    message = "输入数据验证失败"


# 限流异常
class RateLimitExceededError(BaseError):
    """超出速率限制"""
    status_code = 429
    error_code = "RATE_LIMIT_EXCEEDED"
    message = "请求过于频繁，请稍后重试"


# 系统异常
class ConfigurationError(BaseError):
    """配置错误"""
    error_code = "CONFIGURATION_ERROR"
    message = "系统配置错误"


class DatabaseError(BaseError):
    """数据库错误"""
    error_code = "DATABASE_ERROR"
    message = "数据库操作失败"


class ExternalServiceError(BaseError):
    """外部服务错误"""
    error_code = "EXTERNAL_SERVICE_ERROR"
    message = "外部服务调用失败" 