from sanic.exceptions import SanicException  # Importing 'SanicException' from 'sanic.exceptions' (从 'sanic.exceptions' 导入 'SanicException')
from utils import json  # Importing 'json' function from 'utils' (从 'utils' 导入 'json' 函数)

# 自定义异常类，用于处理与安全性相关的错误
class SecurityError(SanicException):
    """
    Sanic 安全相关错误。

    属性:
        json (HTTPResponse): 安全错误的 JSON 响应。

    Args:
        message (str): 错误消息。
        code (int): HTTP 错误码。
    """

    def __init__(self, message: str, code: int):
        self.json = json(message, self.__class__.__name__, code)
        super().__init__(message, code)

# 当资源无法找到时引发的异常
class NotFoundError(SecurityError):
    """
    当资源无法找到时引发。

    Args:
        message (str): 错误消息。
    """

    def __init__(self, message):
        super().__init__(message, 404)

# 当尝试访问已删除资源时引发的异常
class DeletedError(SecurityError):
    """
    尝试访问已删除资源时引发。

    Args:
        message (str): 错误消息。
    """

    def __init__(self, message):
        super().__init__(message, 410)

# 所有其他帐户错误派生自的基本帐户错误
class AccountError(SecurityError):
    """
    所有其他帐户错误派生自的基本帐户错误。

    Args:
        message (str): 错误消息。
        code (int): HTTP 错误码。
    """

    def __init__(self, message, code):
        super().__init__(message, code)

# 当帐户被禁用时引发的异常
class DisabledError(AccountError):
    """
    当帐户被禁用时引发。

    Args:
        message (str): 错误消息，默认为 "Account is disabled."。
        code (int): HTTP 错误码，默认为 401。
    """

    def __init__(self, message: str = "Account is disabled.", code: int = 401):
        super().__init__(message, code)

# 当帐户未验证时引发的异常
class UnverifiedError(AccountError):
    """
    当帐户未验证时引发。

    Args:
        message (str): 默认为 "Account requires verification."。
    """

    def __init__(self):
        super().__init__("Account requires verification.", 401)

# 当帐户已验证时引发的异常
class VerifiedError(AccountError):
    """
    当帐户已验证时引发。

    Args:
        message (str): 默认为 "Account already verified."。
    """

    def __init__(self):
        super().__init__("Account already verified.", 403)

# 所有其他会话错误派生自的基本会话错误
class SessionError(SecurityError):
    """
    所有其他会话错误派生自的基本会话错误。

    Args:
        message (str): 错误消息。
        code (int): HTTP 错误码，默认为 401。
    """

    def __init__(self, message, code=401):
        super().__init__(message, code)

# 当客户端 JWT 无效时引发的异常
class JWTDecodeError(SessionError):
    """
    当客户端 JWT 无效时引发。

    Args:
        message (str): 错误消息，默认为 400。
    """

    def __init__(self, message, code=400):
        super().__init__(message, code)

# 当会话被停用时引发的异常
class DeactivatedError(SessionError):
    """
    当会话被停用时引发。

    Args:
        message (str): 默认为 "Session is deactivated."。
        code (int): HTTP 错误码，默认为 401。
    """

    def __init__(self, message: str = "Session is deactivated.", code: int = 401):
        super().__init__(message, code)

# 当会话已过期时引发的异常
class ExpiredError(SessionError):
    """
    当会话已过期时引发。

    Args:
        message (str): 默认为 "Session has expired"。
    """

    def __init__(self):
        super().__init__("Session has expired")

# 当身份验证会话的两因素要求未满足时引发的异常
class SecondFactorRequiredError(SessionError):
    """
    当身份验证会话的两因素要求未满足时引发。

    Args:
        message (str): 默认为 "Session requires second factor for authentication."。
    """

    def __init__(self):
        super().__init__("Session requires second factor for authentication.")

# 当身份验证会话的两因素要求已满足时引发的异常
class SecondFactorFulfilledError(SessionError):
    """
    当身份验证会话的两因素要求已满足时引发。

    Args:
        message (str): 默认为 "Session second factor requirement already met."。
        code (int): HTTP 错误码，默认为 403。
    """

    def __init__(self):
        super().__init__("Session second factor requirement already met.", 403)

# 当会话挑战尝试无效时引发的异常
class ChallengeError(SessionError):
    """
    当会话挑战尝试无效时引发。

    Args:
        message (str): 错误消息。
    """

    def __init__(self, message):
        super().__init__(message)

# 当会话的挑战尝试次数达到上限时引发的异常
class MaxedOutChallengeError(ChallengeError):
    """
    当会话的挑战尝试次数达到上限时引发。

    Args:
        message (str): 默认为 "The maximum amount of attempts has been reached."。
    """

    def __init__(self):
        super().__init__("The maximum amount of attempts has been reached.")

# 当帐户权限或角色不足以执行操作时引发的异常
class AuthorizationError(SecurityError):
    """
    当帐户权限或角色不足以执行操作时引发。

    Args:
        message (str): 错误消息。
    """

    def __init__(self, message):
        super().__init__(message, 403)

# 当凭据无效时引发的异常
class CredentialsError(SecurityError):
    """
    当凭据无效时引发。
    Args:
        message (str): 错误消息，默认为 400。
        code (int): HTTP 错误码，默认为 400。
    """

    def __init__(self, message, code=400):
        super().__init__(message, code)
