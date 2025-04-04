#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
验证模块，提供账户激活和二步验证功能
"""

import secrets
import datetime
from sanic.request import Request
from app.models import Account, VerificationToken, TwoFactorMethod
from app.services.exceptions import (
    VerificationError,
    TokenExpiredError,
    TokenInvalidError
)
from app.config import settings


async def generate_verification_token(account: Account, token_type: str, expiry_hours: int = 24):
    """
    生成验证令牌
    
    Args:
        account: 账户实例
        token_type: 令牌类型，如 'activation', 'password_reset', 'two_factor'
        expiry_hours: 令牌过期时间（小时）
        
    Returns:
        VerificationToken: 生成的验证令牌实例
    """
    # 删除该账户已有的同类型令牌
    await VerificationToken.filter(account_id=account.id, token_type=token_type).delete()
    
    # 生成令牌
    token = secrets.token_urlsafe(32)
    expires_at = datetime.datetime.now() + datetime.timedelta(hours=expiry_hours)
    
    # 创建令牌记录
    verification_token = await VerificationToken.create(
        account=account,
        token=token,
        token_type=token_type,
        expires_at=expires_at
    )
    
    return verification_token


async def validate_token(token: str, token_type: str):
    """
    验证令牌有效性
    
    Args:
        token: 令牌字符串
        token_type: 令牌类型
        
    Returns:
        VerificationToken: 令牌实例
        
    Raises:
        TokenInvalidError: 令牌无效
        TokenExpiredError: 令牌已过期
    """
    # 查找令牌
    verification_token = await VerificationToken.filter(token=token, token_type=token_type).first()
    
    if not verification_token:
        raise TokenInvalidError("无效的验证令牌")
    
    # 检查令牌是否过期
    if verification_token.expires_at < datetime.datetime.now():
        # 删除过期令牌
        await verification_token.delete()
        raise TokenExpiredError("验证令牌已过期")
    
    return verification_token


async def activate_account(token: str):
    """
    激活账户
    
    Args:
        token: 激活令牌
        
    Returns:
        Account: 激活的账户实例
        
    Raises:
        TokenInvalidError: 令牌无效
        TokenExpiredError: 令牌已过期
        VerificationError: 验证错误
    """
    # 验证令牌
    verification_token = await validate_token(token, 'activation')
    
    # 获取账户
    account = await verification_token.account.get()
    
    if account.is_active:
        # 删除已使用的令牌
        await verification_token.delete()
        raise VerificationError("账户已激活")
    
    # 激活账户
    account.is_active = True
    await account.save()
    
    # 删除已使用的令牌
    await verification_token.delete()
    
    return account


async def reset_password(token: str, new_password: str):
    """
    重置密码
    
    Args:
        token: 重置密码令牌
        new_password: 新密码
        
    Returns:
        Account: 更新密码的账户实例
        
    Raises:
        TokenInvalidError: 令牌无效
        TokenExpiredError: 令牌已过期
    """
    # 验证令牌
    verification_token = await validate_token(token, 'password_reset')
    
    # 获取账户
    account = await verification_token.account.get()
    
    # 更新密码
    account.set_password(new_password)
    await account.save()
    
    # 删除已使用的令牌
    await verification_token.delete()
    
    return account


async def setup_two_factor(account: Account, method: TwoFactorMethod, details: str = None):
    """
    设置二步验证
    
    Args:
        account: 账户实例
        method: 二步验证方法（如 'sms', 'email', 'app'）
        details: 方法详情（如电话号码、电子邮件地址）
        
    Returns:
        bool: 设置成功返回True
    """
    # 更新账户二步验证设置
    account.two_factor_method = method
    
    if details:
        if method == TwoFactorMethod.SMS:
            account.phone_number = details
        elif method == TwoFactorMethod.EMAIL:
            account.email = details
    
    account.two_factor_enabled = True
    await account.save()
    
    return True


async def disable_two_factor(account: Account):
    """
    禁用二步验证
    
    Args:
        account: 账户实例
        
    Returns:
        bool: 禁用成功返回True
    """
    account.two_factor_enabled = False
    await account.save()
    
    return True


async def generate_two_factor_code(account: Account):
    """
    生成二步验证码
    
    Args:
        account: 账户实例
        
    Returns:
        str: 验证码
        VerificationToken: 验证令牌实例
    """
    # 生成6位随机数字验证码
    code = ''.join(secrets.choice('0123456789') for _ in range(6))
    
    # 创建验证令牌，1小时有效期
    verification_token = await generate_verification_token(account, 'two_factor', 1)
    
    # 保存验证码到令牌数据字段
    verification_token.data = {'code': code}
    await verification_token.save()
    
    return code, verification_token


async def verify_two_factor_code(account: Account, code: str):
    """
    验证二步验证码
    
    Args:
        account: 账户实例
        code: 验证码
        
    Returns:
        bool: 验证成功返回True
        
    Raises:
        TokenInvalidError: 验证码无效
        TokenExpiredError: 验证码已过期
    """
    # 查找该账户的二步验证令牌
    verification_token = await VerificationToken.filter(
        account_id=account.id,
        token_type='two_factor'
    ).first()
    
    if not verification_token:
        raise TokenInvalidError("无效的验证码")
    
    # 检查令牌是否过期
    if verification_token.expires_at < datetime.datetime.now():
        # 删除过期令牌
        await verification_token.delete()
        raise TokenExpiredError("验证码已过期")
    
    # 验证码比对
    if verification_token.data.get('code') != code:
        raise TokenInvalidError("验证码错误")
    
    # 删除已使用的令牌
    await verification_token.delete()
    
    return True


async def get_captcha_image():
    """
    生成图形验证码
    
    Returns:
        tuple: (验证码文本, 图像数据base64字符串)
    """
    from captcha.image import ImageCaptcha
    import random
    import string
    import base64
    from io import BytesIO
    
    # 生成随机验证码文本
    chars = string.ascii_uppercase + string.digits
    captcha_text = ''.join(random.choice(chars) for _ in range(4))
    
    # 生成图像
    image = ImageCaptcha(width=160, height=60)
    data = image.generate(captcha_text)
    
    # 转换为base64
    buffer = BytesIO()
    image.write(captcha_text, buffer, format='PNG')
    buffer.seek(0)
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return captcha_text, f"data:image/png;base64,{img_str}"


async def store_captcha(request: Request, captcha_text: str):
    """
    存储验证码到会话
    
    Args:
        request: 请求对象
        captcha_text: 验证码文本
    """
    if hasattr(request, 'session'):
        request.session['captcha'] = captcha_text.upper()
        request.session['captcha_time'] = datetime.datetime.now().timestamp()


async def verify_captcha(request: Request, captcha_input: str):
    """
    验证用户输入的验证码
    
    Args:
        request: 请求对象
        captcha_input: 用户输入的验证码
        
    Returns:
        bool: 验证成功返回True，失败返回False
    """
    if not hasattr(request, 'session'):
        return False
    
    stored_captcha = request.session.get('captcha')
    captcha_time = request.session.get('captcha_time')
    
    if not stored_captcha or not captcha_time:
        return False
    
    # 检查验证码是否过期（5分钟有效期）
    now = datetime.datetime.now().timestamp()
    if now - captcha_time > 300:
        # 清除过期验证码
        del request.session['captcha']
        del request.session['captcha_time']
        return False
    
    # 验证码比对（不区分大小写）
    is_valid = stored_captcha.upper() == captcha_input.upper()
    
    # 验证后清除验证码，防止重复使用
    del request.session['captcha']
    del request.session['captcha_time']
    
    return is_valid 