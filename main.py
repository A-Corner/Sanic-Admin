# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : main.py
# Time       ：10/9/2023 8:46 pm
# Author     : A-Corner
# version    ：python 3.11
# Description：
"""
# 导入所需的库和模块
from sanic import Sanic  # Sanic框架库
from tortoise.contrib.sanic import register_tortoise  # Tortoise ORM的Sanic适配器
from sanic_cors import CORS
from web import *
from auth import *
from restful_api import *
# from sa_model import model_base, model_others
# 导入Sanic Security模块的各个功能
from authentication import (
    create_initial_admin_account,  # 创建初始管理员账户
)
from verification import (
    request_two_step_verification,  # 请求两步验证
    requires_two_step_verification,  # 需要两步验证的装饰器
    verify_account,  # 验证账户
    request_captcha,  # 请求验证码
    requires_captcha,  # 需要验证码的装饰器
)
from configuration import config as sa_config  # 安全配置
from exceptions import SecurityError  # 安全相关异常

# 创建Sanic应用程序实例
app = Sanic("SanicAdmin")
CORS(app, automatic_options=True)
password_hasher = PasswordHasher()  # 创建密码哈希器实例

# 设置静态文件夹的路径
# static_folder = Path(__file__).resolve().parent / 'static'
# app.static('/', static_folder, name='static')

# 指定静态文件目录
app.static("/static", ".amis")
# 指定模板目录
app.blueprint(auth_bp)
app.blueprint(two_step_bp)
app.blueprint(role_bp)
app.blueprint(capt_bp)
app.blueprint(account_bp)
app.blueprint(login_bp)
app.blueprint(index_bp)
app.blueprint(refapi_bp)


# 处理安全错误的异常处理器

@app.exception(SecurityError)
async def on_security_error(request, exception):
    """
    处理安全错误，并返回正确的响应。
    """
    return exception.json


# 配置安全相关参数
# 用于生成和签名JWT的密钥
sa_config.SECRET = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAww3pEiUx6wMFawJNAHCI80Qj3eyrP6Yx3LNNluQZXMyZkd+6ugBN9e1hw7v2z2PwmJENhYrqbBHU4vHCHEEZjdZIQRqwriFpeeoqMA1
ecgwJz3fOuYo6WrUbS6pEyJ9vtjh5TaeZLzER+KIK2uvsjsQnFVt41hh3Xd+tR9p+QXT8aRep9hp4XLF87QlDVDrZIStfVn25+ZfSfKH+WYBUglZBmz/K6uW
41mSRuuH3Pu/lnPgGvsxtT7KE8dkbyrI+Tyg0pniOYdxBxgpu06S6LTC8Zou0U0SGd6uOMUHT86H8uxbDTa8CNiGI251QMHlkstd6FFYu5lJQcuppOm79iQI
DAQABAoIBAACRz1RBMmV9ruIFWtcNu24u1SBw8FAniW4SGuPBbxeg1KcmOlegx3IdkBhG7j9hBF5+S/3ZhGTGhYdglYcS2aSMK0Q6ofd4NDMk+bzlIdEZNTV
bTnlle1vBjVjxOoIP7aL6mC/HFO7T+SYqjIGkjsxYFHf1DFu0nHS5OA/rOoEt1SZA5DO0dCd1IjuPvKsvJIRErjnFuW6bs9K7XNpE2gHKvtvzVFRQC2F7AY7
b45cx6QZ08yCbToITRI59RzGgrpqIsJI0N5yT96DUALQDkAJz4XzhS8+bHoCDGeTPfJLq4xXcLrtFSk5Mhp4eIOPCI/fv3IO8JnSopgeP+y+NeFMCgYEA/rq
0R5v9JuxtcbXsFXua5KWoDojOvHkeP93F5eGSDu8iRo/4zhyHWGhZuMIuMARAOJ7tAyWxDTzoSILhC4+fF6WQJKiBIlLLGXFyJ9qgq2eN+Z/b9+k6PotQV9z
unmIN8vuCrtPBlVbOMrofGHG85zSDyDDDUXZoh7ko8tJ3nosCgYEAxAb/8E/fmEADxJZSFoqwlElXm6h7sfThrhjf12ENwBv7AvH8XsiNVQsIGnoVxeHQJ7U
0pROucD/iykf8I9+ou9ZBQyfoRJiOkzExeMWEyhmGyGmcNCZ1kKK/RZu6Bks/EoqnpVH9bUjjAwSXeFRZE3zfsAclQr3BYjqFjQzuSrsCgYEA7RhLBPwkPT6
C//wcqkJKgdfO/PhJtRPnG/sIYFf84vmiJZuMMgxLzfYSzO2wn/DU9d63LN7AVVoDurpXTbN4mUH5UKWmzJPThvMZFg9gzSmt9FLfI3lqRRzWw3FYiQMriKa
hlKh03tPVSVID73SuJ2Wx43u/0OstkGa/voQ34tECgYA+G2mjnerdtgp7kpTXh4GCueoD61GlhEyseD0TZDCTGUpiGIE5FpmQxDoBCYU0eOMWcZcIZj/yWIt
mQ4BjbU1slel/eXlhomQpxoBCH3J/Ba9qd+uBql29QZMQXtKFg/mryjprapq8sUcbgazr9u1x+zJz9w+bIbvPf3MoyVwGWQKBgQDXKMG9fV+/61imgsOZTyd
2ld8MnIWAeUGgk5e6P+niAOPGFSPue3FgGvLURiJtuu05dM9U9pQhtGVrCwHcT9Yixiwpnyw31DQp3uU91DhrtHyRIf3H/ywrWLwY4Z+TsktW6UPoe2cyGbN
1G1CHHo/vq8zPNkVWmhciIUeHR3YJbw==
-----END RSA PRIVATE KEY-----
"""
# 密钥-- --公钥
sa_config.PUBLIC_SECRET = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAww3pEiUx6wMFawJNAHCI80Qj3eyrP6Yx3LNNluQZXMyZkd+6ugBN9e1hw7v2z2PwmJENhYrqbBHU
4vHCHEEZjdZIQRqwriFpeeoqMA1ecgwJz3fOuYo6WrUbS6pEyJ9vtjh5TaeZLzER+KIK2uvsjsQnFVt41hh3Xd+tR9p+QXT8aRep9hp4XLF87QlDVDrZIStf
Vn25+ZfSfKH+WYBUglZBmz/K6uW41mSRuuH3Pu/lnPgGvsxtT7KE8dkbyrI+Tyg0pniOYdxBxgpu06S6LTC8Zou0U0SGd6uOMUHT86H8uxbDTa8CNiGI251Q
MHlkstd6FFYu5lJQcuppOm79iQIDAQAB
-----END PUBLIC KEY-----
"""
# 指定字体文件的路径
FONT_LIST = [
    "Chalkduster.ttf",
    "Courier New.ttf",
    "Courier New Bold.ttf",
    "Courier New Bold Italic.ttf",
    "Courier New Italic.ttf",
]
sa_config.INITIAL_ADMIN_EMAIL = "SAdmin@Sanic.com"  # 创建初始管理员帐户时使用的电子邮件
sa_config.SESSION_ENCODING_ALGORITHM = "RS256"  # 用于将会话编码为JWT的算法 默认 ：HS256
sa_config.ALLOW_LOGIN_WITH_USERNAME = True  # 是否允许使用用户名登录
sa_config.SESSION_SECURE = False  # session cookie的Secure属性
sa_config.AUTHENTICATION_SESSION_EXPIRATION = 604800  # 认证会话的过期时间（秒）-- 7day
sa_config.INITIAL_ADMIN_PASSWORD = "SAdmin@123"  # 创建初始管理员帐户时使用的密码
sa_config.DATABASE_URL = "sqlite://SA_Admin_DB.sqlite3"
sa_config.CAPTCHA_FONT = f".amis/fonts/{FONT_LIST[1]}"
register_tortoise(
    app,
    db_url=sa_config.DATABASE_URL,
    modules={
        "models": ["models"]
        # 'models': ['__main__'],
    },
    generate_schemas=True,
)
create_initial_admin_account(app)


if __name__ == "__main__":
    app.run(host="127.0.0.1",
            port=22222,
            workers=1,
            debug=True,
            auto_reload=True)
