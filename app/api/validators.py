#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API参数验证模块，提供请求参数验证功能
"""

import functools
from typing import Dict, Any, List, Callable, Optional, Union, Type
from sanic.request import Request
from app.api.responses import APIResponse, APIError


class ValidationRule:
    """
    参数验证规则基类
    """
    def __init__(self, error_message: str = None):
        self.error_message = error_message
    
    def validate(self, value: Any, field_name: str) -> Union[bool, str]:
        """
        验证参数值
        
        Args:
            value: 要验证的值
            field_name: 字段名称
            
        Returns:
            Union[bool, str]: 验证通过返回True，失败返回错误消息
        """
        raise NotImplementedError("必须在子类中实现验证方法")


class Required(ValidationRule):
    """
    必需字段验证规则
    """
    def __init__(self, error_message: str = None):
        super().__init__(error_message or "此字段是必需的")
    
    def validate(self, value: Any, field_name: str) -> Union[bool, str]:
        if value is None or (isinstance(value, str) and value.strip() == ""):
            return self.error_message.format(field=field_name)
        return True


class Type(ValidationRule):
    """
    类型验证规则
    """
    def __init__(self, type_: Union[Type, List[Type]], error_message: str = None):
        self.type = type_
        super().__init__(error_message or f"此字段必须是{type_.__name__}类型")
    
    def validate(self, value: Any, field_name: str) -> Union[bool, str]:
        if value is None:
            return True
        
        if isinstance(self.type, list):
            if not any(isinstance(value, t) for t in self.type):
                type_names = [t.__name__ for t in self.type]
                return f"字段{field_name}必须是以下类型之一: {', '.join(type_names)}"
        elif not isinstance(value, self.type):
            return f"字段{field_name}必须是{self.type.__name__}类型"
        
        return True


class Length(ValidationRule):
    """
    长度验证规则
    """
    def __init__(self, min_: int = None, max_: int = None, error_message: str = None):
        self.min = min_
        self.max = max_
        
        if min_ is not None and max_ is not None:
            default_message = f"此字段长度必须在{min_}到{max_}之间"
        elif min_ is not None:
            default_message = f"此字段长度必须大于等于{min_}"
        elif max_ is not None:
            default_message = f"此字段长度必须小于等于{max_}"
        else:
            default_message = "长度验证错误"
        
        super().__init__(error_message or default_message)
    
    def validate(self, value: Any, field_name: str) -> Union[bool, str]:
        if value is None:
            return True
        
        if not hasattr(value, "__len__"):
            return f"字段{field_name}不支持长度验证"
        
        length = len(value)
        
        if self.min is not None and length < self.min:
            return f"字段{field_name}长度必须大于等于{self.min}"
        
        if self.max is not None and length > self.max:
            return f"字段{field_name}长度必须小于等于{self.max}"
        
        return True


class Range(ValidationRule):
    """
    范围验证规则
    """
    def __init__(self, min_: Union[int, float] = None, max_: Union[int, float] = None, 
                error_message: str = None):
        self.min = min_
        self.max = max_
        
        if min_ is not None and max_ is not None:
            default_message = f"此字段值必须在{min_}到{max_}之间"
        elif min_ is not None:
            default_message = f"此字段值必须大于等于{min_}"
        elif max_ is not None:
            default_message = f"此字段值必须小于等于{max_}"
        else:
            default_message = "范围验证错误"
        
        super().__init__(error_message or default_message)
    
    def validate(self, value: Any, field_name: str) -> Union[bool, str]:
        if value is None:
            return True
        
        try:
            value_float = float(value)
        except (ValueError, TypeError):
            return f"字段{field_name}必须是数字"
        
        if self.min is not None and value_float < self.min:
            return f"字段{field_name}值必须大于等于{self.min}"
        
        if self.max is not None and value_float > self.max:
            return f"字段{field_name}值必须小于等于{self.max}"
        
        return True


class Regex(ValidationRule):
    """
    正则表达式验证规则
    """
    def __init__(self, pattern: str, error_message: str = None):
        import re
        self.pattern = re.compile(pattern)
        super().__init__(error_message or "此字段格式不正确")
    
    def validate(self, value: Any, field_name: str) -> Union[bool, str]:
        if value is None:
            return True
        
        if not isinstance(value, str):
            return f"字段{field_name}必须是字符串才能进行正则验证"
        
        if not self.pattern.match(value):
            return f"字段{field_name}格式不正确"
        
        return True


class Email(ValidationRule):
    """
    电子邮件验证规则
    """
    def __init__(self, error_message: str = None):
        import re
        self.pattern = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
        super().__init__(error_message or "请输入有效的电子邮件地址")
    
    def validate(self, value: Any, field_name: str) -> Union[bool, str]:
        if value is None:
            return True
        
        if not isinstance(value, str):
            return f"字段{field_name}必须是字符串才能验证电子邮件"
        
        if not self.pattern.match(value):
            return f"字段{field_name}必须是有效的电子邮件地址"
        
        return True


class OneOf(ValidationRule):
    """
    枚举值验证规则
    """
    def __init__(self, choices: List[Any], error_message: str = None):
        self.choices = choices
        super().__init__(error_message or f"此字段必须是以下值之一: {', '.join(str(c) for c in choices)}")
    
    def validate(self, value: Any, field_name: str) -> Union[bool, str]:
        if value is None:
            return True
        
        if value not in self.choices:
            return f"字段{field_name}必须是以下值之一: {', '.join(str(c) for c in self.choices)}"
        
        return True


class Custom(ValidationRule):
    """
    自定义验证规则
    """
    def __init__(self, validator: Callable[[Any], Union[bool, str]], error_message: str = None):
        self.validator = validator
        super().__init__(error_message or "验证失败")
    
    def validate(self, value: Any, field_name: str) -> Union[bool, str]:
        result = self.validator(value)
        
        if result is True:
            return True
        
        if isinstance(result, str):
            return result
        
        return f"字段{field_name}{self.error_message}"


def validate_request(rules: Dict[str, List[ValidationRule]], 
                    source: str = 'json',
                    allow_unknown: bool = True):
    """
    请求参数验证装饰器
    
    用法示例:
    ```python
    @app.route('/api/user', methods=['POST'])
    @validate_request({
        'username': [Required(), Length(min_=3, max_=20)],
        'email': [Required(), Email()],
        'age': [Type(int), Range(min_=18)]
    })
    async def create_user(request):
        # 参数已验证通过
        pass
    ```
    
    Args:
        rules: 验证规则字典
        source: 参数来源，可选值: 'json', 'form', 'query', 'all'
        allow_unknown: 是否允许未知字段
        
    Returns:
        装饰器函数
    """
    def decorator(handler):
        @functools.wraps(handler)
        async def wrapper(request, *args, **kwargs):
            # 获取请求数据
            data = None
            
            if source == 'json':
                data = request.json or {}
            elif source == 'form':
                data = {key: request.form.get(key) for key in request.form.keys()}
            elif source == 'query':
                data = {key: request.args.get(key) for key in request.args.keys()}
            elif source == 'all':
                # 合并所有来源
                data = {}
                if request.json:
                    data.update(request.json)
                if request.form:
                    data.update({key: request.form.get(key) for key in request.form.keys()})
                if request.args:
                    data.update({key: request.args.get(key) for key in request.args.keys()})
            
            if data is None:
                data = {}
            
            # 验证参数
            errors = {}
            
            # 检查是否有未知字段
            if not allow_unknown:
                unknown_fields = [field for field in data.keys() if field not in rules]
                if unknown_fields:
                    errors['unknown_fields'] = f"不允许使用未知字段: {', '.join(unknown_fields)}"
            
            # 应用验证规则
            for field, field_rules in rules.items():
                field_value = data.get(field)
                
                for rule in field_rules:
                    result = rule.validate(field_value, field)
                    
                    if result is not True:
                        if field not in errors:
                            errors[field] = []
                        errors[field].append(result)
                        break  # 一个字段的第一个错误就停止验证
            
            # 如果有错误，返回错误响应
            if errors:
                return APIResponse.error(
                    message="参数验证失败",
                    error_code=APIError.VALIDATION_ERROR,
                    status_code=400,
                    details=errors
                )
            
            # 验证通过，继续处理请求
            request.validated_data = data
            return await handler(request, *args, **kwargs)
        
        return wrapper
    
    return decorator


def validate_path_param(param_name: str, rules: List[ValidationRule]):
    """
    路径参数验证装饰器
    
    用法示例:
    ```python
    @app.route('/api/user/<user_id>')
    @validate_path_param('user_id', [Required(), Type(int)])
    async def get_user(request, user_id):
        # 参数已验证通过
        pass
    ```
    
    Args:
        param_name: 参数名称
        rules: 验证规则列表
        
    Returns:
        装饰器函数
    """
    def decorator(handler):
        @functools.wraps(handler)
        async def wrapper(request, *args, **kwargs):
            # 获取路径参数值
            param_value = kwargs.get(param_name)
            
            # 应用验证规则
            for rule in rules:
                result = rule.validate(param_value, param_name)
                
                if result is not True:
                    return APIResponse.error(
                        message=f"路径参数'{param_name}'验证失败: {result}",
                        error_code=APIError.VALIDATION_ERROR,
                        status_code=400
                    )
            
            # 验证通过，继续处理请求
            return await handler(request, *args, **kwargs)
        
        return wrapper
    
    return decorator 