# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : restful_api.py
# Time       ：19/9/2023 8:46 pm
# Author     ：author A-Corner
# version    ：python 3.11
# Description：
"""
from sanic.log import logger
from sanic import Blueprint
from models import Account, get_or_create_record, Role
from auth import requires_authentication
from sanic.response import json
from sanic.views import HTTPMethodView
from exceptions import NotFoundError
from urllib.parse import unquote
from tortoise.expressions import Q


DEFAULT_RETURN_JSON = {
    "status": 0,
    "msg": "",
    "data": {}
}


refapi_bp = Blueprint('refapi', url_prefix='refapi')


# type: ignore
@refapi_bp.route("/<model_name>/<s_id:int>", methods=['GET', 'POST', 'PUT', 'DELETE'])
@requires_authentication
async def refapi_model_id(request, model_name: str, s_id: int):
    """
    函数根据提供的模型名称和 ID 处理特定模型的 HTTP 请求。它接受三个参数：request、model_name 和 s_id。
    :param request: “request”参数是一个对象，表示向 API 端点发出的 HTTP 请求。它包含 HTTP
    方法（GET、POST、PUT、DELETE）、标头、查询参数和请求正文等信息。
    :param model_name: “model_name”参数是一个表示模型名称的字符串。它用于根据提供的名称动态检索模型类。
    :type model_name: str
    :param s_id: 参数“s_id”是一个整数，表示特定模型实例的 ID。它用于检索、更新或删除模型的特定实例。如果 s_id 为 0，则表示应检索模型的所有实例。
    :type s_id: int
    :return: JSON 响应。
    This function handles HTTP requests for a specific model based on the provided model_name and s_id.
    It accepts three parameters: request, model_name, and s_id.
    :param request: The "request" parameter is an object representing the HTTP request made to the API endpoint.
    It contains information such as the HTTP method (GET, POST, PUT, DELETE), headers, query parameters, and request body.
    :param model_name: The "model_name" parameter is a string representing the name of the model.
    It is used to dynamically retrieve the model class based on the provided name.
    :type model_name: str
    :param s_id: The "s_id" parameter is an integer representing the ID of a specific model instance.
    It is used to retrieve, update, or delete a specific instance of the model. If s_id is 0, it means all instances of the model should be retrieved.
    :type s_id: int
    :return: JSON response.
    """
    # model = eval(model_name)
    model_name = model_name.lower()
    model = globals()[model_name.capitalize()]
    if request.method == 'GET':
        if s_id == 0:
            refapi = await model.all()
            return json([i.json for i in refapi])
        else:
            refapi = await model.get(id=s_id)
            return json(refapi.json)
    elif request.method == 'POST':
        refapi = await model.get(id=s_id)
        await refapi.update_from_dict(request.json)
        await refapi.save()
        return json(refapi.json)
    elif request.method == 'PUT' and s_id == 0:
        logger.info(f"「Debug Messages」 -- > {request.json}")
        # logger.info(f"「Debug Messages」 -- > {model.describe()}")
        # logger.info(f"「Debug Messages」 -- > {model._meta.fields_map.keys()}")
        except_list = ['id', 'date_created', 'date_updated']
        put_list = {
            k: request.json[k]
            for k in request.json
            if k in model._meta.fields_map.keys() and k not in except_list
        }
        logger.info(f"「Debug Messages」 -- > {put_list}")
        # refapi = await model.create(put_list)
        refapi = await get_or_create_record(model, put_list)
        logger.info(f"「Debug Messages」 -- >{type(refapi)}: {refapi}")
        return json(refapi.json)
    elif request.method == 'DELETE':
        refapi = await model.get(id=s_id)
        await refapi.delete()
        return json(refapi.json)


@refapi_bp.route("/<model_name>/search", methods=['GET'])
@requires_authentication
async def refapi_model_key(request, model_name: str):
    """
    函数“refapi_model_key”是一个异步 Python 函数，它将请求和模型名称作为输入，并根据提供的搜索名称和值执行搜索。

    :param request: “request”参数是一个对象，表示向服务器发出的 HTTP 请求。它包含请求方法（GET、POST 等）、标头、查询参数和请求正文等信息。
    :param model_name: “model_name”参数是一个表示模型名称的字符串。它用于从全局命名空间中检索相应的模型类。
    :type model_name: str
    :return: JSON 响应。

    The function "refapi_model_key" is an asynchronous Python function that takes a request and a model name as input and performs a search based on the provided search name and value.

    :param request: The "request" parameter is an object representing an HTTP request to the server. It contains information such as request method (GET, POST, etc.), headers, query parameters, and request body.
    :param model_name: The "model_name" parameter is a string representing the name of the model. It is used to retrieve the corresponding model class from the global namespace.
    :type model_name: str
    :return: JSON response.
    """
    search_name = request.args.get('name')
    if search_name is not None:
        search_name = unquote(search_name)
    search_value = request.args.get('value')
    if search_value is not None:
        search_value = unquote(search_value)
    model_name = model_name.lower()
    model = globals()[model_name.capitalize()]
    logger.info(f"「Debug Messages」 -- > {search_name}:{search_value}")

    if request.method == 'GET':
        query = Q(**{search_name: search_value})
        logger.info(f"「Debug Messages」 -- > {type(query)}:{query}")
        if query is None:
            DEFAULT_RETURN_JSON['msg'] = "ok"
        else:
            DEFAULT_RETURN_JSON['status'] = 1
            DEFAULT_RETURN_JSON['msg'] = "[Error]:用户记录已经存在"
        logger.info(
            f"「Debug Messages」 -- >DEFAULT_RETURN_JSON:{DEFAULT_RETURN_JSON}")
        return json(DEFAULT_RETURN_JSON)
