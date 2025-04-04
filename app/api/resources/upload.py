#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
文件上传API资源模块，提供头像和附件上传功能
"""

import os
import uuid
import time
import imghdr
import magic
from sanic.request import Request
from sanic.views import HTTPMethodView
from sanic.exceptions import InvalidUsage
from app.api import APIResponse, v1_bp
from app.auth.authentication import get_authenticated_account
from app.auth.authorization import check_permissions
from app.models import Account, Profile, UploadedFile
from app.config import settings
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple


class FileUploadResource(HTTPMethodView):
    """
    文件上传资源
    
    提供通用文件上传功能
    """
    
    # 允许的文件类型和最大文件大小
    MAX_FILE_SIZE = 1024 * 1024 * 10  # 10MB
    ALLOWED_TYPES = {
        "image": ["image/jpeg", "image/png", "image/gif"],
        "document": ["application/pdf", "application/msword", 
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "application/vnd.ms-excel", 
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    "text/plain", "text/csv"],
        "archive": ["application/zip", "application/x-rar-compressed"]
    }
    
    async def post(self, request: Request, category: str = "general"):
        """
        上传文件
        
        Args:
            request: Sanic请求对象
            category: 文件分类，默认为general
            
        Returns:
            Response: Sanic响应
        """
        @check_permissions("file", "upload")
        async def upload_file(request):
            # 获取当前用户
            account = await get_authenticated_account(request)
            
            # 检查请求中是否包含文件
            if not request.files:
                return APIResponse.error(
                    message="请求中未包含文件",
                    error_code="NO_FILE_UPLOADED",
                    status_code=400
                )
            
            uploaded_files = []
            errors = []
            
            for file_name, file_object in request.files.items():
                # 如果是多文件上传，file_object可能是列表
                if isinstance(file_object, list):
                    files = file_object
                else:
                    files = [file_object]
                
                for file in files:
                    result = await self._process_file(file, account, category)
                    if "error" in result:
                        errors.append({
                            "filename": file.name,
                            "error": result["error"]
                        })
                    else:
                        uploaded_files.append(result["file_data"])
            
            # 根据上传结果返回响应
            if not uploaded_files and errors:
                # 所有文件上传失败
                return APIResponse.error(
                    message="文件上传失败",
                    error_code="UPLOAD_FAILED",
                    data={"errors": errors},
                    status_code=400
                )
            elif errors:
                # 部分文件上传失败
                return APIResponse.success(
                    data={
                        "files": uploaded_files,
                        "errors": errors
                    },
                    message=f"成功上传{len(uploaded_files)}个文件，{len(errors)}个上传失败"
                )
            else:
                # 所有文件上传成功
                return APIResponse.created(
                    data={"files": uploaded_files},
                    message=f"成功上传{len(uploaded_files)}个文件"
                )
        
        return await upload_file(request)
    
    async def _process_file(self, file, account, category: str) -> Dict[str, Any]:
        """
        处理上传的文件
        
        Args:
            file: 上传的文件对象
            account: 当前用户账户
            category: 文件分类
            
        Returns:
            Dict[str, Any]: 处理结果
        """
        # 检查文件大小
        if len(file.body) > self.MAX_FILE_SIZE:
            return {
                "error": f"文件大小超过限制（最大{self.MAX_FILE_SIZE // (1024 * 1024)}MB）"
            }
        
        # 使用python-magic库检测文件类型
        mime_type = magic.from_buffer(file.body, mime=True)
        
        # 检查是否是允许的文件类型
        allowed_mime_types = []
        for types in self.ALLOWED_TYPES.values():
            allowed_mime_types.extend(types)
        
        if mime_type not in allowed_mime_types:
            return {
                "error": f"不支持的文件类型: {mime_type}"
            }
        
        # 确定文件分类
        file_category = None
        for cat, types in self.ALLOWED_TYPES.items():
            if mime_type in types:
                file_category = cat
                break
        
        # 生成文件信息
        original_filename = file.name
        file_ext = os.path.splitext(original_filename)[1].lower()
        if not file_ext and mime_type.startswith("image/"):
            # 如果是图片但没有扩展名，添加适当的扩展名
            img_type = imghdr.what(None, h=file.body)
            if img_type:
                file_ext = f".{img_type}"
        
        # 生成唯一文件名
        timestamp = int(time.time())
        unique_id = str(uuid.uuid4().hex)
        new_filename = f"{timestamp}_{unique_id}{file_ext}"
        
        # 确定保存路径
        upload_dir = os.path.join(settings.UPLOAD_DIR, file_category, category)
        os.makedirs(upload_dir, exist_ok=True)
        
        file_path = os.path.join(upload_dir, new_filename)
        relative_path = os.path.join(file_category, category, new_filename)
        
        # 保存文件
        with open(file_path, "wb") as f:
            f.write(file.body)
        
        # 计算文件大小（KB）
        file_size = len(file.body) / 1024
        
        # 创建数据库记录
        uploaded_file = await UploadedFile.create(
            filename=original_filename,
            stored_filename=new_filename,
            file_path=relative_path,
            file_type=mime_type,
            file_size=file_size,
            category=category,
            account_id=account.id
        )
        
        # 生成URL
        url = f"/uploads/{relative_path}"
        
        return {
            "file_data": {
                "id": uploaded_file.id,
                "filename": original_filename,
                "url": url,
                "file_type": mime_type,
                "file_size": file_size,
                "category": category,
                "upload_time": uploaded_file.created_at
            }
        }


class AvatarUploadResource:
    """
    头像上传资源
    
    提供用户头像上传功能
    """
    
    async def post(self, request: Request):
        """
        上传用户头像
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应
        """
        @check_permissions("profile", "update")
        async def upload_avatar(request):
            # 获取当前用户
            account = await get_authenticated_account(request)
            
            # 检查请求中是否包含文件
            if not request.files or "avatar" not in request.files:
                return APIResponse.error(
                    message="请求中未包含头像文件",
                    error_code="NO_AVATAR_UPLOADED",
                    status_code=400
                )
            
            avatar_file = request.files["avatar"][0]
            
            # 检查是否是图片
            mime_type = magic.from_buffer(avatar_file.body, mime=True)
            if not mime_type.startswith("image/"):
                return APIResponse.error(
                    message="上传的文件不是图片",
                    error_code="NOT_IMAGE_FILE",
                    status_code=400
                )
            
            # 使用通用文件上传功能
            upload_resource = FileUploadResource()
            result = await upload_resource._process_file(avatar_file, account, "avatar")
            
            if "error" in result:
                return APIResponse.error(
                    message=f"头像上传失败: {result['error']}",
                    error_code="AVATAR_UPLOAD_FAILED",
                    status_code=400
                )
            
            # 更新用户个人资料的头像字段
            profile = await Profile.filter(account_id=account.id).first()
            if not profile:
                profile = await Profile.create(account_id=account.id)
            
            profile.avatar = result["file_data"]["url"]
            await profile.save()
            
            return APIResponse.success(
                data={
                    "avatar_url": profile.avatar,
                    "file_info": result["file_data"]
                },
                message="头像上传成功"
            )
        
        return await upload_avatar(request)


class FileDownloadCounterMiddleware:
    """
    文件下载计数中间件
    
    用于记录文件下载次数
    """
    
    async def __call__(self, request):
        """
        处理文件下载请求
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: 处理后的响应
        """
        # 当前路径是否是下载路径
        if request.path.startswith("/uploads/"):
            try:
                # 提取文件路径
                file_path = request.path.replace("/uploads/", "", 1)
                
                # 查找对应的上传文件记录
                uploaded_file = await UploadedFile.filter(file_path=file_path).first()
                if uploaded_file:
                    # 更新下载次数
                    uploaded_file.download_count += 1
                    await uploaded_file.save()
            except Exception as e:
                # 记录错误但不影响下载
                print(f"Error counting download: {str(e)}")
        
        return False  # 继续处理请求


class FileListResource:
    """
    文件列表资源
    
    提供文件列表查询功能
    """
    
    async def get(self, request: Request):
        """
        获取文件列表
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应
        """
        @check_permissions("file", "read")
        async def get_file_list(request):
            # 获取当前用户
            account = await get_authenticated_account(request)
            
            # 解析查询参数
            page = int(request.args.get("page", "1"))
            page_size = int(request.args.get("page_size", "20"))
            category = request.args.get("category")
            file_type = request.args.get("file_type")
            only_mine = request.args.get("only_mine", "false").lower() == "true"
            
            # 构建查询
            query = UploadedFile.all()
            
            # 筛选条件
            if category:
                query = query.filter(category=category)
            if file_type:
                query = query.filter(file_type__startswith=file_type)
            if only_mine:
                query = query.filter(account_id=account.id)
            
            # 计算总数
            total = await query.count()
            
            # 分页
            offset = (page - 1) * page_size
            files = await query.order_by("-created_at").offset(offset).limit(page_size).all()
            
            # 格式化响应
            items = []
            for file in files:
                url = f"/uploads/{file.file_path}"
                items.append({
                    "id": file.id,
                    "filename": file.filename,
                    "url": url,
                    "file_type": file.file_type,
                    "file_size": file.file_size,
                    "category": file.category,
                    "account_id": file.account_id,
                    "download_count": file.download_count,
                    "upload_time": file.created_at
                })
            
            return APIResponse.list(
                items=items,
                total=total,
                page=page,
                page_size=page_size,
                message="获取文件列表成功"
            )
        
        return await get_file_list(request)


class FileDeleteResource:
    """
    文件删除资源
    
    提供文件删除功能
    """
    
    async def delete(self, request: Request, file_id: int):
        """
        删除文件
        
        Args:
            request: Sanic请求对象
            file_id: 文件ID
            
        Returns:
            Response: Sanic响应
        """
        @check_permissions("file", "delete")
        async def delete_file(request, file_id):
            # 获取当前用户
            account = await get_authenticated_account(request)
            
            # 查找文件
            file = await UploadedFile.filter(id=file_id).first()
            if not file:
                return APIResponse.error(
                    message="文件不存在",
                    error_code="FILE_NOT_FOUND",
                    status_code=404
                )
            
            # 检查权限
            is_admin = await check_permissions("file", "manage", request=request, check_only=True)
            if file.account_id != account.id and not is_admin:
                return APIResponse.error(
                    message="无权删除此文件",
                    error_code="PERMISSION_DENIED",
                    status_code=403
                )
            
            # 删除物理文件
            file_path = os.path.join(settings.UPLOAD_DIR, file.file_path)
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as e:
                # 记录错误但继续删除数据库记录
                print(f"Error deleting file {file_path}: {str(e)}")
            
            # 删除数据库记录
            await file.delete()
            
            return APIResponse.success(
                message="文件删除成功"
            )
        
        return await delete_file(request, file_id)


# 注册路由
file_upload_resource = FileUploadResource()
avatar_upload_resource = AvatarUploadResource()
file_list_resource = FileListResource()
file_delete_resource = FileDeleteResource()

v1_bp.add_route(file_upload_resource.as_view(), "/upload", methods=["POST"])
v1_bp.add_route(file_upload_resource.as_view(), "/upload/<category:string>", methods=["POST"])
v1_bp.add_route(avatar_upload_resource.post, "/upload/avatar", methods=["POST"])
v1_bp.add_route(file_list_resource.get, "/files", methods=["GET"])
v1_bp.add_route(file_delete_resource.delete, "/files/<file_id:int>", methods=["DELETE"]) 