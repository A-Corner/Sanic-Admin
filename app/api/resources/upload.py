#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
文件上传 / 下载 API 资源模块

安全要点：
* 存储文件名完全由服务端生成（uuid + 由检测到的 MIME 推导出的扩展名），不使用客户端文件名；
  客户端文件名只作为展示用元数据（取 basename 并清理控制字符）。
* 客户端文件名含路径穿越片段（``../``、``%2e%2e``、绝对路径、null 字节）时**直接拒绝**，
  不给"上传成功却夹带路径"的错觉。
* 分类（category）只接受固定白名单；最终路径在写入/读取/删除前都用 realpath 校验必须位于
  UPLOAD_DIR 之内（同时拒绝 URL 编码的路径分隔符与符号链接逃逸）。
* 文件内容用 libmagic 检测真实类型，只允许白名单类型；大小有上限。
* 上传目录不对外静态托管：下载走需要鉴权的 ``GET /api/v1/files/<id>/download``，并强制
  ``Content-Disposition: attachment`` 与 ``X-Content-Type-Options: nosniff``。
* 响应只给相对路径与下载 URL，不泄露服务器绝对路径。

权限：上传/列表/下载使用资源 ``file`` 的 upload/read 操作，删除使用 delete（他人文件需 manage）；
头像是自助操作，登录即可（只接受图片）。
"""

import os
import re
import uuid
from typing import Any, Dict, Optional

import magic
from sanic import response
from sanic.log import logger
from sanic.request import Request
from sanic.views import HTTPMethodView
from tortoise.expressions import F

from app.api import APIResponse, v1_bp
from app.api.responses import APIError
from app.auth.authentication import authenticate_request
from app.auth.authorization import check_permissions, has_permission, requires_permission
from app.models import Profile, UploadedFile

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_AVATAR_SIZE = 2 * 1024 * 1024  # 2MB
ALLOWED_CATEGORIES = ("general", "avatar", "document", "image", "archive")

# MIME 白名单 -> 存储扩展名（扩展名只由这里决定，绝不取自客户端文件名）
ALLOWED_TYPES: Dict[str, str] = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "application/pdf": ".pdf",
    "text/plain": ".txt",
    "text/csv": ".csv",
    "application/msword": ".doc",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/zip": ".zip",
}
IMAGE_TYPES = {"image/jpeg", "image/png", "image/gif"}
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
# URL 编码的路径分隔符（%2f/%5c 及其大小写形式）：解码后即成为分隔符
_URL_SEP_RE = re.compile(r"%2f|%5c", re.IGNORECASE)
# 客户端文件名里出现这些片段即为可疑的路径穿越尝试
_TRAVERSAL_RE = re.compile(r"(^|[\\/])\.\.([\\/]|$)|%2e%2e", re.IGNORECASE)


def is_suspicious_filename(name: Optional[str]) -> bool:
    """
    客户端提供的文件名是否含路径穿越尝试。

    拒绝以下形态（不区分操作系统）：

    * 含 ``..`` 路径片段（``../``、``..\\``、``a/../b``）；
    * 含 URL 编码的 ``..``（``%2e%2e``）或 URL 编码的路径分隔符（``%2f``/``%5c``）；
    * 是绝对路径（以 ``/`` 或 ``\\`` 开头，或形如 ``C:\\...``）；
    * 含 null 字节。

    存储文件名完全由服务端生成（uuid + MIME 推导扩展名），客户端文件名只作展示，
    但**含穿越片段的文件名一律拒绝**——不给人"上传成功"却夹带路径的错觉，
    也避免下游任何把展示名当路径使用的代码被误导。
    """
    if not name:
        return False
    if "\x00" in name:
        return True
    if _TRAVERSAL_RE.search(name) or _URL_SEP_RE.search(name):
        return True
    # 绝对路径：/etc/passwd 或 C:\windows\...
    if name.startswith(("/", "\\")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", name):
        return True
    return False


class UploadError(Exception):
    """上传校验失败（用户可见的错误信息）。"""


def get_upload_root() -> str:
    """当前应用配置的上传目录（realpath）。"""
    from sanic import Sanic
    root = Sanic.get_app().config.UPLOAD_DIR
    os.makedirs(root, exist_ok=True)
    return os.path.realpath(root)


def safe_upload_path(relative_path: str) -> str:
    """
    把相对上传目录的路径解析为绝对路径；解析后不在上传目录内（路径穿越、符号链接逃逸）则抛 ValueError。

    拒绝的输入（均抛 ValueError）：
    * 空路径；
    * 含 null 字节（``\\x00``）的路径；
    * 绝对路径（``/etc/passwd``）；
    * 含 URL 编码分隔符（``%2f`` / ``%5c`` 及其大小写形式）的路径——
      上层若把这类值直接当文件名解码，会还原成 ``../`` 从而绕过 realpath 校验；
    * 解析后落在 UPLOAD_DIR 之外的路径（``../`` 穿越、符号链接逃逸）。
    """
    root = get_upload_root()
    if not relative_path or "\x00" in relative_path or os.path.isabs(relative_path):
        raise ValueError("非法的文件路径")
    # URL 编码的路径分隔符：解码后即为分隔符，必须在 realpath 之前拒绝
    if _URL_SEP_RE.search(relative_path):
        raise ValueError("非法的文件路径")
    full = os.path.realpath(os.path.join(root, relative_path))
    if full != root and not full.startswith(root + os.sep):
        raise ValueError("文件路径超出上传目录")
    return full


def sanitize_filename(name: Optional[str]) -> str:
    """客户端文件名只用于展示：取 basename、去控制字符、限制长度。"""
    name = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = _CONTROL_CHARS_RE.sub("", name).strip().strip(".")
    return (name or "file")[:200]


def download_filename(name: Optional[str]) -> str:
    """
    生成用于 ``Content-Disposition`` 的文件名。

    ``sanitize_filename`` 已去掉路径与控制字符，但引号会破坏
    ``Content-Disposition: attachment; filename="..."`` 的引号串结构，
    因此这里再剔除引号与分号。
    """
    return sanitize_filename(name).replace('"', "").replace(";", "").strip() or "file"


def _iter_uploaded_files(files) -> list:
    """
    把 ``request.files`` 里某个字段的值统一成 list。

    ``request.files`` 的值是 Sanic 的 ``RequestParameters``，其 ``get()`` 返回**第一个**
    元素而不是列表（``getlist()`` 才返回列表）。直接对 ``get()`` 的结果取 ``[0]``
    会拿到 ``File`` 元组的第一个字段（即 MIME 类型字符串）而不是文件对象。
    """
    if not files:
        return []
    if isinstance(files, (list, tuple)):
        # Sanic 的 File 是 NamedTuple（tuple 子类），必须先判 list/tuple 再判 File
        if hasattr(files, "body") and hasattr(files, "name"):
            return [files]
        return list(files)
    getlist = getattr(files, "getlist", None)
    if callable(getlist):
        return list(getlist())
    return [files]


def _parse_positive_int(value, default: int, maximum: Optional[int] = None) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    number = max(1, number)
    return min(number, maximum) if maximum else number


async def store_upload(file, account, category: str, *, allowed: Optional[set] = None,
                       max_size: int = MAX_FILE_SIZE) -> UploadedFile:
    """校验并保存一个上传文件，返回数据库记录。校验失败抛 UploadError。"""
    if category not in ALLOWED_CATEGORIES:
        raise UploadError(f"不支持的文件分类，可选: {', '.join(ALLOWED_CATEGORIES)}")
    # 客户端文件名含路径穿越片段一律拒绝（存储名由服务端生成，不含客户端输入）
    if is_suspicious_filename(getattr(file, "name", None)):
        raise UploadError("文件名不合法")
    body = file.body or b""
    if not body:
        raise UploadError("文件为空")
    if len(body) > max_size:
        raise UploadError(f"文件大小超过限制（最大 {max_size // (1024 * 1024)}MB）")

    mime_type = magic.from_buffer(body, mime=True)
    if mime_type not in ALLOWED_TYPES or (allowed is not None and mime_type not in allowed):
        raise UploadError(f"不支持的文件类型: {mime_type}")

    stored_filename = f"{uuid.uuid4().hex}{ALLOWED_TYPES[mime_type]}"
    relative_path = f"{category}/{stored_filename}"
    full_path = safe_upload_path(relative_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "xb") as fh:
        fh.write(body)

    try:
        return await UploadedFile.create(
            filename=sanitize_filename(file.name),
            stored_filename=stored_filename,
            file_path=relative_path,
            file_type=mime_type,
            file_size=len(body) / 1024,
            category=category,
            account_id=account.id,
        )
    except Exception:
        os.remove(full_path)
        raise


def file_info(record: UploadedFile) -> Dict[str, Any]:
    return {
        "id": record.id,
        "filename": record.filename,
        "url": f"/api/v1/files/{record.id}/download",
        "file_type": record.file_type,
        "file_size": record.file_size,
        "category": record.category,
        "account_id": record.account_id,
        "download_count": record.download_count,
        "upload_time": record.created_at,
    }


def remove_stored_file(record: UploadedFile) -> None:
    """删除物理文件；路径不合法或文件缺失只记录日志，不抛出。"""
    try:
        full = safe_upload_path(record.file_path)
        if os.path.isfile(full):
            os.remove(full)
    except (ValueError, OSError) as exc:
        logger.warning("删除上传文件失败 (id=%s): %r", record.id, exc)


class FileUploadResource(HTTPMethodView):
    """通用文件上传：``POST /api/v1/upload[/<category>]``"""

    @requires_permission("file:upload")
    async def post(self, request: Request, category: str = "general"):
        account = request.ctx.authentication_session.bearer
        if category not in ALLOWED_CATEGORIES:
            return APIResponse.error(message=f"不支持的文件分类，可选: {', '.join(ALLOWED_CATEGORIES)}",
                                     error_code=APIError.INVALID_PARAMETER, status_code=400)
        if not request.files:
            return APIResponse.error(message="请求中未包含文件", error_code="NO_FILE_UPLOADED",
                                     status_code=400)

        uploaded, errors = [], []
        for _field, files in request.files.items():
            for file in _iter_uploaded_files(files):
                try:
                    uploaded.append(file_info(await store_upload(file, account, category)))
                except UploadError as exc:
                    errors.append({"filename": sanitize_filename(file.name), "error": str(exc)})

        if not uploaded:
            return APIResponse.error(message="文件上传失败", error_code="UPLOAD_FAILED",
                                     status_code=400, details={"errors": errors})
        if errors:
            return APIResponse.success(
                data={"files": uploaded, "errors": errors},
                message=f"成功上传{len(uploaded)}个文件，{len(errors)}个上传失败")
        return APIResponse.created(data={"files": uploaded}, message=f"成功上传{len(uploaded)}个文件")


class AvatarUploadResource:
    """
    头像上传（自助操作）：``POST /api/v1/upload/avatar``

    语义：**只要求登录**（``authenticate_request``），不要求 ``file:upload`` 权限——
    头像属于账户自身的资料，普通用户也必须能改自己的头像。
    头像只能写到当前登录账户自己的 Profile 上，不接受客户端指定账户。
    """

    async def post(self, request: Request):
        session = await authenticate_request(request)
        account = session.bearer
        files = request.files.get("avatar") if request.files else None
        candidates = _iter_uploaded_files(files)
        if not candidates:
            return APIResponse.error(message="请求中未包含头像文件", error_code="NO_AVATAR_UPLOADED",
                                     status_code=400)
        try:
            record = await store_upload(candidates[0], account, "avatar",
                                        allowed=IMAGE_TYPES, max_size=MAX_AVATAR_SIZE)
        except UploadError as exc:
            return APIResponse.error(message=f"头像上传失败: {exc}", error_code="AVATAR_UPLOAD_FAILED",
                                     status_code=400)

        profile = await Profile.filter(account_id=account.id).first()
        if profile is None:
            profile = await Profile.create(account_id=account.id)
        old_avatar_id = _avatar_file_id(profile.avatar)
        profile.avatar = file_info(record)["url"]
        await profile.save()
        if old_avatar_id:
            old = await UploadedFile.get_or_none(id=old_avatar_id, account_id=account.id, category="avatar")
            if old:
                remove_stored_file(old)
                await old.delete()
        return APIResponse.success(data={"avatar_url": profile.avatar, "file_info": file_info(record)},
                                   message="头像上传成功")


def _avatar_file_id(avatar_url: Optional[str]) -> Optional[int]:
    match = re.fullmatch(r"/api/v1/files/(\d+)/download", avatar_url or "")
    return int(match.group(1)) if match else None


class FileListResource:
    """文件列表：``GET /api/v1/files``"""

    @requires_permission("file:read")
    async def get(self, request: Request):
        account = request.ctx.authentication_session.bearer
        page = _parse_positive_int(request.args.get("page"), 1)
        page_size = _parse_positive_int(request.args.get("page_size"), 20, maximum=100)
        query = UploadedFile.filter(deleted=False)
        if request.args.get("category"):
            query = query.filter(category=request.args.get("category"))
        if request.args.get("file_type"):
            query = query.filter(file_type__startswith=request.args.get("file_type"))
        if (request.args.get("only_mine") or "").lower() == "true":
            query = query.filter(account_id=account.id)

        total = await query.count()
        files = await query.order_by("-created_at").offset((page - 1) * page_size).limit(page_size)
        return APIResponse.list(items=[file_info(f) for f in files], total=total, page=page,
                                page_size=page_size, message="获取文件列表成功")


class FileDownloadResource:
    """
    文件下载：``GET /api/v1/files/<id>/download``

    归属判定（任一成立即放行）：

    1. ``record.category == "avatar"``——头像是账户对外展示的形象，登录用户可见；
    2. ``record.account_id == account.id``——**上传者本人**；
    3. ``has_permission(account, "file", "read")``——持有 file 读权限者可下载全部文件。

    不满足以上任一条返回 403。下载路径**不**用文件 id 拼路径，而是取数据库记录里的
    相对 ``file_path``，再经 ``safe_upload_path`` 做 realpath 越界校验。
    """

    async def get(self, request: Request, file_id: int):
        session = await authenticate_request(request)
        account = session.bearer
        record = await UploadedFile.filter(id=file_id, deleted=False).first()
        if record is None:
            return APIResponse.error(message="文件不存在", error_code="FILE_NOT_FOUND", status_code=404)

        allowed = (
            record.category == "avatar"
            or record.account_id == account.id
            or await has_permission(account, "file", "read")
        )
        if not allowed:
            return APIResponse.error(message="无权下载此文件", error_code=APIError.FORBIDDEN,
                                     status_code=403)

        try:
            full_path = safe_upload_path(record.file_path)
        except ValueError:
            logger.error("上传记录路径越界 (id=%s)", record.id)
            return APIResponse.error(message="文件不存在", error_code="FILE_NOT_FOUND", status_code=404)
        if not os.path.isfile(full_path):
            return APIResponse.error(message="文件不存在", error_code="FILE_NOT_FOUND", status_code=404)

        # 原子自增，避免并发下载丢计数
        await UploadedFile.filter(id=record.id).update(download_count=F("download_count") + 1)
        return await response.file(
            full_path,
            filename=download_filename(record.filename),
            mime_type=record.file_type or "application/octet-stream",
            # no_store=True 让 Sanic 生成唯一的 cache-control: no-store；
            # 若手工再传 Cache-Control 会与框架生成的头重复。
            no_store=True,
            headers={"X-Content-Type-Options": "nosniff"},
        )


class FileDeleteResource:
    """
    文件删除：``DELETE /api/v1/files/<id>``

    归属判定：

    * 删除**自己的**文件：只需 ``file:delete`` 权限；
    * 删除**他人**的文件：额外需要 ``file:manage`` 权限，否则 403。

    磁盘文件与数据库记录保持一致：先删物理文件，再软删除记录
    （``remove_stored_file`` 在路径非法或文件缺失时只记日志，不阻断记录删除）。
    """

    @requires_permission("file:delete")
    async def delete(self, request: Request, file_id: int):
        account = request.ctx.authentication_session.bearer
        record = await UploadedFile.filter(id=file_id, deleted=False).first()
        if record is None:
            return APIResponse.error(message="文件不存在", error_code="FILE_NOT_FOUND", status_code=404)
        if record.account_id != account.id and not await check_permissions(
                "file", "manage", request=request, check_only=True):
            return APIResponse.error(message="无权删除此文件", error_code=APIError.FORBIDDEN,
                                     status_code=403)
        remove_stored_file(record)
        record.deleted = True
        await record.save(update_fields=["deleted"])
        return APIResponse.success(message="文件删除成功")


# 注册路由
file_upload_resource = FileUploadResource()
avatar_upload_resource = AvatarUploadResource()
file_list_resource = FileListResource()
file_download_resource = FileDownloadResource()
file_delete_resource = FileDeleteResource()

v1_bp.add_route(avatar_upload_resource.post, "/upload/avatar", methods=["POST"])
v1_bp.add_route(file_upload_resource.as_view(), "/upload", methods=["POST"])
v1_bp.add_route(file_upload_resource.as_view(), "/upload/<category:str>", methods=["POST"])
v1_bp.add_route(file_list_resource.get, "/files", methods=["GET"])
v1_bp.add_route(file_download_resource.get, "/files/<file_id:int>/download", methods=["GET"])
v1_bp.add_route(file_delete_resource.delete, "/files/<file_id:int>", methods=["DELETE"])
