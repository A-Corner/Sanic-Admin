#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
上传安全测试：路径穿越被拒、存储文件名由服务端生成、目录逃逸被拦。

覆盖 CPL 验收口径第 7 项。

关键事实
========
* 存储文件名**完全由服务端生成**（uuid + 由 libmagic 探测出的 MIME 推导扩展名），
  客户端文件名只作为展示用元数据（取 basename、去控制字符）。
* 上传目录**不对外静态托管**，下载走需要鉴权的 ``GET /api/v1/files/<id>/download``。
* 分类只接受固定白名单；最终路径写入前用 realpath 校验必须位于 UPLOAD_DIR 之内。

因此"文件名里带 ``../``"不应该造成任何逃逸：文件要么被接受但落在上传目录内
（存成 uuid 名），要么被拒绝——**任何情况下都不允许在上传目录之外生成文件**。
"""

import pytest

TRAVERSAL_NAMES = [
    "../../evil.txt",
    "../../../evil.txt",
    "..%2f..%2fevil.txt",
    "/etc/evil.txt",
    "subdir/../../evil.txt",
]


async def _upload(client, headers, filename: str, content: bytes = b"hello world"):
    return await client.post(
        "/api/v1/upload",
        headers=headers,
        files={"file": (filename, content, "text/plain")},
    )


@pytest.mark.parametrize("evil_name", TRAVERSAL_NAMES)
async def test_upload_traversal_never_writes_outside_upload_dir(
    client, auth_headers, tmp_path, evil_name
):
    """
    路径穿越文件名 → 上传目录之外**不得**产生任何文件。

    允许的两种结果：
    * 400/403（被拒绝）；
    * 201，但文件被存成服务端生成的 uuid 名，落在上传目录内。

    无论哪种，上传目录之外都不允许出现新文件。
    """
    upload_root = tmp_path / "uploads"

    # 上传目录之外的"目标位置"：测试临时目录的上两级
    outside_targets = [
        tmp_path.parent / "evil.txt",
        tmp_path.parent.parent / "evil.txt",
        Path_cwd_evil(),
    ]
    for target in outside_targets:
        if target.exists():
            target.unlink()

    response = await _upload(client, auth_headers, evil_name)

    assert response.status_code in (200, 201, 400, 403), (
        f"穿越文件名返回了意料之外的状态码 {response.status_code}：{response.text}"
    )

    # 上传目录之外不得出现文件
    for target in outside_targets:
        assert not target.exists(), (
            f"路径穿越导致上传目录之外出现了文件：{target}"
        )

    # 上传目录内部只允许出现服务端生成的 uuid 名文件
    for path in upload_root.rglob("*"):
        if path.is_file():
            assert path.parent.name in ("general", "avatar", "document", "image", "archive"), (
                f"上传产生了预期外层级的文件：{path}"
            )
            # 文件名是 uuid（32 位十六进制）+ 扩展名，不含路径分隔符
            stem = path.stem
            assert len(stem) == 32 and all(c in "0123456789abcdef" for c in stem), (
                f"存储文件名不是服务端生成的 uuid：{path.name}"
            )


def Path_cwd_evil():
    """返回"当前工作目录下的 evil.txt"作为第三个逃逸目标。"""
    from pathlib import Path

    return Path.cwd() / "evil.txt"


async def test_upload_traversal_rejected_or_sanitized(client, auth_headers):
    """
    具体断言：穿越文件名要么被拒（400），要么被清洗成 basename。

    被接受时，响应里的 ``filename`` 必须只剩 basename（不含 ``/`` 与 ``..``）。
    """
    response = await _upload(client, auth_headers, "../../evil.txt")

    if response.status_code in (400, 403):
        body = response.json()
        assert body["success"] is False
        return

    assert response.status_code in (200, 201), response.text
    body = response.json()
    assert body["success"] is True
    for record in body["data"]["files"]:
        assert "/" not in record["filename"], (
            f"回显的文件名仍含路径分隔符：{record['filename']}"
        )
        assert ".." not in record["filename"], (
            f"回显的文件名仍含 ..：{record['filename']}"
        )
        assert record["filename"] == "evil.txt"


async def test_upload_rejects_disallowed_category(client, auth_headers):
    """不支持的分类 → 400。"""
    response = await client.post(
        "/api/v1/upload/evil-category",
        headers=auth_headers,
        files={"file": ("a.txt", b"hello", "text/plain")},
    )
    assert response.status_code == 400, response.text


async def test_upload_rejects_executable_content(client, auth_headers):
    """不在 MIME 白名单里的内容 → 400（按真实内容判定，不看扩展名）。"""
    response = await client.post(
        "/api/v1/upload",
        headers=auth_headers,
        files={"file": ("evil.sh", b"#!/bin/sh\nrm -rf /\n", "text/plain")},
    )
    # libmagic 会把 shell 脚本识别成 text/x-shellscript，不在白名单里
    assert response.status_code == 400, response.text
    assert response.json()["success"] is False


async def test_upload_requires_authentication(client):
    """未认证上传 → 401。"""
    response = await client.post(
        "/api/v1/upload", files={"file": ("a.txt", b"hello", "text/plain")}
    )
    assert response.status_code == 401, response.text


async def test_upload_dir_is_not_publicly_served(client):
    """
    上传目录不对外静态托管 → ``/uploads/<file>`` 返回 404。

    静态挂载在 M1 已移除；下载必须走带鉴权的 ``/api/v1/files/<id>/download``。
    """
    response = await client.get("/uploads/whatever.txt")
    assert response.status_code == 404, response.text


async def test_download_requires_authentication(client):
    """
    下载接口未认证 → 401。

    注意：这里**不能**依赖 ``auth_headers`` 夹具——它会先登录，
    session Cookie 落进 ``client`` 的 cookie jar，之后的请求就变成"已认证"了。
    """
    response = await client.get("/api/v1/files/1/download")
    assert response.status_code == 401, response.text


async def test_file_list_requires_authentication(client):
    """文件列表未认证 → 401。"""
    response = await client.get("/api/v1/files")
    assert response.status_code == 401, response.text
