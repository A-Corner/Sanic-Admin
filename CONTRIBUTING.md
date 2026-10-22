# 贡献指南

感谢你关注 Sanic-Admin。项目目前处于重构阶段（见 [README.md](README.md) 的"项目状态"），主线尚不可用于生产，欢迎通过 Issue 和 Pull Request 帮助改进。

## 开发环境

- Python：建议 3.10 – 3.11（部分依赖在 3.12 及以上无法编译，见相关 Issue）。
- 后端：Sanic + Tortoise ORM；前端主线为 AMIS（`amis/`），`frontend/`（Vue 3）为实验性。
- 搭建步骤：

```bash
git clone <你的 fork 地址>
cd Sanic-Admin
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main.py        # 开发服务器，默认端口 22222
```

注意：重构期间 `requirements.txt` 与启动流程可能存在已知问题，遇到安装或启动失败请先搜索已有 Issue，再决定是否新开。

- 默认管理员口令仅用于本地开发。production 环境真正必填的是 `JWT_PRIVATE_KEY` 与 `INITIAL_ADMIN_PASSWORD`，两者必须通过环境变量提供，缺失会导致进程直接退出。`SECRET_KEY` 与 `PASSWORD_SALT` 当前不参与任何签名或加密，可留空。无论是否必填，任何密钥都不要提交到仓库。

## 分支与 Pull Request 流程

1. 先开 Issue（Bug 或功能建议）说明想做的事，较大改动请先讨论再动手。
2. Fork 本仓库，从最新的默认分支创建功能分支，例如 `feat/xxx`、`fix/xxx`、`docs/xxx`。
3. 保持改动聚焦：一个 PR 只做一件事，避免夹带无关格式化或重构。
4. 提交信息建议使用 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/)，如 `fix(auth): 修复会话过期判断`。
5. 推送分支并发起 PR，按模板填写变更说明与测试情况，关联对应 Issue。
6. 维护者审阅后可能提出修改意见；请在原分支上追加提交，不要强推覆盖他人已评论的历史。
7. 涉及用户可见行为的改动，请同步更新 [CHANGELOG.md](CHANGELOG.md) 的 `Unreleased` 段。

## 测试

```bash
pip install pytest pytest-asyncio pytest-cov sanic-testing
pytest
pytest tests/test_auth.py          # 运行单个文件
```

新增或修复功能时请补充对应测试。当前主线测试可能因重构而无法完整收集，如实在 PR 中说明你实际运行了什么、结果如何，不要声称未验证的结果。

## 代码风格

- 遵循 PEP 8，缩进 4 个空格，尽量补充类型注解。
- 提交前建议运行 `flake8`（或 `ruff`）检查；前端改动在 `frontend/` 下运行 `npm run lint`。
- 保持简单直接，处理好错误、边界和输入校验；不要提交密钥、数据库文件（`*.sqlite3`）或系统文件（`.DS_Store`）。
- 注释和文档中文、英文均可。

## 安全问题

请不要在公开 Issue 中披露漏洞，按 [SECURITY.md](SECURITY.md) 私下报告。

## 行为准则

参与本项目即表示同意遵守 [行为准则](CODE_OF_CONDUCT.md)。
