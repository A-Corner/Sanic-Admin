# Sanic-Admin 前端界面

基于 Vue 3 和 Element Plus 构建的现代化管理系统前端界面。

## 特性

- 📦 基于 Vue 3 的组件化开发
- 🔩 使用 Composition API 和 Pinia 进行状态管理
- 📱 响应式设计，支持各种设备尺寸
- 🌈 使用 Element Plus 组件库，美观且功能丰富
- 📊 集成 ECharts 实现数据可视化
- 🔑 完整的认证与授权流程
- 🌐 路由守卫确保安全访问
- 🧩 模块化组织，易于维护和扩展

## 目录结构

```
src/
├── api/            # API 通信模块
├── assets/         # 静态资源
├── components/     # 通用组件
│   └── layout/     # 布局组件
├── router/         # 路由配置
├── store/          # 状态管理
├── styles/         # 全局样式
├── utils/          # 工具函数
└── views/          # 页面组件
    ├── dashboard/  # 仪表盘页面
    ├── login/      # 登录页面
    ├── user/       # 用户管理页面
    ├── role/       # 角色管理页面
    └── system/     # 系统管理页面
```

## 安装与使用

### 开发环境

```bash
# 安装依赖
npm install

# 启动开发服务器
npm run serve
```

### 生产构建

```bash
# 构建生产版本
npm run build
```

## 技术栈

- Vue 3
- Vue Router
- Pinia
- Element Plus
- Axios
- ECharts
- SASS

## 功能模块

- 登录与认证
- 用户管理
- 角色与权限管理
- 系统设置
- 操作日志
- 仪表盘与数据统计
- 个人资料管理

## 构建与部署

项目使用 Vue CLI 进行构建，可以轻松整合到后端项目中。构建后的文件位于 `dist` 目录，可以被任何 Web 服务器托管。 