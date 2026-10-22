import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import './styles/index.scss'

// 创建应用实例
const app = createApp(App)

// 挂载全局属性
app.config.globalProperties.$TITLE = process.env.VUE_APP_TITLE || 'Sanic-Admin系统'

// 注册插件
app.use(createPinia()) // 状态管理
app.use(router) // 路由
app.use(ElementPlus, {
  locale: zhCn,
  size: 'default'
}) // UI组件库

// 挂载应用
app.mount('#app')
