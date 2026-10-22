import { createRouter, createWebHistory } from 'vue-router'
import Layout from '@/components/layout/index.vue'
import { getToken } from '@/utils/auth'

// 路由配置
const routes = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/login/index.vue'),
    meta: { title: '登录', hidden: true }
  },
  {
    path: '/',
    component: Layout,
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/dashboard/index.vue'),
        meta: { title: '仪表盘', icon: 'dashboard' }
      }
    ]
  },
  {
    path: '/user',
    component: Layout,
    redirect: '/user/list',
    meta: { title: '用户管理', icon: 'user' },
    children: [
      {
        path: 'list',
        name: 'UserList',
        component: () => import('@/views/user/index.vue'),
        meta: { title: '用户列表', icon: 'list' }
      },
      {
        path: 'profile',
        name: 'UserProfile',
        component: () => import('@/views/user/profile.vue'),
        meta: { title: '个人资料', icon: 'profile' }
      }
    ]
  },
  {
    path: '/role',
    component: Layout,
    redirect: '/role/list',
    meta: { title: '角色权限', icon: 'lock' },
    children: [
      {
        path: 'list',
        name: 'RoleList',
        component: () => import('@/views/role/index.vue'),
        meta: { title: '角色列表', icon: 'list' }
      },
      {
        path: 'permission',
        name: 'Permission',
        component: () => import('@/views/role/permission.vue'),
        meta: { title: '权限管理', icon: 'permission' }
      }
    ]
  },
  {
    path: '/system',
    component: Layout,
    redirect: '/system/settings',
    meta: { title: '系统管理', icon: 'setting' },
    children: [
      {
        path: 'settings',
        name: 'Settings',
        component: () => import('@/views/system/settings.vue'),
        meta: { title: '系统设置', icon: 'setting' }
      },
      {
        path: 'logs',
        name: 'Logs',
        component: () => import('@/views/system/logs.vue'),
        meta: { title: '系统日志', icon: 'log' }
      }
    ]
  },
  // 404页面必须放在最后
  {
    path: '/:pathMatch(.*)*',
    component: () => import('@/views/error/404.vue'),
    meta: { hidden: true }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 导航守卫
router.beforeEach((to, from, next) => {
  // 设置页面标题
  document.title = to.meta.title ? `${to.meta.title} - ${process.env.VUE_APP_TITLE}` : process.env.VUE_APP_TITLE
  
  // 检查是否需要登录
  const token = getToken()
  if (to.path === '/login') {
    // 已登录则跳转到首页
    if (token) {
      next({ path: '/' })
    } else {
      next()
    }
  } else {
    // 需要登录的页面
    if (token) {
      next()
    } else {
      next(`/login?redirect=${to.path}`)
    }
  }
})

export default router
