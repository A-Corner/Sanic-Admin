import { defineStore } from 'pinia'
import { authAPI } from '@/api'
import { setToken, removeToken } from '@/utils/auth'

// 用户状态
export const useUserStore = defineStore('user', {
  state: () => ({
    token: '',
    userInfo: null,
    roles: [],
    permissions: []
  }),
  
  getters: {
    // 判断是否有某个权限
    hasPermission: (state) => (permission) => {
      return state.permissions.includes(permission)
    },
    
    // 判断是否有某个角色
    hasRole: (state) => (role) => {
      return state.roles.includes(role)
    },
    
    // 是否是管理员
    isAdmin: (state) => {
      return state.roles.includes('admin')
    }
  },
  
  actions: {
    // 登录
    async login(loginData) {
      try {
        const response = await authAPI.login(loginData)
        const { token } = response.data
        this.token = token
        setToken(token)
        return Promise.resolve(response)
      } catch (error) {
        return Promise.reject(error)
      }
    },
    
    // 获取用户信息
    async getUserInfo() {
      try {
        const response = await authAPI.getUserInfo()
        const { user, roles, permissions } = response.data
        this.userInfo = user
        this.roles = roles
        this.permissions = permissions
        return Promise.resolve(response)
      } catch (error) {
        return Promise.reject(error)
      }
    },
    
    // 登出
    async logout() {
      try {
        await authAPI.logout()
        this.reset()
        return Promise.resolve()
      } catch (error) {
        return Promise.reject(error)
      } finally {
        this.reset()
      }
    },
    
    // 重置状态
    reset() {
      this.token = ''
      this.userInfo = null
      this.roles = []
      this.permissions = []
      removeToken()
    }
  }
})

// 应用设置状态
export const useAppStore = defineStore('app', {
  state: () => ({
    sidebar: {
      opened: true,
      withoutAnimation: false
    },
    device: 'desktop',
    theme: 'light',
    size: 'default'
  }),
  
  actions: {
    // 切换侧边栏
    toggleSidebar() {
      this.sidebar.opened = !this.sidebar.opened
      this.sidebar.withoutAnimation = false
    },
    
    // 关闭侧边栏
    closeSidebar() {
      this.sidebar.opened = false
      this.sidebar.withoutAnimation = false
    },
    
    // 设置设备类型
    setDevice(device) {
      this.device = device
    },
    
    // 设置主题
    setTheme(theme) {
      this.theme = theme
    },
    
    // 设置尺寸
    setSize(size) {
      this.size = size
    }
  }
})

// 标签页状态
export const useTagsStore = defineStore('tags', {
  state: () => ({
    visitedViews: [],
    cachedViews: []
  }),
  
  actions: {
    // 添加访问视图
    addVisitedView(view) {
      if (this.visitedViews.some(v => v.path === view.path)) return
      this.visitedViews.push(
        Object.assign({}, view, {
          title: view.meta.title || 'no-name'
        })
      )
    },
    
    // 添加缓存视图
    addCachedView(view) {
      if (this.cachedViews.includes(view.name)) return
      if (!view.meta.noCache) {
        this.cachedViews.push(view.name)
      }
    },
    
    // 删除访问视图
    removeVisitedView(view) {
      const index = this.visitedViews.findIndex(v => v.path === view.path)
      if (index !== -1) {
        this.visitedViews.splice(index, 1)
      }
    },
    
    // 删除缓存视图
    removeCachedView(view) {
      const index = this.cachedViews.indexOf(view.name)
      if (index !== -1) {
        this.cachedViews.splice(index, 1)
      }
    },
    
    // 删除所有视图
    removeAllViews() {
      this.visitedViews = []
      this.cachedViews = []
    }
  }
})
