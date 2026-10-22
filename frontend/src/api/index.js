import request from '@/utils/request'

// 认证相关API
export const authAPI = {
  // 登录
  login(data) {
    return request({
      url: '/auth/login',
      method: 'post',
      data
    })
  },
  
  // 登出
  logout() {
    return request({
      url: '/auth/logout',
      method: 'post'
    })
  },
  
  // 获取当前用户信息
  getUserInfo() {
    return request({
      url: '/auth/me',
      method: 'get'
    })
  }
}

// 用户管理API
export const userAPI = {
  // 获取用户列表
  getList(params) {
    return request({
      url: '/users',
      method: 'get',
      params
    })
  },
  
  // 获取用户详情
  getDetail(id) {
    return request({
      url: `/users/${id}`,
      method: 'get'
    })
  },
  
  // 创建用户
  create(data) {
    return request({
      url: '/users',
      method: 'post',
      data
    })
  },
  
  // 更新用户
  update(id, data) {
    return request({
      url: `/users/${id}`,
      method: 'put',
      data
    })
  },
  
  // 删除用户
  delete(id) {
    return request({
      url: `/users/${id}`,
      method: 'delete'
    })
  }
}

// 角色管理API
export const roleAPI = {
  // 获取角色列表
  getList(params) {
    return request({
      url: '/roles',
      method: 'get',
      params
    })
  },
  
  // 获取角色详情
  getDetail(id) {
    return request({
      url: `/roles/${id}`,
      method: 'get'
    })
  },
  
  // 创建角色
  create(data) {
    return request({
      url: '/roles',
      method: 'post',
      data
    })
  },
  
  // 更新角色
  update(id, data) {
    return request({
      url: `/roles/${id}`,
      method: 'put',
      data
    })
  },
  
  // 删除角色
  delete(id) {
    return request({
      url: `/roles/${id}`,
      method: 'delete'
    })
  }
}

// 系统设置API
export const systemAPI = {
  // 获取系统设置
  getSettings() {
    return request({
      url: '/system/settings',
      method: 'get'
    })
  },
  
  // 更新系统设置
  updateSettings(data) {
    return request({
      url: '/system/settings',
      method: 'put',
      data
    })
  },
  
  // 获取系统日志
  getLogs(params) {
    return request({
      url: '/system/logs',
      method: 'get',
      params
    })
  }
}

// 仪表盘API
export const dashboardAPI = {
  // 获取仪表盘数据
  getData() {
    return request({
      url: '/dashboard',
      method: 'get'
    })
  }
}
