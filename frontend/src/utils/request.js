import axios from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getToken, getRefreshToken, setToken, removeToken } from '@/utils/auth'
import router from '@/router'

// 创建axios实例
const service = axios.create({
  baseURL: process.env.VUE_APP_BASE_API,
  timeout: 10000 // 请求超时时间
})

// 请求拦截器
service.interceptors.request.use(
  config => {
    // 设置token
    const token = getToken()
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`
    }
    return config
  },
  error => {
    console.error('请求错误:', error)
    return Promise.reject(error)
  }
)

// 响应拦截器
service.interceptors.response.use(
  response => {
    const res = response.data
    
    // 如果返回的不是JSON数据，直接返回
    if (response.config.responseType === 'blob') {
      return response
    }
    
    // 如果请求成功
    if (res.success === true) {
      return res
    }
    
    // 处理业务错误
    ElMessage({
      message: res.message || '请求失败',
      type: 'error',
      duration: 5 * 1000
    })
    
    // 处理特定错误码
    if (res.code === 'INVALID_TOKEN') {
      // Token无效，尝试刷新Token
      tryRefreshToken()
    }
    
    return Promise.reject(new Error(res.message || '未知错误'))
  },
  error => {
    const { response } = error
    
    if (response) {
      // 请求已发出，但服务器响应的状态码不在 2xx 范围内
      if (response.status === 401) {
        // 未授权，Token过期或无效
        if (getRefreshToken()) {
          tryRefreshToken()
        } else {
          // 无刷新令牌，需要重新登录
          handleLogout()
        }
      } else if (response.status === 403) {
        // 权限不足
        ElMessage({
          message: '权限不足，请联系管理员',
          type: 'error',
          duration: 5 * 1000
        })
      } else {
        // 其他错误
        const errMsg = response.data?.message || `请求错误: ${response.status}`
        ElMessage({
          message: errMsg,
          type: 'error',
          duration: 5 * 1000
        })
      }
    } else {
      // 请求未发出或网络错误
      ElMessage({
        message: '网络错误，请检查您的互联网连接',
        type: 'error',
        duration: 5 * 1000
      })
    }
    
    return Promise.reject(error)
  }
)

// 尝试刷新Token
async function tryRefreshToken() {
  const refreshToken = getRefreshToken()
  if (!refreshToken) {
    handleLogout()
    return
  }
  
  try {
    // 调用刷新Token接口
    const res = await axios.post(
      `${process.env.VUE_APP_BASE_API}/auth/refresh`,
      { refresh_token: refreshToken }
    )
    
    if (res.data.success && res.data.data.token) {
      setToken(res.data.data.token)
      ElMessage({
        message: '已为您刷新授权',
        type: 'success'
      })
      // 刷新页面重新发起请求
      window.location.reload()
    } else {
      handleLogout()
    }
  } catch (error) {
    handleLogout()
  }
}

// 处理登出
function handleLogout() {
  ElMessageBox.confirm(
    '您的登录已过期，请重新登录',
    '提示',
    {
      confirmButtonText: '重新登录',
      type: 'warning',
      showCancelButton: false,
      showClose: false
    }
  ).then(() => {
    removeToken()
    router.push(`/login?redirect=${router.currentRoute.value.fullPath}`)
  })
}

export default service
