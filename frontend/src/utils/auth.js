import Cookies from 'js-cookie'

const TokenKey = 'sanic_admin_token'
const RefreshTokenKey = 'sanic_admin_refresh_token'

// 获取token
export function getToken() {
  return Cookies.get(TokenKey)
}

// 设置token
export function setToken(token) {
  return Cookies.set(TokenKey, token)
}

// 移除token
export function removeToken() {
  Cookies.remove(TokenKey)
  Cookies.remove(RefreshTokenKey)
}

// 获取刷新token
export function getRefreshToken() {
  return Cookies.get(RefreshTokenKey)
}

// 设置刷新token
export function setRefreshToken(token) {
  return Cookies.set(RefreshTokenKey, token)
}

// 检查是否已登录
export function isAuthenticated() {
  return !!getToken()
}
