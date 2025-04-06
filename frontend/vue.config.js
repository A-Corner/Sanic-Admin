const { defineConfig } = require('@vue/cli-service')

module.exports = defineConfig({
  transpileDependencies: true,
  devServer: {
    port: 8080,
    open: true,
    proxy: {
      // 开发环境代理配置
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true, // 支持跨域
        pathRewrite: {
          '^/api': '/api'
        }
      }
    }
  },
  css: {
    loaderOptions: {
      sass: {
        additionalData: `
          @import "@/styles/variables.scss";
        `
      }
    }
  },
  configureWebpack: {
    // 提供代码分割和优化
    optimization: {
      splitChunks: {
        chunks: 'all'
      }
    },
    // 源码映射配置
    devtool: process.env.NODE_ENV === 'development' ? 'source-map' : false
  }
})
