import random
import aiohttp
import asyncio


async def fetch(session, url):
    async with session.get(url) as response:
        return await response.text()


async def main():
    urls = ['http://127.0.0.1:11121/refapi/account/search?value=account_verification&name=username',
            'http://127.0.0.1:11121/refapi/account/0']

    max_concurrent_requests = 100  # 最大并发请求数
    request_interval = 0  # 请求时间间隔（秒）
    total_requests = 0  # 记录总请求数
    err_num = 0

    async with aiohttp.ClientSession() as session:
        start_time = asyncio.get_event_loop().time()  # 记录开始时间

        while True:
            current_time = asyncio.get_event_loop().time()
            elapsed_time = current_time - start_time

            if elapsed_time >= 60:
                break  # 达到 60 秒，停止请求

            if total_requests >= max_concurrent_requests:
                # 达到最大并发数后，等待一段时间再继续发送请求
                await asyncio.sleep(request_interval)
            url = random.choice(urls)
            task = asyncio.ensure_future(fetch(session, url))
            total_requests += 1
            try:
                response = await task
                # print(f"Response {total_requests}: {response}")
            except Exception as e:
                err_num += 1
                # print(f"Request {total_requests}: Error - {e}")

    print("Total requests:", total_requests, "Error:", err_num)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
