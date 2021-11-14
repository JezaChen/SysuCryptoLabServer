import multiprocessing

bind = "127.0.0.1:5000"
workers = multiprocessing.cpu_count() * 2 + 1
workers = 10
accesslog = 'access.log'  # 访问日志目录
errorlog  = 'error.log'  # 错误日志目录
capture_output = True  # 重定向标准输出到错误日志。默认为False。
timeout = 600  # 过期时间
loglevel = "debug"  # 日志级别，这个日志级别指的是错误日志的级别，而访问日志的级别无法设置
# debug、info、warning、error、critical
reload = False  # 重载 更改代码的时候重启workers， 只建议在开发过程中开启。
daemon = True  # 以守护进程形式来运行Gunicorn进程。其实就是将这个服务放到后台去运行。默认为False。