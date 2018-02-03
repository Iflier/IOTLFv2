# -*- coding: utf-8 -*-
"""
Level : Fun
Dec:
Created on : 2017.07.28
Modified on : 2017.08.22
如果允许多用户登陆呢？
可以。连接在server端的一个设备实例可以允许多个用户操作，Tornado并不会创建多个该设备的连接
Modified on : 2017.08.28
当由于cookie过期，无法操作退出登录时，由server主动修改访问次数
Modified on : 2017.08.29
更正首次登陆设备状态与页面显示不符的问题：
1.在登陆过程中读取存储的上一次设备状态，通过串口发送给设备
2.定时器任务使用内置库
Modified on：2017.09.04
使用mget获取redis的键值，副作用是不得不检查返回的列表包含的元素
Modified on : 2017.10.15
在初始化redis实例时添加decode_response=True参数，这样返回的就是字符串了
Modified on: 2018.01.31
取消对登陆人数的限制
Modified on: 2018.02.02
美化样式
Author : Iflier
"""
print(__doc__)

import sys
import time
import json
import pickle
import os.path
from threading import Timer

import serial
import redis
import MySQLdb
import MySQLdb.cursors
import tornado.web
import tornado.httpserver
from tornado.web import url
from tornado.options import define, options, parse_command_line


PORT = "COM3"
BAUDRATE = 115200

try:
    arduino = serial.Serial(PORT, BAUDRATE, timeout=20)
    print("Connect to Arduino Succeed!  :)")
    print("Port is open? {0}".format(arduino.is_open))
except Exception as err:
    print(err)
    print("Connect to Port {0} failed  :(".format(PORT))
    sys.exit(1)

if os.path.exists(os.path.join(os.getcwd(), 'config.pkl')):
    with open("config.pkl", 'rb') as file:
        conf = pickle.load(file)
else:
    print("Can't find configure file!")
    sys.exit(1)

define("port", default=11000, help="Runing on the given port.", type=int)

conn = MySQLdb.connect(host="localhost", db="userCount", user=conf.get("user"),
                       password=conf.get("password"),
                       cursorclass=MySQLdb.cursors.DictCursor)
clientCache = redis.StrictRedis(host='localhost', port=6379, db=0,
                                decode_responses=True,
                                password=conf.get("cachePassword"))


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            url('/', EnterHandler, name='enterPoint'),
            url('/login', LoginHandler, dict(board=arduino, databaseLogin=conn, databaseCache=clientCache), name='login'),
            url('/welcome', WelcomeHandler, dict(database=clientCache, board=arduino), name='welcome'),
            url(r'/fan/', FanHandler, dict(database=clientCache, board=arduino), name='fan'),
            url(r'/led/', LedHandler, dict(database=clientCache, board=arduino), name='led'),
            url("/logout/", LogoutHandler, dict(cacheDB=clientCache), name='logout')
        ]
        settings = {
            "static_path": os.path.join(os.path.dirname(__file__), "static"),
            "template_path": os.path.join(os.path.dirname(__file__), 'template'),
            "xsrf_cookies": True,
            "debug": True,
            "cookie_secret": "b397a194-4ad6-40fa-a057-8e008432f943",
            "login_url": '/login',
            "static_url_prefix": "/static/"
        }
        tornado.web.Application.__init__(self, handlers=handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    """"Handler的基类"""
    def write_error(self, status_code, **kwargs):
        if status_code == 404:
            self.render('404.html')
        elif status_code == 500:
            self.render('500.html')
        elif status_code == 405:
            self.render("verboseNotAllowed.html")            
        else:
            self.write("Error: {0}".format(status_code))


class DeviceHandler(BaseHandler):
    def initialize(self, database, board):
        self.cacheDB = database
        self.board = board

    def get(self):
        self.redirect('/')


class EnterHandler(BaseHandler):
    def get_current_user(self):
        # print("Type of get_secure_cookie: {0}".format(self.get_secure_cookie("username")))
        # 字节字符串
        username = self.get_secure_cookie('username')
        if isinstance(username, bytes):
            return username.decode(encoding='utf-8')
        return None

    @tornado.web.authenticated
    def get(self):
        """只有已经认证的用户在重新打开窗口时才会被重定向到欢迎页面，否则为login_url键指定的url"""
        self.redirect("/welcome")


class LoginHandler(BaseHandler):
    def initialize(self, board, databaseLogin, databaseCache):
        self.board = board
        self.db = databaseLogin
        self.cache = databaseCache

    def prepare(self):
        self.cursor = self.db.cursor()
        # 首次打开页面会把Redis中缓存的设备的上一次状态同步过来
        bytes_count = self.board.write((self.cache.get("ledStatus") + ',' + self.cache.get("fanSpeed") + ';').encode(encoding='utf_8'))
        print("At login, written {0:>02,d} bytes.".format(bytes_count))

    def get(self):
        """取消登录时的用户个数检查，不限制登陆人数。搞清一个设备实例是否可以由多个用户操作。2017.08.22
        可以允许多个用户操作，server不会退出。
        """
        print("登录前的人数：{0}".format(self.cache.get("iotUsers")))
        self.set_header('Content-Type', 'text/html')
        self.render("login.html")

    def post(self):
        username = self.get_argument("username", None)
        password = self.get_argument("password", None)
        # 以上返回类型为str，它们已经被解码了
        # 下面排除了3种包含None的情况
        if username is None or password is None:
            self.render("login.html")
        else:
            sql = "SELECT * FROM iotusers WHERE username=%s AND password=%s"
            self.cursor.execute(sql, (username, password))  # 返回的是结果集中的行数
            result = self.cursor.fetchone()
            if result.get("password") == password and result.get("username") == username:
                self.set_secure_cookie("username", username, expires_days=None)  # cookie有效期为30min
                # 2017.08.28修复当cookie过期后，用户无法点击退出登录修改访问人数的问题
                # 此处修改为一个定时器任务，在30 min后自动修改访问次数，从而达到与点击退出登录一样的修改作用
                # 删除定时删除cookie的功能，仅在关闭后才删除cookie
                times = self.cache.incr("iotUsers", amount=1)  # 返回增加后的数值
                self.redirect("/welcome", permanent=False)
            else:
                self.redirect("/login", permanent=False)

    def on_finish(self):
        # 每一个请求结束后都会被调用，例如：GET，POST
        print("[INFO] Closing DB ...")
        self.cursor.close()


class WelcomeHandler(BaseHandler):
    """欢迎页面"""
    def initialize(self, database, board):
        self.cacheDB = database
        self.board = board
    
    def prepare(self):
        pass

    def get(self):
        # 当GET请求处理完成后，也算是一次请求结束，会执行on_finish函数
        username = self.get_secure_cookie("username", None)
        if isinstance(username, bytes):
            kwargs = dict()  # 2017.07.29将kwargs置入if语句内
            print("Current user: {0}".format(username))
            kwargs['username'] = username
            kwargsList = self.cacheDB.mget(["iotUsers", "ledStatus", "fanSpeed"])
            if all(kwargsList):
                for key, val in zip(["times", "ledStatus", "fanSpeed"], kwargsList):
                    kwargs[key] = val
            else:
                try:
                    kwargs["times"] = self.cacheDB.get("iotUsers")
                    print("In GET, times: {0}".format(kwargs["times"]))
                except AttributeError as err1:
                    print("[ERROR] {0}".format(err1))
                    self.cacheDB.set("iotUsers", 1)
                    kwargs["times"] = 1
                try:
                    kwargs["ledStatus"] = self.cacheDB.get('ledStatus')
                    print("In GET, ledStatus: {0}".format(kwargs["ledStatus"]))
                except AttributeError as err2:
                    print("[ERROR] {0}".format(err2))
                    kwargs["ledStatus"] = None
                try:
                    kwargs["fanSpeed"] = self.cacheDB.get('fanSpeed')
                    print("In GET, fanSpeed: {0}".format(kwargs["fanSpeed"]))
                except AttributeError as err3:
                    print("[ERROR] {0}".format(err3))
                    kwargs["fanSpeed"] = None
            self.set_header('Content-Type', 'text/html')
            self.render("welcome.html", **kwargs)
        else:
            self.set_header('Content-Type', 'text/html')
            self.redirect("/login")

    def post(self):
        # 检查操作者是否登录
        # 当POST处理完成后，也算是请求结束，会执行on_finish函数
        username = self.get_secure_cookie("username", None)
        if username is None:
            # 如果是未登录的用户恶意操作
            self.redirect("/login")
        else:
            ledStatus = self.get_argument("ledSwitch", "OFF")
            fanSpeed = self.get_argument("fanSpeed", "20")
            # print("Type of fanSpeed: {0}".format(type(fanSpeed)))  # 是 str
            # print(ledStatus)
            print("Got fan speed: {0}".format(fanSpeed))
            print("Write: {0}".format((ledStatus + ',' + fanSpeed + ';')))
            bytes_count = self.board.write((ledStatus + ',' + fanSpeed + ';').encode(encoding='utf_8'))
            print("Writen {0:>02,d} bytes.".format(bytes_count))
            self.cacheDB.set("ledStatus", ledStatus)
            self.cacheDB.set("fanSpeed", fanSpeed)
            # print("ledStatus: {0}".format(ledStatus))
            self.redirect("/welcome")
    
    def on_finish(self):
        print("本次请求结束，访问人数为：{0}".format(self.cacheDB.get("iotUsers")))


class FanHandler(DeviceHandler):
    def post(self):
        username = self.get_secure_cookie("username", None)
        if username is None:
            self.redirect("/login")
        else:
            ledStatus = self.cacheDB.get("ledStatus")
            fanSpeed = self.request.arguments.get('fanSpeed')[0].decode()
            print("fanSpeed: {0}".format(fanSpeed))
            bytes_count = self.board.write((ledStatus + ',' + fanSpeed + ';').encode(encoding='utf_8'))
            print("Writen {0:>02,d} bytes.".format(bytes_count))
            self.cacheDB.set("fanSpeed", fanSpeed)
            self.write(json.dumps({'status': 'ok'}))


class LedHandler(DeviceHandler):
    def post(self):
        username = self.get_secure_cookie("username", None)
        if username is None:
            self.redirect("/login")
        else:
            fanSpeed = self.cacheDB.get("fanSpeed")
            ledStatus = self.request.arguments.get('ledStatus')[0].decode()
            # print("Requests: {0}".format(self.request.arguments.get('ledStatus')))
            print("In LedHandler, ledStatus: {0}".format(ledStatus))
            bytes_count = self.board.write((ledStatus + ',' + fanSpeed + ';').encode(encoding='utf_8'))
            print("Writen {0:>02,d} bytes.".format(bytes_count))
            self.cacheDB.set("ledStatus", ledStatus)
            self.write(json.dumps({'status': 'ok'}))


class LogoutHandler(BaseHandler):
    """退出登录，清理cookie"""
    def initialize(self, cacheDB):
        self.cacheDB = cacheDB

    def get(self):
        self.clear_cookie("username")
        # self.cacheDB.set("iotUsers", 1)
        self.redirect("/login")


if __name__ == "__main__":
    parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application(), xheaders=True)
    http_server.bind(options.port, reuse_port=False)  # On windows, it is unavailable
    http_server.start()
    tornado.ioloop.IOLoop.current().start()
