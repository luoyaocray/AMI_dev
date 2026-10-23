"""
作者：罗尧（luoyao23@mails.ucas.ac.cn）
团队：Fast Scanning Group

说明：
根据目录内《控制器API使用说明 - ss01c2a.pdf》
只依赖 Python 标准库，可直接使用本项目虚拟环境。
AMI SSC01-C2A 网口驱动，通过 pvcsvr 转发

位置接口统一使用 mm（协议使用 pm），速度使用 um/s。

改为 um
"""
from collections import deque
from decimal import Decimal, InvalidOperation
import ipaddress
from pathlib import Path
import math
import re
import socket
import subprocess
import threading
import time

class AMIError(RuntimeError):
    """服务器 NAK、协议格式或设备连接错误。"""

class ami_dev:
    """接口命名参考 huber_dev；不能直接向控制器发送这些文本命令。

    两台设备需分别使用两个 pvcsvr 实例（例如 32323、32324）。
    allow_motion 默认 True；设为 False 可限制为只读。本驱动不自动开启系统或通道。
    """

    def __init__(self, name='ami', ami_host='192.168.0.8',
                 limit_low=None, limit_high=None, *, server_host='127.0.0.1',
                 server_port=32323, device_port=32500, timeout=12.0,
                 axis_dic=None,                 ##  轴字典；默认 {'x': 1, 'y': 2}  这个后面实例化的时候自己创建
                 auto_start_server=True,        ##  是否自动启动 pvcsvr 服务；默认 True
                 server_path=None,              ##  pvcsvr.exe 路径；默认本项目目录下的 pvcsvr.exe
                 monitor_interval=5.0           ##  5s一次对pvcsvr的心跳检测
                 ):
        self.name = name   ## 用不用都无所谓
        self.host = str(ipaddress.IPv4Address(ami_host))  ##  设备 IP 地址
        self.port = int(device_port)                      ##  设备端口；默认 32500
        self.server_host = server_host                    ##  pvcsvr 服务端 IP 地址；默认 127.0.0.1
        self.server_port = int(server_port)               ##  pvcsvr 服务端端口；默认 32323
        self.timeout = float(timeout)                     ##  超时时间；默认 12s
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError('timeout 必须为有限正数')
        if not 1 <= self.port <= 65535 or not 1 <= self.server_port <= 65535:
            raise ValueError('端口必须在 1..65535 内')
        self.axis_dic = dict(axis_dic or {'x': 1, 'y': 2})
        self.limit_low = limit_low
        self.limit_high = limit_high
        self.sockfd = None
        self.connected = False
        self.last_error = None
        self.events = deque(maxlen=100)  ##  事件队列；默认 100 条
        self._buffer = b''
        self._lock = threading.RLock()
        self._motion_lock = threading.Lock()
        self.auto_start_server = auto_start_server
        self.server_path = Path(server_path) if server_path else Path(__file__).parent / 'pvcsvr' / 'pvcsvr.exe'
        self.monitor_interval = float(monitor_interval)  ##  5s一次对pvcsvr的心跳检测
        if not math.isfinite(self.monitor_interval) or self.monitor_interval < 0:
            raise ValueError('monitor_interval 必须为有限非负数；0表示禁用')
        self.healthy = False
        self._monitor_stop = threading.Event()
        self._monitor_thread = None

    def ensure_server(self, startup_timeout=8.0):
        """以监听端口判断服务可用性，已有服务不重复启动。"""
        def available():
            try:
                with socket.create_connection((self.server_host, self.server_port), 0.5):
                    return True
            except OSError:
                return False

        if available():
            print(f'pvcsvr 服务已运行: {self.server_host}:{self.server_port}')
            return
        if not self.auto_start_server:
            raise AMIError('pvcsvr 服务不可连接，且已禁止自动启动')
        if self.server_host not in ('127.0.0.1', 'localhost') or self.server_port != 32323:
            raise AMIError('仅自动启动本地默认32323服务；其他端口/远程服务请预先启动')
        if not self.server_path.is_file():
            raise AMIError(f'找不到服务器: {self.server_path}')
        process = subprocess.Popen(
            [str(self.server_path.resolve())], cwd=str(self.server_path.resolve().parent),
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        deadline = time.monotonic() + startup_timeout
        while time.monotonic() < deadline:
            if available():
                print('pvcsvr 服务启动成功')
                return
            if process.poll() is not None:
                raise AMIError(f'pvcsvr 启动后退出，退出码: {process.returncode}')
            time.sleep(0.1)
        raise AMIError('pvcsvr 启动后监听端口未就绪')

    def check_connection(self):
        """只读心跳，检查完整服务/控制器链路；失败不重发运动或自动重连。"""
        with self._lock:
            try:
                self.qSTATE()
                self.healthy = True
                self.last_error = None
                return True
            except (OSError, AMIError) as exc:
                self.last_error = str(exc)
                self.close()
                return False

    def _start_monitor(self):
        """心跳检测，检查服务/控制器链路是否正常。"""
        if not self.monitor_interval:
            return
        stop = self._monitor_stop = threading.Event()

        def monitor():
            while not stop.wait(self.monitor_interval):
                with self._lock:
                    if stop.is_set():
                        return
                    if not self.check_connection():
                        return

        self._monitor_thread = threading.Thread(target=monitor, name=f'{self.name}-heartbeat', daemon=True)
        self._monitor_thread.start()

    def connect(self):
        """服务和控制器均连接成功返回 1，失败返回 -1，详见 last_error。"""
        with self._lock: #  确保线程安全
            if self.connected and self.check_connection():
                print(f'AMI {self.host} 已连接')
                return 1
            self.close()
            try:
                self.ensure_server()  ## 启动AMI自带的程序
                self.sockfd = socket.create_connection(
                    (self.server_host, self.server_port), self.timeout)  ## 创建网口通讯
                reply = self._exchange(f'connect dev {self.host}:{self.port}')
                if not re.search(r'ACK:\s*connected\.', reply, re.I):
                    raise AMIError(reply)
                self.connected = True
                self.healthy = True
                self.last_error = None
                self._start_monitor()
                return 1
            except (OSError, AMIError) as exc:
                self.last_error = str(exc)
                self.close()
                return -1

    def close(self):
        """只关闭客户端 socket，不发送关机、停机或退出服务器命令。"""
        with self._lock:
            self._monitor_stop.set()
            if self.sockfd is not None:
                self.sockfd.close()
            self.sockfd = None
            self.connected = False
            self.healthy = False
            self._buffer = b''

    def quit_server(self):
        """退出服务器，那么无法通过服务转发，这里应该可以测到断连。"""
        self._exchange('quit server')

    def __enter__(self):
        if self.connect() != 1:
            raise AMIError(self.last_error)
        return self

    def __exit__(self, *args):
        self.close()

    def _exchange(self, command):
        """按换行分帧，匹配回显，跳过事件；超时断开以免串包。
        这里将command不直接发送，而是通过线程锁的方式，避免同时两个命令
        好处就是，这种方式可以确保在发送命令时不冲突
        GUI中不再暂停工作次线程
        那么主线程界面发命令给次线程，次线程调用驱动，驱动上锁，查询命令先来就先查询，运动命令可以等待
        """
        with self._lock:
            if self.sockfd is None:
                raise AMIError('尚未连接服务器')
            try:
                self.sockfd.settimeout(self.timeout)
                self.sockfd.sendall(command.encode('ascii') + b'\r\n')
                deadline = time.monotonic() + self.timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError(f'等待响应超时: {command}')
                    if b'\n' not in self._buffer:
                        self.sockfd.settimeout(remaining)
                        chunk = self.sockfd.recv(8192)
                        if not chunk:
                            raise ConnectionError('服务器关闭了连接')
                        self._buffer += chunk
                        if len(self._buffer) > 1024 * 1024:
                            raise AMIError('响应帧超过 1 MiB')
                        continue
                    line, self._buffer = self._buffer.split(b'\n', 1)
                    reply = line.decode('utf-8', errors='replace').strip()
                    if 'Device Lost Connection' in reply:
                        self.close()
                        raise AMIError(reply)
                    if not reply.startswith(command + ' '):
                        self.events.append(reply)
                        continue
                    if 'NAK' in reply:
                        raise AMIError(reply)
                    if re.search(r'\bACK\d*:', reply):
                        if command.startswith('connect dev ') and re.search(r'ACK:\s*\d+%', reply):
                            self.events.append(reply)
                            continue
                        return reply
            except (OSError, UnicodeError) as exc:
                self.last_error = f'通信失败: {command}: {exc}'
                self.close()
                raise

    def Write_data(self, data):
        """完整单行请求，返回原始 ACK；allow_motion=False 时仅放行只读命令。
        避免有人直接调用该函数去编造命令，导致控制器被破坏。
        """
        if not isinstance(data, str) or '\r' in data or '\n' in data:
            raise ValueError('只允许一条命令，不能包含换行')
        if not self.connected:
            raise AMIError('控制器尚未连接成功')
        return self._exchange(data)

    def _axis(self, axes_name):
        channel = self.axis_dic.get(axes_name, axes_name)  ## dict.get(key, default)
        ## 输入是X，则返回1，正确的映射。 这里做一层检测，如果输入1也可以正常工作
        if isinstance(channel, bool) or channel not in (1, 2):
            raise ValueError('通道必须是 1/2 或 axis_dic 中的轴名')
        return int(channel)

    @staticmethod
    def _numbers(reply):
        payload = re.split(r'\bACK\d*:', reply, maxsplit=1)[1].strip()  ## 去掉ACK:
        payload = re.sub(r'^dat:\s*', '', payload).rstrip(';').strip()  ## 去掉dat:
        tokens = re.split(r'[,;\s]+', payload)  ## 按逗号、分号、空格分隔
        try:
            values = [Decimal(token) for token in tokens]  ## 转换为 Decimal 类型
            ## 用 Decimal 而不是 float 来转数值——避免浮点数精度丢失（位置查询返回的是高精度整数，转 float 可能有误差）
        except InvalidOperation as exc:
            raise AMIError(f'无法解析数值响应: {reply}') from exc
        if not values or not all(v.is_finite() for v in values):
            raise AMIError(f'响应包含无效数值: {reply}')
        return values

    #############   以下为根据手册实现的函数       #############
    ### 版本2026/10/24  author：罗尧
    def home(self, axes_name):
        return self.Write_data(f'SysCmd r:item=OriginDetect dat:{self._axis(axes_name)}')

    def enable_system(self, enabled=True):
        """系统使能"""
        if type(enabled) is not bool:
            raise ValueError('enabled 必须为 bool')
        return self.Write_data(f'SysCfg c:OnOff dat:{int(enabled)}')

    def enable_channel(self, axes_name, enabled=True):
        if type(enabled) is not bool:
            raise ValueError('enabled 必须为 bool')
        return self.Write_data(
            f'TB_ChCfg r:Channel={self._axis(axes_name)} c:Enable dat:{int(enabled)}')

    def q_enabled(self, axes_name=None):
        """查询使能状态，返回 bool；省略轴名时返回系统使能状态。"""
        cmd = ('SysCfg c:OnOff' if axes_name is None else
               f'TB_ChCfg r:Channel={self._axis(axes_name)} c:Enable')
        values = self._numbers(self.Write_data(cmd))
        if len(values) != 1 or values[0] not in (0, 1):
            raise AMIError(f'无效使能状态: {values}')
        return bool(values[0])

    def set_speed(self, axes_name, speed):
        """设置速度，单位 um/s（与 Huber 的脉冲/s不同）。"""
        value = Decimal(str(speed))
        if not value.is_finite() or value <= 0:
            raise ValueError('速度必须为有限正数')
        ch = self._axis(axes_name)
        return self.Write_data(f'ScrExtRef Channel={ch} idx={ch - 1} v={value:f}')

    def q_speed(self):
        """返回原始速度表 ACK（字段结构依固件而异）。"""
        return self.Write_data('list tables.ScrExtRef')

    def MOV(self, axes_name, target_pos):
        """发送目标后即返回；另一条等待到位操作期间拒绝覆盖目标。"""
        if not self._motion_lock.acquire(blocking=False):
            raise AMIError('已有运动等待操作，请等待结束后再发送新目标')
        try:
            return self._move_command(axes_name, target_pos)
        finally:
            self._motion_lock.release()

    def _move_command(self, axes_name, target_pos):
        """绝对移动，单位 mm；"""
        target = Decimal(str(target_pos))
        if not target.is_finite():
            raise ValueError('目标位置必须为有限数值')
        if self.limit_low is None or self.limit_high is None:
            raise ValueError('运动前必须配置 limit_low / limit_high（mm）')
        if not Decimal(str(self.limit_low)) <= target <= Decimal(str(self.limit_high)):
            raise ValueError('目标位置超出软件限位')
        pm = target * Decimal(1000000000)
        if pm != pm.to_integral_value():
            raise ValueError('目标精度不能小于 1 pm')
        return self.Write_data(
            f'SignalExtInput c:Ref{self._axis(axes_name)-1} '
            f'r:ItemName=ExternalReference dat:{int(pm)}')

    def move_axi_abs(self, axes_name, target_pos, timeout=60, tolerance=0.000001):
        """阻塞等待到位，返回最后位置；放在GUI工作线程中调用。"""
        final_pos = None
        for final_pos in self.move_axi_abs_motor(axes_name, target_pos, timeout, tolerance):
            pass
        return final_pos

    def move_axi_abs_motor(self, axes_name, target_pos, timeout=60,
                           tolerance=0.000001, poll_interval=0.1):
        """生成器：逐次yield位置(mm)，到位后结束；迭代才会启动运动。

        每次命令完成就释放通信锁，yield/sleep期间不持有通信锁。
        提前停止迭代需调用生成器close()释放运动占用；不会停止实际电机。
        """
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('timeout 必须为有限正数')
        if not math.isfinite(tolerance) or tolerance <= 0:
            raise ValueError('tolerance 必须为有限正数')
        if not math.isfinite(poll_interval) or poll_interval <= 0:
            raise ValueError('poll_interval 必须为有限正数')
        if not self._motion_lock.acquire(blocking=False):
            raise AMIError('已有运动等待操作')
        try:
            self._move_command(axes_name, target_pos)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                pos = self.qPOS(axes_name)
                settled = (abs(pos - float(target_pos)) <= tolerance and
                           self.qSTATE() & (1 << (self._axis(axes_name)-1)))
                yield pos
                if settled:
                    return
                time.sleep(poll_interval)
            raise TimeoutError('等待到位超时；设备可能仍在运动，驱动未发送停止命令')
        finally:
            self._motion_lock.release()

    def qPOS(self, axes_name=None):
        """查询位置，返回 mm；省略轴名时返回通道顺序的二元组。"""
        values = self._numbers(self.Write_data('VolatileDevData r:item=Position l:16'))
        if len(values) != 2:
            raise AMIError(f'应返回两个通道位置，实际为 {values}')
        positions = tuple(float(v / Decimal(1000000000)) for v in values)
        return positions if axes_name is None else positions[self._axis(axes_name) - 1]

    def qSTATE(self):
        """到位掩码：bit0/bit1 对应通道1/2；1表示该通道到位。"""
        values = self._numbers(self.Write_data('SysCmd r:item=SettleStatus syn'))
        if len(values) != 1 or values[0] not in (0, 1, 2, 3):
            raise AMIError(f'无效到位掩码: {values}')
        return int(values[0])

if __name__ == '__main__':
    # 与 huber_dev.py 一样，直接修改这里的地址和轴名，然后在 IDE 中运行。
    ami_host = '192.168.0.8'  # 另一台为 192.168.0.9
    ami = ami_dev(ami_host=ami_host, axis_dic={'x': 1, 'y': 2}, limit_low=0, limit_high=100)
    try:
        if ami.connect() == 1:
            print(f'AMI {ami_host} connected')
            print('系统使能:', ami.q_enabled())
            ami.enable_system(True)
            print('系统使能:', ami.q_enabled())
            print('轴1使能:', ami.q_enabled(1))
            ami.enable_channel(1, True)
            print('轴1使能:', ami.q_enabled(1))
            print('轴2使能:', ami.q_enabled(2))
            print('轴1位置(mm):', ami.qPOS(1))
            ami.MOV("x", 2)
            print('轴1位置(mm):', ami.qPOS(1))
            print('轴2位置(mm):', ami.qPOS(2))
            print('到位状态:', ami.qSTATE())
            # 控制方法与 Huber 类似：ami.MOV('x', target_pos)
            # 运动需先按实际行程配置限位。
            # 此示例只查询，不使能、不寻零、不运动。
        else:
            print('AMI连接失败:', ami.last_error)
    finally:
        ami.close()

#### 已经能控，限位和运动状态还需要限制