import frida
import os
import sys


def read_agent_js_source():
    """
    读取 _agent.js 文件内容。
    """
    with open("_agent.js", "r", encoding='utf-8') as f:
        return f.read()


def on_message(message, data):
    """
    处理从设备端发送的消息。
    """
    if message['type'] == 'send':  # 检查消息类型
        log = message['payload']  # 获取日志内容
        print(f"[DEBUG] Received log: {log}")

        # 确保日志是字符串类型
        if not isinstance(log, str):
            log = str(log)

        # 检查日志内容是否为空
        if not log or log.strip() == "":
            print("[WARNING] Ignoring empty log.")
            return

        # 确保日志以换行符结束
        if not log.endswith('\n'):
            log += '\n'

        # 将日志添加到缓冲区
        log_buffer.append(log)
        print(f"[DEBUG] Log added to buffer: {log.strip()}")
    else:
        print(f"[DEBUG] Received message: {message}")


def build_agent_js():
    """
    编译 agent.js 文件。
    """
    _agent_path = "_agent.js"
    if os.path.exists(_agent_path):
        os.remove(_agent_path)
    print("[DEBUG] Building agent.js...")
    os.system("npm run build")

    if not os.path.exists(_agent_path):
        raise RuntimeError('frida-compile agent.js error')


def remove_agent_js():
    """
    删除 _agent.js 文件。
    """
    _agent_path = "_agent.js"
    if os.path.exists(_agent_path):
        os.remove(_agent_path)


def create_log_directory(log_path):
    """
    创建日志文件所在的目录（如果不存在）。

    Args:
        log_path (str): 日志文件的完整路径
    """
    log_dir = os.path.dirname(log_path)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        print(f"[DEBUG] Created log directory: {log_dir}")


def verify_file_permissions(file_path):
    """
    验证文件权限。

    Args:
        file_path (str): 要验证的文件路径
    Returns:
        bool: 是否具有写入权限
    """
    try:
        with open(file_path, "a") as f:
            f.write("")
        return True
    except IOError as e:
        print(f"[ERROR] File permission error: {e}")
        return False


if __name__ == "__main__":
    try:
        # 编译 agent.js
        build_agent_js()

        # 获取当前目录
        curdir = os.path.dirname(os.path.abspath(sys.argv[0]))

        # 设置 libQBDI.so 和 frida-qbdi.js 的路径
        libQBDI = os.path.join(curdir, "QBDI/libQBDI.so").replace("\\", "/")
        frida_qbdi_js = os.path.join(curdir, "QBDI/frida-qbdi.js").replace("\\", "/")

        print(f"[DEBUG] libQBDI path: {libQBDI}")
        print(f"[DEBUG] frida-qbdi.js path: {frida_qbdi_js}")

        # 连接到设备
        device: frida.core.Device = frida.get_usb_device()
        print(f"[DEBUG] Connected to device: {device}")

        # 获取前台应用的 PID
        pid = device.get_frontmost_application().pid
        print(f"[DEBUG] Frontmost application PID: {pid}")

        # 附加到目标进程
        session: frida.core.Session = device.attach(pid)
        print(f"[DEBUG] Attached to process with PID: {pid}")

        # 创建脚本并加载
        script = session.create_script(read_agent_js_source())
        script.on('message', on_message)  # 绑定 on_message 回调
        script.load()
        print("[DEBUG] Script loaded successfully.")

        # 获取设备上的文件目录
        filesdir = script.exports_sync.getfilesdir()
        print(f"[DEBUG] Files directory on device: {filesdir}")

        # 设置目标 libQBDI.so 路径
        target_so_path = os.path.join(filesdir, "libQBDI.so").replace("\\", "/")
        print(f"[DEBUG] Target libQBDI.so path on device: {target_so_path}")

        # 检查 libQBDI.so 是否存在，如果不存在则推送到设备
        if not script.exports_sync.checksoexist(target_so_path):
            print("[DEBUG] libQBDI.so does not exist on device. Pushing...")
            with open(libQBDI, "rb") as f:
                so_buffer = f.read()
                script.exports_sync.writelibqbdiso(target_so_path, list(so_buffer))
            print("[DEBUG] libQBDI.so pushed to device.")
        else:
            print("[DEBUG] libQBDI.so already exists on device.")

        # 设置日志文件路径
        log_path = os.path.join(filesdir, "trace.log").replace("\\", "/")
        print(f"[DEBUG] Log file path on device: {log_path}")

        # 设置本地日志文件路径
        local_log_path = os.path.join(curdir, "local_trace.txt").replace("\\", "/")
        print(f"[DEBUG] Local log file path: {local_log_path}")

        # 创建日志目录（如果不存在）
        create_log_directory(local_log_path)

        # 验证文件权限
        if not verify_file_permissions(local_log_path):
            raise PermissionError(f"Cannot write to log file: {local_log_path}")

        # 创建一个变量来存储日志内容
        log_buffer = []

        # 启动 VM 运行
        try:
            print("[DEBUG] Starting VM run...")
            script.exports_sync.vmrun(log_path)
            print("[DEBUG] VM run completed.")
        except Exception as e:
            print(f"[ERROR] VM run failed: {e}")

        # 将 log_buffer 中的内容写入本地文件
        if log_buffer:
            print("[DEBUG] Writing logs to local file...")
            with open(local_log_path, "w", encoding="utf-8") as local_log_file:
                local_log_file.writelines(log_buffer)
            print(f"[DEBUG] Logs written to {local_log_path}.")  # 修复变量名
        else:
            print("[WARNING] No logs received.")

    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
    finally:
        # 清理 _agent.js 文件
        remove_agent_js()
        print("[DEBUG] Cleaned up _agent.js.")