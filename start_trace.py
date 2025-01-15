import frida
import os
import sys

def read_agent_js_source():
    with open("_agent.js", "r", encoding='utf-8') as f:
        return f.read()

def on_message(message, data):
    print("[DEBUG] Message from script:", message)
    if data:
        print("[DEBUG] Data:", data.hex())
    pass

def build_agent_js():
    _agent_path = "_agent.js"
    if os.path.exists(_agent_path):
        os.remove(_agent_path)
    print("[DEBUG] Building agent.js...")
    os.system("npm run build")

    if not os.path.exists(_agent_path):
        raise RuntimeError('frida-compile agent.js error')

def remove_agent_js():
    _agent_path = "_agent.js"
    if os.path.exists(_agent_path):
        os.remove(_agent_path)

if __name__ == "__main__":
    build_agent_js()

    curdir = os.path.dirname(os.path.abspath(sys.argv[0]))
    libQBDI = os.path.join(curdir, "QBDI/libQBDI.so").replace("\\", "/")
    frida_qbdi_js = os.path.join(curdir, "QBDI/frida-qbdi.js").replace("\\", "/")

    print(f"[DEBUG] libQBDI path: {libQBDI}")
    print(f"[DEBUG] frida-qbdi.js path: {frida_qbdi_js}")

    device: frida.core.Device = frida.get_usb_device()
    print(f"[DEBUG] Connected to device: {device}")

    pid = device.get_frontmost_application().pid
    print(f"[DEBUG] Frontmost application PID: {pid}")

    session: frida.core.Session = device.attach(pid)
    print(f"[DEBUG] Attached to process with PID: {pid}")

    script = session.create_script(read_agent_js_source())
    script.on('message', on_message)
    script.load()
    print("[DEBUG] Script loaded successfully.")

    filesdir = script.exports_sync.getfilesdir()
    print(f"[DEBUG] Files directory on device: {filesdir}")

    target_so_path = os.path.join(filesdir, "libQBDI.so").replace("\\", "/")
    print(f"[DEBUG] Target libQBDI.so path on device: {target_so_path}")

    if not script.exports_sync.checksoexist(target_so_path):
        print("[DEBUG] libQBDI.so does not exist on device. Pushing...")
        with open(libQBDI, "rb") as f:
            so_buffer = f.read()
            script.exports_sync.writelibqbdiso(target_so_path, list(so_buffer))
        print("[DEBUG] libQBDI.so pushed to device.")
    else:
        print("[DEBUG] libQBDI.so already exists on device.")

    log_path = os.path.join(filesdir, "trace.log").replace("\\", "/")
    print(f"[DEBUG] Log file path: {log_path}")

    print("[DEBUG] Starting VM run...")
    script.exports_sync.vmrun(log_path)
    print("[DEBUG] VM run completed.")

    remove_agent_js()
    print("[DEBUG] Cleaned up _agent.js.")