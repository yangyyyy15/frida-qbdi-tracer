import { VM, InstPosition, VMAction, Options, MemoryAccessType, AnalysisType, RegisterAccessType, OperandType ,VMEvent} from "./QBDI/frida-qbdi.js";
import warp_vm_run from "./warp_vm_run.js";

function vm_run(func_ptr, args, log_file_path) {
    let start_time = new Date().getTime();
    console.log("[DEBUG] Starting VM run...");

    // 创建 QBDI VM 实例
    let vm = new VM();
    console.log("[DEBUG] VM instance created.");

    // 设置 VM 选项，启用异常处理
    vm.setOptions(
        Options.OPT_DISABLE_LOCAL_MONITOR |
        Options.OPT_BYPASS_PAUTH |
        Options.OPT_ENABLE_BTI |
        Options.OPT_ENABLE_EXCEPTION_HANDLING
    );
    console.log("[DEBUG] VM options set.");

    // 分配虚拟栈
    vm.allocateVirtualStack(vm.getGPRState(), 0x100000);
    console.log("[DEBUG] Virtual stack allocated.");

    // 打开手机上的日志文件
    console.log("log_file_path: ", log_file_path);
    let file_pointer = new File(log_file_path, "w");
    console.log("[DEBUG] Log file opened on device.");

    // 获取目标模块信息
    let module = Process.findModuleByAddress(func_ptr);
    let user_data = {
        "file_pointer": file_pointer,
        "module_base": module.base,
        "module_name": module.name
    };
    console.log(`[DEBUG] Instrumenting module: ${module.name} at base address: ${module.base.toString(16)}`);

    // 添加目标模块到 VM
    vm.addInstrumentedModuleFromAddr(func_ptr);
    console.log("[DEBUG] Module instrumented.");

    // 添加异常处理回调
    let exception_callback = vm.newVMCallback(function (vm, event, gpr, fpr, data) {
        console.log("[DEBUG] Exception occurred:", event);
        return VMAction.CONTINUE; // 继续执行
    });
    vm.addVMEventCB(VMEvent.SIGNAL, exception_callback, user_data);
    console.log("[DEBUG] Exception callback added.");

    // 添加指令执行前回调（PREINST）
    let preinst_callback = vm.newInstCallback(function (vm, gpr, fpr, data) {
        let _user_data = data;
        let inst = vm.getInstAnalysis(
            AnalysisType.ANALYSIS_INSTRUCTION |
            AnalysisType.ANALYSIS_DISASSEMBLY |
            AnalysisType.ANALYSIS_OPERANDS |
            AnalysisType.ANALYSIS_SYMBOL
        );

        let log = "0x" + inst.address.toString(16) + " [" + inst.module + "!0x" + (inst.address - _user_data.module_base).toString(16) + "] " + inst.disassembly + "\t";
        let read_regs = "";
        inst.operands.forEach(operand => {
            if (operand.regAccess == RegisterAccessType.REGISTER_READ || operand.regAccess == RegisterAccessType.REGISTER_READ_WRITE) {
                if (operand.regCtxIdx != -1) {
                    if (operand.type == OperandType.OPERAND_GPR) {
                        try {
                            read_regs += operand.regName + "=" + gpr.getRegister(operand.regCtxIdx) + " ";
                        } catch (error) {
                            console.error(error);
                        }
                    }
                }
            }
        });
        if (read_regs != "") {
            if (read_regs[read_regs.length - 1] === " ") {
                read_regs = read_regs.slice(0, -1);
            }
            log += " r[" + read_regs + "]";
        }

        // 检查日志内容是否为空
        if (log && log.trim() !== "") {
            console.log("[DEBUG] Sending log to Python (PREINST):", log);
            send(log);  // 使用 send() 发送日志
        } else {
            console.error("[ERROR] Log is empty or invalid (PREINST).");
        }

        return VMAction.CONTINUE;
    });

    // 添加指令执行后回调（POSTINST）
    let postinst_callback = vm.newInstCallback(function (vm, gpr, fpr, data) {
        let _user_data = data;
        let inst = vm.getInstAnalysis(
            AnalysisType.ANALYSIS_INSTRUCTION |
            AnalysisType.ANALYSIS_DISASSEMBLY |
            AnalysisType.ANALYSIS_OPERANDS |
            AnalysisType.ANALYSIS_SYMBOL
        );
        let write_regs = "";
        inst.operands.forEach(operand => {
            if (operand.regAccess == RegisterAccessType.REGISTER_WRITE || operand.regAccess == RegisterAccessType.REGISTER_READ_WRITE) {
                if (operand.regCtxIdx != -1) {
                    if (operand.type == OperandType.OPERAND_GPR) {
                        try {
                            write_regs += operand.regName + "=" + gpr.getRegister(operand.regCtxIdx) + " ";
                        } catch (error) {
                            console.error(error);
                        }
                    }
                }
            }
        });
        if (write_regs != "") {
            if (write_regs[write_regs.length - 1] === " ") {
                write_regs = write_regs.slice(0, -1);
            }
            let log = " w[" + write_regs + "]\n";

            // 检查日志内容是否为空
            if (log && log.trim() !== "") {
                console.log("[DEBUG] Sending log to Python (POSTINST):", log);
                send(log);  // 使用 send() 发送日志
            } else {
                console.error("[ERROR] Log is empty or invalid (POSTINST).");
            }
        } else {
            let log = "\n";

            // 检查日志内容是否为空
            if (log && log.trim() !== "") {
                console.log("[DEBUG] Sending log to Python (POSTINST):", log);
                send(log);  // 使用 send() 发送日志
            } else {
                console.error("[ERROR] Log is empty or invalid (POSTINST).");
            }
        }
        return VMAction.CONTINUE;
    });

    // 添加回调到 VM
    vm.addCodeCB(InstPosition.PREINST, preinst_callback, user_data);
    vm.addCodeCB(InstPosition.POSTINST, postinst_callback, user_data);
    console.log("[DEBUG] Callbacks added to VM.");

    // 调用目标函数
    console.log("start vm.call");
    try {
        let ret = vm.call(func_ptr, args);

        // 关闭手机上的日志文件
        file_pointer.close();
        console.log("[DEBUG] Device log file closed.");

        let end_time = new Date().getTime();
        console.log('cost is', `${(end_time - start_time)/1e3}s`);
        return ret;
    } catch (e) {
        // 捕获异常并记录偏移地址
        let current_inst = vm.getInstAnalysis(
            AnalysisType.ANALYSIS_INSTRUCTION |
            AnalysisType.ANALYSIS_DISASSEMBLY |
            AnalysisType.ANALYSIS_OPERANDS |
            AnalysisType.ANALYSIS_SYMBOL
        );

        // 计算偏移地址
        let offset = current_inst.address - module.base;
        let error_message = `[ERROR] Access violation at offset: 0x${offset.toString(16)} (${current_inst.disassembly})\n`;
        console.error(error_message);

        // 写入手机上的日志文件
        file_pointer.write(error_message);
        console.log(`[DEBUG] Wrote to log (ERROR): ${error_message}`);

        // 通过 send() 将日志发送到电脑
        send(error_message);

        // 关闭日志文件
        file_pointer.close();
        return null;
    }
}

function chmod(path) {
    var chmod_ptr = Module.getExportByName('libc.so', 'chmod');
    var chmod_func = new NativeFunction(chmod_ptr, 'int', ['pointer', 'int']);
    var c_path = Memory.allocUtf8String(path);
    chmod_func(c_path, parseInt('0755', 8));
    console.log(`[DEBUG] chmod 0755 applied to: ${path}`);
}

function getContext() {
    let currentApplication = Java.use("android.app.ActivityThread").currentApplication();
    return currentApplication.getApplicationContext();
}

async function getFilesDir() {
    return await new Promise(resolve => {
        Java.perform(() => {
            let path = getContext().getFilesDir().getAbsolutePath();
            let File = Java.use("java.io.File");
            let file = File.$new(path);
            if (!file.exists()) {
                file.mkdirs();
            }
            console.log(`[DEBUG] Files directory: ${path}`);
            resolve(path);
        });
    });
}

async function checkQBDIExist(so_path) {
    return await new Promise(resolve => {
        Java.perform(() => {
            let File = Java.use("java.io.File");
            let file = File.$new(so_path);
            if (file.exists()) {
                console.log(`[DEBUG] libQBDI.so exists at: ${so_path}`);
                resolve(true);
            } else {
                console.log(`[DEBUG] libQBDI.so does not exist at: ${so_path}`);
                resolve(false);
            }
        });
    });
}

function call_vm_run(log_file_path) {
    console.log("[DEBUG] Calling warp_vm_run...");
    warp_vm_run(vm_run, log_file_path);
}

rpc.exports = {
    getfilesdir: function () {
        return getFilesDir();
    },
    writelibqbdiso: function (so_path, so_buffer) {
        console.log(`[DEBUG] Writing libQBDI.so to: ${so_path}`);
        let file = new File(so_path, "wb");
        file.write(so_buffer);
        file.close();
        chmod(so_path);
    },
    checksoexist: function (so_path) {
        return checkQBDIExist(so_path);
    },
    vmrun: function (log_file_path) {
        console.log("start vmrun");
        call_vm_run(log_file_path);
        console.log("end vmrun");
    },
    writelog: function (log) {
        console.log("[writelogcalled] writelog called with log:", log);
        // 这个函数会在电脑端实现
    }
};