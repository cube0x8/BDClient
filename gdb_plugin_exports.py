import gdb
import os
from datetime import datetime

# Offset relativo al return site dopo XlmrdLoadModule, calcolato dalla base
# runtime del modulo xlmrd.cvd quando viene protetto/deoffuscato.
XLMRD_LOAD_MODULE_RET_ADDR_OFFSET = 0x336E

LOG_PATH = "/tmp/plugin_exports_helper.log"

STATE = {
    "target_plugin": None,
    "xlmrd_ret_addr": None,
    "armed": False,
    "vp_bp": None,
}

def log(msg):
    line = f"{datetime.now().strftime('%H:%M:%S')} {msg}\n"
    with open(LOG_PATH, "a", encoding="utf-8") as fp:
        fp.write(line)
        fp.flush()

def read_mem(addr, size):
    inferior = gdb.selected_inferior()
    return inferior.read_memory(addr, size).tobytes()

def read_u64(addr):
    return int.from_bytes(read_mem(addr, 8), "little")

def read_u32(addr):
    return int.from_bytes(read_mem(addr, 4), "little")

def read_c_string(addr, max_len=256):
    inferior = gdb.selected_inferior()
    out = bytearray()
    for i in range(max_len):
        b = inferior.read_memory(addr + i, 1).tobytes()
        if b == b"\x00":
            break
        out += b
    return out.decode("utf-8", errors="replace")

def dump_exports_from_handle(hmodule):
    exports = read_u64(hmodule + 0x0)
    image_base = read_u64(hmodule + 0x130)
    image_size = read_u32(hmodule + 0x138)

    log(f"[+] hModule         = 0x{hmodule:x}")
    log(f"[+] exports         = 0x{exports:x}")
    log(f"[+] mappedImageBase = 0x{image_base:x}")
    log(f"[+] mappedImageSize = 0x{image_size:x}")
    log("[+] export table:")

    idx = 0
    while True:
        entry = exports + idx * 0x10
        name_ptr = read_u64(entry + 0x0)
        proc_ptr = read_u64(entry + 0x8)

        if name_ptr == 0 and proc_ptr == 0:
            break

        try:
            name = read_c_string(name_ptr)
        except Exception:
            name = f"<bad-string@0x{name_ptr:x}>"

        log(f'    "{name}" -> 0x{proc_ptr:x}')
        idx += 1

class XlmrdReturnBreakpoint(gdb.Breakpoint):
    def __init__(self, addr):
        super().__init__(f"*0x{addr:x}", temporary=True, internal=False)

    def stop(self):
        try:
            hmodule = int(gdb.parse_and_eval("$rax"))
            log("[+] XlmrdLoadModule returned")
            dump_exports_from_handle(hmodule)
        except Exception as e:
            log(f"[!] failed dumping handle: {e}")
        return True

class VirtualProtectBreakpoint(gdb.Breakpoint):
    def __init__(self):
        super().__init__("winapi/Memory.c:166", internal=False)

    def stop(self):
        try:
            plugin_name_ptr = int(gdb.parse_and_eval("plugin_name"))
            lpAddress = int(gdb.parse_and_eval("lpAddress"))
            dwSize = int(gdb.parse_and_eval("dwSize"))
            plugin_name = read_c_string(plugin_name_ptr)
        except Exception as e:
            log(f"[!] VirtualProtect parse failed: {e}")
            return False

        log(f"[DEBUG] VirtualProtect plugin={plugin_name} base=0x{lpAddress:x} size=0x{dwSize:x}")

        if plugin_name == "xlmrd.cvd":
            STATE["xlmrd_ret_addr"] = lpAddress + XLMRD_LOAD_MODULE_RET_ADDR_OFFSET
            log("[+] xlmrd.cvd matched")
            log(f"[+] XlmrdLoadModule return addr = 0x{STATE['xlmrd_ret_addr']:x}")
            return False

        if plugin_name == STATE["target_plugin"]:
            log(f"[+] target plugin matched: {plugin_name}")

            if STATE["xlmrd_ret_addr"] is None:
                log("[!] xlmrd return address is still unknown")
                return True

            if not STATE["armed"]:
                XlmrdReturnBreakpoint(STATE["xlmrd_ret_addr"])
                STATE["armed"] = True
                log(f"[+] armed temporary breakpoint at 0x{STATE['xlmrd_ret_addr']:x}")

            gdb.post_event(lambda: gdb.execute("continue"))
            return False

        return False

class PluginExportsHelper(gdb.Command):
    def __init__(self):
        super().__init__("plugin-exports-helper", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if len(argv) != 1:
            log("usage: plugin-exports-helper <plugin_name>")
            return

        STATE["target_plugin"] = argv[0]
        STATE["xlmrd_ret_addr"] = None
        STATE["armed"] = False

        try:
            if os.path.exists(LOG_PATH):
                os.remove(LOG_PATH)
        except Exception:
            pass

        if STATE["vp_bp"] is not None:
            try:
                STATE["vp_bp"].delete()
            except:
                pass

        STATE["vp_bp"] = VirtualProtectBreakpoint()

        log(f"[+] target_plugin = {STATE['target_plugin']}")
        log("[+] VirtualProtect breakpoint installed")
        log("[+] run: continue")

PluginExportsHelper()

