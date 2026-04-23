import re
import sys

regex = re.compile(r"Memory range for ([a-zA-Z0-9\.\_]+): (0x[0-9a-f]+) - (0x[0-9a-f]+). Size: (0x[0-9a-f]+)")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("./get_plugin_range_from_addr.py logfile.txt addr")
        exit()
    addr = int(sys.argv[2], 16)
    fp = open(sys.argv[1], "r")
    for line in fp:
        groups = regex.match(line)
        start_addr = int(groups[2], 16)
        end_addr = int(groups[3], 16)
        mod_name = groups[1]
        size = int(groups[4], 16)
        if addr > start_addr and addr < end_addr:
            print(f"Module name: {mod_name} Start addr: {hex(start_addr)} End addr: {hex(end_addr)} Size: {hex(size)}")
            break

