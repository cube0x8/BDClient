import re
import sys

regex = re.compile(r"Memory range for ([a-zA-Z0-9\.\_]+): (0x[0-9a-f]+) - (0x[0-9a-f]+). Size: (0x[0-9a-f]+)")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("./get_plugin_range_from_addr.py logfile1.txt logfile2.txt")
        exit()
    fp1 = open(sys.argv[1], "r")
    fp2 = open(sys.argv[2], "r")
    map_1 = {}
    map_2 = {}
    for line in fp1:
        groups = regex.match(line)
        start_addr = int(groups[2], 16)
        mod_name = groups[1]
        map_1[mod_name] = start_addr
    for line in fp2:
        groups = regex.match(line)
        start_addr = int(groups[2], 16)
        mod_name = groups[1]
        map_2[mod_name] = start_addr

    if map_1 == map_2:
        print("they're equal")
