import sys


def open_coverage_file(coverage_file_name):
    fp = open(coverage_file_name, "r")
    return fp


def get_file_name(line):
    filename = line.split(":")[1]
    return filename.lstrip().rstrip()


def get_unpacker_module_name(coverage_file_stream):
    unpacker_name = next(coverage_file_stream).split(":")[1].lstrip().rstrip()
    return unpacker_name


def get_module_coverage(coverage_file_stream):
    unique_insn = int(next(coverage_file_stream).lstrip().split(" ")[0], 10)
    unique_bbl = int(next(coverage_file_stream).lstrip().split(" ")[0], 10)
    total_insn = int(next(coverage_file_stream).lstrip().split(" ")[0], 10)
    total_bbl = int(next(coverage_file_stream).lstrip().split(" ")[0], 10)
    return {"n. unique insn": unique_insn, "n. unique bbl": unique_bbl, "n. total insn": total_insn,
            "n. total bbl": total_bbl}


def parse(coverage_file_stream):
    parsed_coverage_results = []
    coverage_record = {}
    filename = ""
    unpacker_module_name = ""
    for line in coverage_file_stream:
        # A coverage block is started
        if line.lstrip().rstrip() == "----- START -----":
            coverage_record = {}
        # Get the filename of the current coverage block
        elif line.startswith("FILENAME"):
            filename = get_file_name(line)
            coverage_record.update({filename: []})
        # per-module coverage result
        elif line.lstrip().rstrip() == "----- COVERAGE ANALYSIS -----":
            unpacker_module_name = get_unpacker_module_name(coverage_file_stream)
            coverage_module_record = get_module_coverage(coverage_file_stream)
            coverage_record[filename].append({unpacker_module_name: coverage_module_record})
        elif line.lstrip().rstrip() == "----- END -----":
            parsed_coverage_results.append(coverage_record)
    return parsed_coverage_results


def calculate_hottest_unpacker_module(unpacker_module_list, filename):
    max_insn = 0
    hottest_module = {}
    unpacker_modules = unpacker_module_list[filename]
    for unpacker_module in unpacker_modules:
        coverage_data = list(unpacker_module.values())[0]
        if coverage_data['n. total insn'] > max_insn:
            hottest_module = unpacker_module
            max_insn = coverage_data['n. total insn']
    return hottest_module


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python3 parse_coverage_file.py coverage_file.txt")
        exit()
    coverage_file = sys.argv[1]
    fp = open_coverage_file(coverage_file)
    parsed_coverage = parse(fp)

    # Calculate the hottest unpacker for all files
    for file_entry in parsed_coverage:
        filename = list(file_entry)[0]
        hottest_unpacker_module = calculate_hottest_unpacker_module(file_entry, filename)
        print(f"Hottest unpacker for: {filename}")
        print(hottest_unpacker_module)

6c00000055550000