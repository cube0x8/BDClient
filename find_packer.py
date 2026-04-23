import zlib
import sys
import os
import re

import peid
from pefile import PE

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    try:
        db_path = sys.argv[1]
        packer_name = sys.argv[2]
        dir = sys.argv[3]
        output_dir = sys.argv[4]
    except IndexError as e:
        print("usage: packer_identifier db_path packer_name compressed_file_dir output_dir")
        exit(1)

    db = peid.open_signature_db(db_path)

    file_paths = os.scandir(dir)
    found = 0
    for file_path in file_paths:
        if file_path.is_file():
            full_path = os.path.join(dir, file_path.name)
            with open(full_path, "rb") as fp:
                content = fp.read()
                fp.close()
                pe_bytes = zlib.decompress(content)
                pe = PE(data=pe_bytes)
                identified_packer = db.match(pe)
                if identified_packer is not None and len(identified_packer) > 0:
                    if re.findall(packer_name, identified_packer[0], re.IGNORECASE):
                        found += 1
                        print(f"Total found: {found}")
                        fp = open(os.path.join(output_dir, file_path.name), "wb")
                        fp.write(pe_bytes)
                        fp.close()


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
