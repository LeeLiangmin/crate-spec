import os
from os import path
import sys
import hashlib
file_dir = path.dirname(path.abspath(__file__))
os.chdir(file_dir)
args = sys.argv[1:]

src_file_path = "../output/crate-spec-0.2.0.scrate"

with open(src_file_path, "rb") as fp:
    bin = bytearray(fp.read())


with open(src_file_path, "wb") as fp:
    opt = int(args[0])
    if opt == 0:
        bin[200:202] = [10, 20, 30]
        fp.write(bin)
    else:
        bin = bin[:-32]
        bin[400] = 0x52
        data_sha = hashlib.sha256(bin).digest()
        fp.write(bin)
        fp.write(data_sha)

print(f"hack file {src_file_path} done")
