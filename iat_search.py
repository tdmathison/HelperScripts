# iat_search.py
# Searches the Import Address Table (IAT) of Windows binary files (PE) to find a specified DLL being used
#
# Travis Mathison
#

import pefile
import argparse
import os
import sys
import multiprocessing as mp

def search_file(path, dll):
    try:
        pe = pefile.PE(path)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.lower().decode() == dll.lower():
                return '\"{0}\":{1}'.format(path, entry.dll)
    except pefile.PEFormatError:
        return None

results = []
def collect_result(res):
    global results
    results.append(res)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Search for DLL in PE IAT')
    parser.add_argument('-p', '--path', type=str, required=True, help='The base path to search from')
    parser.add_argument('-e', '--extension', type=str, required=True, help='The extension of files to search')
    parser.add_argument('-dll', type=str, required=True, help='The DLL file to search for')
    args = parser.parse_args()

    pool = mp.Pool(mp.cpu_count())
    file_list = []
    files_seen = 0

    for root, dirs, files in os.walk(args.path):
        for file in files:
            files_seen += 1
            sys.stdout.write("\rIndexing files: %i" % files_seen)
            sys.stdout.flush()
            if file.endswith(args.extension):
                pool.apply_async(search_file, args=(os.path.join(root, file), args.dll), callback=collect_result)

    pool.close()

    print('\n\n{0} eligible files | {1} detections'.format(len(results), sum(x is not None for x in results)))
    print('----------------------------------')
    for result in results:
        if result is not None:
            print(result)
