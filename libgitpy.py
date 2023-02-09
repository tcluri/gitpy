import sys

import hashlib
import zlib
import os
import stat
from struct import pack
import struct
from math import modf, ceil

# Util module imports
from util import read_file, write_file

# Create the IndexEntry namedtuple from collections module
# to store the file properties
import collections
# Data for one entry in the git index (.git/index)
IndexEntry = collections.namedtuple('IndexEntry', [
    'ctime_s', 'ctime_n', 'mtime_s', 'mtime_n', 'dev', 'ino', 'mode', 'uid',
    'gid', 'size', 'sha1', 'flags', 'path',
])


# Creating and write hash object to file
def hash_object(data, obj_type, write=True):
    # Create header string and assign blob/tree/commit
    header_bytestring = '{} {}'.format(obj_type, len(data)).encode()
    full_data_in_bytes = header_bytestring + b'\0'+ data
    # Calculating hash digest and hash hex digest
    obj_sha1_hex_hash = hashlib.sha1(full_data_in_bytes).hexdigest()
    # obj_sha1_hash = hashlib.sha1(full_data_in_bytes).digest()
    # Write full data to the sha1 hash hex path
    if write:
        path = os.path.join('.git', 'objects', obj_sha1_hex_hash[:2], obj_sha1_hex_hash[2:])
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            write_file(path, zlib.compress(full_data_in_bytes))
    # Return object obj_sha1_hex_hash digest & obj_sha1_hash digest
    return obj_sha1_hex_hash



def read_index():
    """
    Reads index binary file and return entries currently present in
    the index file.

    Returns list of IndexEntry-ies
    """
    entries = []
    try:
        data = read_file(os.path.join('.git', 'index'))
    except FileNotFoundError:
        return entries
    # Unpacking index data
    digest = hashlib.sha1(data[:-20]).digest()
    signature, version, num_entries = struct.unpack('!4sLL', data[:12])
    # Entry data
    entry_data = data[12:-20]
    # Unpacking depending on the properties of entries in the
    # index binary
    i = 0
    while i + 62 < len(entry_data):
        fields_end = i + 62
        fields = struct.unpack('!LLLLLLLLLL20sH',
                               entry_data[i:fields_end])
        path_end = entry_data.index(b'\0', fields_end)
        path = entry_data[fields_end:path_end]
        entry = IndexEntry(*(fields + (path.decode(),)))
        entries.append(entry)
        entry_len = ((62 + len(path) + 8) // 8) * 8
        i += entry_len
    return entries


def create_index(entries):
    """
    Creating the index(sorted by filepaths) given the current
    entries list containing IndexEntry items.
    """
    # pack(format{fstring}, var1, var2)  => 'I' is unsigned int
    VERSION = 2
    header = b''.join([b'DIRC',                  # 4-byte signature
                      pack('>I', VERSION),       # 4-byte version number
                      pack('>I', len(entries))   # (len(entries))# 32-bit number of entries
                       ])
    with open(os.path.join('.git', 'index'), 'wb') as index_file:
        index_file.write(header)
        # Iterate over each entry and write to index - sorted filenames
        for entry in sorted(entries, key=lambda e: e.path):
            index_file.write(entry_bytes(entry))


from binascii import unhexlify


def entry_bytes(entry):
    """
    Get properties of file path with bit-packing in bytes

    Returns byte string with the information of the
    file properties - creation time, modified time,
    st_dev, ino, file mode, uid, gid, size, sha1 digest(unhexlify-ed),
    bit packed properties -- length of encoded path string, padding
    encdoded path
    """
    # Write each entry body to the index file
    path = entry.path
    st = os.stat(path)             # Stat on file
    path_enc = path.encode()       # Convert path to bytes

    # Calculate the time variables
    (ctime_ns, ctime), (mtime_ns, mtime) = modf(st.st_ctime), modf(st.st_mtime)
    return b''.join([
        pack('>II', round(ctime), round(ctime_ns * 10e6)),
        pack('>II', round(mtime), round(mtime_ns * 10e6)),
        pack('>III', st.st_dev, st.st_ino, st.st_mode),
        pack('>III', st.st_uid, st.st_gid, st.st_size),
        unhexlify(entry.sha1),
        pack('>H', 0 << 15 | 0 << 14 | 0 << 12 | len(path_enc) if len(path_enc) < 0xFFF else 0xFFF),
        pack(f'{ceil((len(path_enc)) / 8) * 8}sxx', path_enc)       # pad to 8 bytes
    ])


def add_git_objects(filepaths):
    """
    Create hashes of blobs to be added to the index given filepaths.

    Returns list containing tuples - (blob hashe, filepath)
    """
    filepaths_with_data = []
    for filepath in filepaths:
        # Classify the filepath
        fpath_mode, fpath_gitclass, fpath_size = classify(filepath)
        # If it is a file and not a folder
        if fpath_gitclass == "blob":
            data_string = read_file(filepath)
        # # TODO If there is folder that needs to be added use else and
        # # some more conditionals to use it
        # else:
        #     data_string = ''
        filepaths_with_data.append((data_string, filepath, fpath_mode, fpath_gitclass, fpath_size))

    # Get hashes with filepaths and trees
    hashes_with_filepaths = []
    for (data, each_filepath, fp_mode, fp_gitclass, fp_size) in filepaths_with_data:
        hashes_with_filepaths.append((hash_object(data, fp_gitclass), each_filepath))

        # TODO
        # if fp_gitclass == "tree":
        #     hashes_with_filepaths.append(("tree", each_filepath))
        # else:
        #     hashes_with_filepaths.append((hash_object(data, fp_gitclass), each_filepath))

    # Get the trees for the filepaths as well
    hashes_with_files_and_folders = sorted_trees_with_files(hashes_with_filepaths)
    return hashes_with_files_and_folders


def find_parent_folders(a_folder_path):
    # Find root(.git/) folder for project
    a_folder_path = os.path.abspath(a_folder_path)
    rel_path_from_git_root = a_folder_path.replace(find_git_root(a_folder_path), '').lstrip('/')
    # print("Relative path from git root:", rel_path_from_git_root)
    # Split the filepath into folders
    filepath_folders = rel_path_from_git_root.split('/')
    # print("Folders path:", filepath_folders)

    filepath_folders_len = len(filepath_folders)
    parent_folders_and_subfolders = []
    while filepath_folders:
        if filepath_folders_len == 1:
            parent_folders_and_subfolders.append(filepath_folders[0])
            # filepath_folders = filepath_folders[:-1]
            break
        else:
            parent_folders_and_subfolders.append('/'.join(filepath_folders))
        filepath_folders = filepath_folders[:-1]
    return parent_folders_and_subfolders


def find_git_root(test, dirs=(".git",), default=None):
    import os
    prev, test = None, os.path.abspath(test)
    while prev != test:
        if any(os.path.isdir(os.path.join(test, d)) for d in dirs):
            return test
        prev, test = test, os.path.abspath(os.path.join(test, os.pardir))
    return default


def sorted_trees_with_files(path_blobs_list):
    # Get all the subfolders of the hashes_with_paths
    tree_folders = []
    for each_path_blob in path_blobs_list:
        # Find filepaths and their parent folders
        parent_folders = find_parent_folders(each_path_blob[1])
        for each_parent_folder in parent_folders:
            if each_parent_folder != each_path_blob[1]:
                tree_folders.append(('tree', each_parent_folder))
            else:
                tree_folders.append(each_path_blob)
    sorted_tree_folders = sorted(list(set(tree_folders)), key= lambda x : x[1])
    return sorted_tree_folders


def exists_in_hash_with_filepath(inp_str, hash_with_filepath_list):
    for each_hash_with_filepath in hash_with_filepath_list:
        if each_hash_with_filepath[1] == inp_str:
            return True
    return False


def create_nested_trees(hash_with_tree_and_blobs):
    # Separate trees from non-trees
    tree_folders = [tree_with_path for tree_with_path in hash_with_tree_and_blobs if tree_with_path[0] == "tree"]
    blob_files = [blob_with_path for blob_with_path in hash_with_tree_and_blobs if blob_with_path[0] != "tree"]
    # print("Tree folders:",tree_folders)
    # print("Blob files:", blob_files)

    blob_hierarchy = dict()
    tree_levels = []
    for each_tree_folder in tree_folders:
        each_tree_folder_unit = each_tree_folder[1] + '/'
        tree_levels.append(each_tree_folder_unit)
    # print("Tree levels:", tree_levels)

    # Create tree hierarchy in the blob_hierarchy
    for each_tree_level in tree_levels:
        if each_tree_level[:-1] in blob_hierarchy:
            for each_blob_or_tree in hash_with_tree_and_blobs:
                if exists_in_hash_with_filepath(each_blob_or_tree[1], blob_hierarchy[each_tree_level[:-1]]):
                    continue
        else:
            tree_level_files_folders = []
            current_tree_level = each_tree_level
            current_tree_levels_len = len(each_tree_level.split('/'))
            for each_blob_or_tree in hash_with_tree_and_blobs:
                tree_folder = each_blob_or_tree[1]
                tree_folder_split_len = len((tree_folder+'/').split('/'))
                if current_tree_level in tree_folder and tree_folder_split_len == current_tree_levels_len+1:
                    tree_level_files_folders.append(each_blob_or_tree)
            # Add just the one folder above and its files
            blob_hierarchy[each_tree_level[:-1]] = tree_level_files_folders
    # print("Blob hierarchy after adding trees:")
    # print(blob_hierarchy)
    blob_files_at_root = [each_blob_file for each_blob_file in hash_with_tree_and_blobs if '/' not in each_blob_file[1]]
    blob_hierarchy['./'] = []
    for blob_file_at_root in blob_files_at_root:
        blob_hierarchy['./'].append(blob_file_at_root)
    return blob_hierarchy


def update_index(hashes_with_paths):
    """
    Updates index given the list of tuples containing (blob hash, filepath)

    Create index entry with default value as None for file properties
    except the sha1hash and filepath.

    Returns nothing
    """

    strees_with_files = sorted_trees_with_files(hashes_with_paths)
    entries = []
    for (sha1hash, file_path) in hashes_with_paths:
        # If it is a filepath with no
        named_tuple_defaultdict = {'ctime_s': None, 'ctime_n': None,
                                   'mtime_s': None, 'mtime_n': None,
                                   'dev': None, 'ino': None,
                                   'mode': None, 'uid': None,
                                   'gid': None, 'size': None,
                                   'sha1': sha1hash, 'flags': None,
                                   'path': file_path}
        new_file_index = IndexEntry(**named_tuple_defaultdict)
        entries.append(new_file_index)
    # Write to the index
    create_index(entries)
    return


def test_index_functions():
    """
    Checking to see if the index related functions work
    """

    # Adding hello.txt blob
    file1 = "hello.txt"
    # Adding another blob
    file2 = "test/this/now/testthisnow.txt"

    # Testing files within folders
    file3 = "test/this.txt"

    # Writing files to .git/objects
    filepaths_list = [file1, file2, file3]
    files_with_hashes_and_folders = add_git_objects(filepaths_list)
    print("Hashes of blobs(files) and folders:\n", files_with_hashes_and_folders)
    # TODO Writing to index file after adding

    # update_index(hash_with_filepath1)

    return

def classify(path):
    """
    Return git classification of a path (as both mode,
    100644/100755 etc, and git object type, i.e., blob vs tree).
    Also throw in st_size field since we want it for file blobs.
    """
    # We need the X bit of regular files for the mode, so
    # might as well just use lstat rather than os.isdir().
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        gitclass = 'blob'
        mode = '120000'
    elif stat.S_ISDIR(st.st_mode):
        gitclass = 'tree'
        mode = '40000' # note: no leading 0!
    elif stat.S_ISREG(st.st_mode):
        # 100755 if any execute permission bit set, else 100644
        gitclass = 'blob'
        mode = '100755' if (st.st_mode & 0o111) != 0 else '100644'
    else:
        raise ValueError('un-git-able file system entity %s' % fullpath)
    return mode, gitclass, st.st_size

def write_tree():
    # Write to tree object and return a sha1 hash of the tree object
    tree_entries = []
    for entry in read_index():
        mode_path = '{:o} {}'.format(entry.mode, entry.path).encode()
        tree_entry = mode_path + b'\0' + entry.sha1
        tree_entries.append(tree_entry)
    return hash_object(b''.join(tree_entries), 'tree')




# Argument parsing in the main command
import argparse

argparser = argparse.ArgumentParser(description="Gitpy content tracker")
argsubparsers = argparser.add_subparsers(title="Command", dest="command")
argsubparsers.required = True


def cmd_hash_object(args):
    with open(args.path, "rb") as fd:
        sha = hash_object(fd, args.type.encode(), write=True)
        print(sha)

def main(argv=sys.argv[1:]):
    args = argparser.parse_args(argv)
    # Command list to call the right function
    if args.command == "hash-object"        : cmd_hash_object(args)
