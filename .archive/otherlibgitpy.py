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


def index_entry_properties_from_filepath_and_hash(path, sha1hash=None):
    st = os.stat(path)
    path_enc = path.encode()
    # Calculate the time variables
    (ctime_ns, ctime), (mtime_ns, mtime) = modf(st.st_ctime), modf(st.st_mtime)
    named_tuple_defaultdict = {'ctime_s': ctime, 'ctime_n': ctime_ns,
                               'mtime_s': mtime, 'mtime_n': mtime_ns,
                               'dev': st.st_dev, 'ino': st.st_ino,
                               'mode': st.st_mode, 'uid': st.st_uid,
                               'gid': st.st_gid, 'size': st.st_size,
                               'sha1': sha1hash, 'flags': None,
                               'path': file_path}
    file_index_entry = IndexEntry(**named_tuple_defaultdict)
    return file_index_entry


def add_blobs(filepaths):
    """
    Create hashes of blobs to be added to the index given filepaths.

    Returns list containing tuples - (blob hashe, filepath)
    """
    filepaths_with_data = []
    for filepath in filepaths:
        data_string = read_file(filepath)
        filepaths_with_data.append((data_string, filepath))
    hashes_with_filepaths = [(hash_object(data, 'blob'), each_filepath) for (data, each_filepath) in filepaths_with_data]
    return hashes_with_filepaths


def update_index(hashes_with_paths):
    """
    Updates index given the list of tuples containing (blob hash, filepath)

    Create index entry with default value as None for file properties
    except the sha1hash and filepath.

    Returns nothing
    """
    entries = []
    for (sha1hash, file_path) in hashes_with_paths:
        named_tuple_defaultdict = {'ctime_s': None, 'ctime_n': None,
                                   'mtime_s': None, 'mtime_n': None,
                                   'dev': None, 'ino': None,
                                   'mode': None, 'uid': None,
                                   'gid': None, 'size': None,
                                   'sha1': sha1hash, 'flags': None,
                                   'path': file_path}
        new_file_index = IndexEntry(**named_tuple_defaultdict)
        entries.append(new_file_index)
    # breakpoint()
    # Write to the index
    create_index(entries)
    return


def test_index_functions():
    """
    Checking to see if the index related functions work
    """

    # Adding lol.txt
    file1 = "lol.txt"

    # # Commented out - Manual way
    # data_file1 = read_file(file1)
    # data_file1_sha1hash = hash_object(data_file1, "blob", write=True)

    # Adding test/test.txt
    file2 = "test/test.txt"

    # # Commented out - Manual way
    # data_file2 = read_file(file2)
    # data_file2_sha1hash = hash_object(data_file2, "blob", write=True)

    ## Simplified way ##

    # Adding files using add_blobs
    filepaths_list1 = [file1]
    hash_with_filepath1 = add_blobs(filepaths_list1)
    update_index(hash_with_filepath1)

    breakpoint()

    filepaths_list2 = [file2]
    hash_with_filepath2 = add_blobs(filepaths_list2)
    update_index(hash_with_filepath2)

    breakpoint()

    all_filepaths_list = [file1, file2]
    all_hash_with_filepaths = add_blobs(all_filepaths_list)
    update_index(all_hash_with_filepaths)

    breakpoint()
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
