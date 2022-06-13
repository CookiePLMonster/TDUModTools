#!/usr/bin/python3
from collections import namedtuple
from contextlib import contextmanager
import os
import struct
import sys

HEADER_SIZE = 52
SECTOR_SIZE = 2048
DEFAULT_HASH_PRIME = 31


class BadMHPFFileError(ValueError):
    pass


@contextmanager
def _fopen(file, *args, **kwargs):
    if isinstance(file, (str, bytes, os.PathLike)):
        with open(file, *args, **kwargs) as f:
            yield f
    elif hasattr(file, 'read') or hasattr(file, 'write'):
        yield file
    else:
        raise TypeError('file must be a str or bytes object, or a file')


def _isHidden(file_path):
    if os.name == 'nt':
        import stat
        return bool(os.stat(file_path).st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)
    return file_path.startswith('.')


def _parseMHPFHeader(file):
    # Verify validity and endianness from the magic
    try:
        magic = struct.unpack('<4s', file.read(4))[0]
        if magic != b'MHPF' and magic != b'FPHM':
            raise BadMHPFFileError(f'Not a valid MHPF file ({magic!r})')

        endianness = '<' if magic == b'MHPF' else '>'
        (version1, version2, total_size, num_resources, hash_prime, res_offset, res_size, files_offset, files_size, name_offsets_offset,
         name_offsets_size, names_offset, names_size) = struct.unpack(f'{endianness}HHIII2I2I2I2I', file.read(HEADER_SIZE - 4))

        # Total size of the file must match total_size
        file.seek(0, 2)
        actual_size = file.tell()
        file.seek(HEADER_SIZE, 0)
        if total_size != actual_size:
            raise BadMHPFFileError('Not a valid MHPF file')

        TableEntry = namedtuple('TableEntry', ['offset', 'size'])
        return (endianness, (version1, version2), total_size, num_resources, hash_prime, TableEntry(res_offset, res_size), TableEntry(files_offset, files_size),
                TableEntry(name_offsets_offset, name_offsets_size), TableEntry(names_offset, names_size))

    except struct.error as ex:
        raise BadMHPFFileError('Not a valid MHPF file') from ex


def _getResourcesTable(file, endianness, num_resources, res_table_attr):
    try:
        file.seek(res_table_attr.offset, 0)

        # TODO: Validate table size in strict mode
        ResEntry = namedtuple('ResEntry', ['hash', 'offset', 'size'])
        return [ResEntry(*res) for res in struct.iter_unpack(f'{endianness}3I', file.read(12 * num_resources))]
    except struct.error as ex:
        raise BadMHPFFileError('Not a valid MHPF file') from ex


def _getNamesTable(file, endianness, num_resources, names_table_attr, names_block_attr):
    file.seek(names_table_attr.offset, 0)
    # TODO: Validate table size in strict mode
    name_offsets = [res[0] for res in struct.iter_unpack(
        f'{endianness}I', file.read(4 * num_resources))]

    def readString(file):
        name = bytearray()
        while True:
            ch = file.read(1)
            if ch == b'' or ch == b'\0':
                return name.decode('ascii')
            name.extend(ch)

    names = []
    for offset in name_offsets:
        file.seek(offset + names_block_attr.offset, 0)
        names.append(readString(file))
    return names


def _gatherFiles(directory, hash_prime):
    FileEntry = namedtuple('FileEntry', ['path', 'name', 'hash', 'size'])

    result = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if _isHidden(file_path):
                continue

            game_path = os.path.normpath(os.path.relpath(file_path, directory)).replace(
                '\\', '/').lower().encode('ascii')
            result.append(FileEntry(path=file_path, size=os.stat(
                file_path).st_size, name=game_path, hash=pathHash(game_path, hash_prime)))

    # Sort by hash already to return a properly sorted list
    result.sort(key=lambda x: x.hash)
    return result


def unpack(file, output_dir='.'):
    with _fopen(file, 'rb') as f:

        # Read and parse the file header
        (endianness, _, _, num_resources, _, res_table, files_table,
         name_offsets_table, names_block_table) = _parseMHPFHeader(f)

        # Read the resources table and names
        resources = _getResourcesTable(f, endianness, num_resources, res_table)
        names = _getNamesTable(f, endianness, num_resources,
                               name_offsets_table, names_block_table)

        # Only now extract the files
        for res, name in zip(resources, names):
            try:
                print(f'Unpacking {name}...')

                # Keep the name in uppercase so it matches the files on disc
                full_path = os.path.join(output_dir, name.upper())
                os.makedirs(os.path.dirname(full_path), exist_ok=True)

                f.seek(res.offset, 0)
                with open(full_path, 'wb') as out:
                    BUF_SIZE = 64 * 1024 * 1024  # 64MB buffer
                    size_to_read = res.size
                    while size_to_read > 0:
                        chunk_size = min(size_to_read, BUF_SIZE)
                        out.write(f.read(chunk_size))
                        size_to_read -= chunk_size

            except OSError:
                print(f'Failed to unpack file {name}!', file=sys.stderr)


def pack(directory, output, *, hash_prime=DEFAULT_HASH_PRIME, big_endian=False):
    if not os.path.isdir(directory):
        raise ValueError(f'{directory} does not exist')

    files = _gatherFiles(directory, hash_prime)
    endianness = '<' if not big_endian else '>'
    TableEntry = namedtuple('TableEntry', ['offset', 'size'])

    # Start building the internal structures, all at once
    def alignToSector(offset):
        return (offset + SECTOR_SIZE - 1) & ~(SECTOR_SIZE - 1)

    # res_table and files_table should be aligned to SECTOR_SIZE, name_offsets_table and names_table don't have to be
    res_table = TableEntry(offset=alignToSector(
        HEADER_SIZE), size=12*len(files))

    resources = bytearray()
    name_offsets = bytearray()
    names = bytearray()
    cur_files_offset = alignToSector(res_table.offset + res_table.size)
    files_size = 0

    for file in files:
        resources.extend(struct.pack(
            f'{endianness}3I', file.hash, cur_files_offset, file.size))
        name_offsets.extend(struct.pack(f'{endianness}I', len(names)))
        names.extend(file.name + b'\0')

        size_aligned = alignToSector(file.size)
        files_size += size_aligned
        cur_files_offset += size_aligned

    files_table = TableEntry(offset=alignToSector(
        res_table.offset + res_table.size), size=files_size)
    name_offsets_table = TableEntry(
        offset=files_table.offset + files_table.size, size=4*len(files))
    names_table = TableEntry(
        offset=name_offsets_table.offset + name_offsets_table.size, size=len(names))

    with _fopen(output, 'wb') as f:

        # Prepare the header
        total_size = alignToSector(HEADER_SIZE) + alignToSector(res_table.size) + alignToSector(
            files_table.size) + name_offsets_table.size + names_table.size
        f.write(struct.pack(f'{endianness}4sHHIII2I2I2I2I', b'MHPF' if not big_endian else b'FPHM', 1, 0,
                            total_size, len(files), hash_prime,
                            res_table.offset, res_table.size, files_table.offset, files_table.size,
                            name_offsets_table.offset, name_offsets_table.size, names_table.offset, names_table.size).ljust(alignToSector(HEADER_SIZE), b'\x00'))

        f.write(resources.ljust(alignToSector(res_table.size), b'\x00'))

        for file in files:
            print(f'Packing {file.name.decode("ascii")}...')
            with open(file.path, 'rb') as in_file:
                BUF_SIZE = 64 * 1024 * 1024  # 64MB buffer
                size_to_read = file.size
                while size_to_read > 0:
                    chunk_size = alignToSector(min(size_to_read, BUF_SIZE))
                    f.write(in_file.read(chunk_size).ljust(
                        chunk_size, b'\x00'))
                    size_to_read -= chunk_size

        f.write(name_offsets)
        f.write(names)


def pathHash(path, prime=DEFAULT_HASH_PRIME):
    result = 0
    separator = True
    for c in path:
        if c == '/' or c == '\\':
            if separator:
                continue
            c = '/'
            separator = True
        else:
            separator = False
        result = (result * prime) + ord(chr(c).lower())
    return result & 0xffffffff


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description="A package tool for unpacking and repacking MHPF (Melbourne House Pack File) .PCK files in Test Drive Unlimited PS2/PSP.")
    subparsers = parser.add_subparsers(required=True, help='sub-command')

    parser_unpack = subparsers.add_parser(
        'unpack', help='Unpack the MPHF archive to a specified directory')
    parser_unpack.add_argument(
        'file', metavar='PCK', type=str, help='path to the input PCK file')
    parser_unpack.add_argument('-o', '--output', dest='output_dir',
                               type=str, default='.', help='path to the target directory')
    parser_unpack.set_defaults(func=unpack)

    parser_pack = subparsers.add_parser(
        'pack', help='Create a MHPF archive from the files from a specified directory')
    parser_pack.add_argument('directory', metavar='DIR',
                             type=str, help='path to the input directory')
    parser_pack.add_argument('-o', '--output', dest='output',
                             type=str, help='path to the PCK file to create')
    parser_pack.add_argument('-hp', '--hash-prime', dest='hash_prime', type=int,
                             default=DEFAULT_HASH_PRIME, help='a custom prime for file name hashes')
    parser_pack.add_argument('-be', '--big-endian', dest='big_endian', action='store_true',
                             help='build a big endian archive (do NOT use for TDU, currently not known if big endian archives were ever used)')
    parser_pack.set_defaults(func=pack)

    arguments = parser.parse_args()
    func = arguments.func

    # for pack, unspecified output directory should be set to a file of the name of the input directory
    if func is pack:
        if arguments.output is None:
            arguments.output = os.path.abspath(arguments.directory + '.PCK')

    args_var = vars(arguments)
    del args_var['func']

    func(**args_var)
