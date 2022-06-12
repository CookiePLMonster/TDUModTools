#!/usr/bin/python3
from contextlib import contextmanager
import os
import struct
import sys

HEADER_SIZE = 52
SECTOR_SIZE = 2048


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

        return (endianness, (version1, version2), total_size, num_resources, hash_prime, (res_offset, res_size), (files_offset, files_size),
                (name_offsets_offset, name_offsets_size), (names_offset, names_size))

    except struct.error as ex:
        raise BadMHPFFileError('Not a valid MHPF file') from ex


def _getResourcesTable(file, endianness, num_resources, res_offset):
    try:
        file.seek(res_offset[0], 0)

        # TODO: Validate table size in strict mode
        return [res for res in struct.iter_unpack(f'{endianness}3I', file.read(12 * num_resources))]
    except struct.error as ex:
        raise BadMHPFFileError('Not a valid MHPF file') from ex


def _getNamesTable(file, endianness, num_resources, names_offset, names_block_offset):
    file.seek(names_offset[0], 0)
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
        file.seek(offset + names_block_offset[0], 0)
        names.append(readString(file))
    return names


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

                f.seek(res[1], 0)
                with open(full_path, 'wb') as out:
                    BUF_SIZE = 64 * 1024 * 1024  # 64MB buffer
                    size_to_read = res[2]
                    while size_to_read > 0:
                        chunk_size = min(size_to_read, BUF_SIZE)
                        out.write(f.read(chunk_size))
                        size_to_read -= chunk_size

            except OSError:
                print(f'Failed to unpack file {name}!', file=sys.stderr)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description="A package tool for unpacking and repacking MHPF (Melbourne House Pack File) .PCK files in Test Drive Unlimited PS2/PSP.")
    subparsers = parser.add_subparsers(required=True, help='sub-command')

    parser_unpack = subparsers.add_parser(
        'unpack', help='Unpack the MPHF archive to a specified directory')
    parser_unpack.add_argument(
        'file', metavar='PCK', type=str, help='path to the PCK file')
    parser_unpack.add_argument('-o', '--output', dest='output_dir',
                               type=str, default='.', help='path to the output directory')
    parser_unpack.set_defaults(func=unpack)

    args = parser.parse_args()

    func = args.func
    args_var = vars(args)
    del args_var['func']

    func(**args_var)
