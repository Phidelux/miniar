#!/usr/bin/python3

import argparse
import ctypes
import ctypes.util
import enum
import os
import platform
import sys

libPath = ctypes.util.find_library('archive')

if platform.system == 'Windows':
	libarchive = ctypes.windll.LoadLibrary(libPath)
elif platform.system() == 'Linux' or platform.system() == 'Darwin':
	libarchive = ctypes.cdll.LoadLibrary(libPath)
else:
	sys.exit(1)

def export2python(lib, funcname, restype, argtypes, errcheck=None):
	func = lib.__getattr__(funcname)
	func.restype = restype
	func.argtypes = argtypes

	if errcheck:
	    func.errcheck = errcheck

	globals()[funcname] = func
	return func

# NOTE: It is not necessary to explicitly wrap `struct archive`
#       and `struct archive_entry` by providing ctypes structures, as the
#       members of these structs are never explicitly accessed.
#       Thus, using a void pointer (`ctypes.c_void_p`) is sufficient.

# NOTE: See libarchive/libarchive/archive.h for details
class ArchiveCode(enum.IntEnum):
	ARCHIVE_EOF    = 1   # Found end of archive.
	ARCHIVE_OK     = 0   # Operation was successful.
	ARCHIVE_RETRY  = -10 # Retry might succeed.
	ARCHIVE_WARN   = -20 # Partial success.
	ARCHIVE_FAILED = -25 # Current operation cannot complete.
	ARCHIVE_FATAL  = -30 # No more operations are possible.

# NOTE: See libarchive/libarchive/archive.h for details
class ArchiveFilter(enum.IntEnum):
	ARCHIVE_FILTER_NONE     = 0
	ARCHIVE_FILTER_GZIP     = 1
	ARCHIVE_FILTER_BZIP2    = 2
	ARCHIVE_FILTER_COMPRESS = 3
	ARCHIVE_FILTER_PROGRAM  = 4
	ARCHIVE_FILTER_LZMA     = 5
	ARCHIVE_FILTER_XZ       = 6
	ARCHIVE_FILTER_UU       = 7
	ARCHIVE_FILTER_RPM      = 8
	ARCHIVE_FILTER_LZIP     = 9
	ARCHIVE_FILTER_LRZIP    = 10
	ARCHIVE_FILTER_LZOP     = 11
	ARCHIVE_FILTER_GRZIP    = 12

# NOTE: See libarchive/libarchive/archive.h for details
class ArchiveFormat(enum.IntEnum):
	ARCHIVE_FORMAT_BASE_MASK           = 0xff0000
	ARCHIVE_FORMAT_CPIO                = 0x10000
	ARCHIVE_FORMAT_CPIO_POSIX          = (ARCHIVE_FORMAT_CPIO | 1)
	ARCHIVE_FORMAT_CPIO_BIN_LE         = (ARCHIVE_FORMAT_CPIO | 2)
	ARCHIVE_FORMAT_CPIO_BIN_BE         = (ARCHIVE_FORMAT_CPIO | 3)
	ARCHIVE_FORMAT_CPIO_SVR4_NOCRC     = (ARCHIVE_FORMAT_CPIO | 4)
	ARCHIVE_FORMAT_CPIO_SVR4_CRC       = (ARCHIVE_FORMAT_CPIO | 5)
	ARCHIVE_FORMAT_CPIO_AFIO_LARGE     = (ARCHIVE_FORMAT_CPIO | 6)
	ARCHIVE_FORMAT_SHAR                = 0x20000
	ARCHIVE_FORMAT_SHAR_BASE           = (ARCHIVE_FORMAT_SHAR | 1)
	ARCHIVE_FORMAT_SHAR_DUMP           = (ARCHIVE_FORMAT_SHAR | 2)
	ARCHIVE_FORMAT_TAR                 = 0x30000
	ARCHIVE_FORMAT_TAR_USTAR           = (ARCHIVE_FORMAT_TAR | 1)
	ARCHIVE_FORMAT_TAR_PAX_INTERCHANGE = (ARCHIVE_FORMAT_TAR | 2)
	ARCHIVE_FORMAT_TAR_PAX_RESTRICTED  = (ARCHIVE_FORMAT_TAR | 3)
	ARCHIVE_FORMAT_TAR_GNUTAR          = (ARCHIVE_FORMAT_TAR | 4)
	ARCHIVE_FORMAT_ISO9660             = 0x40000
	ARCHIVE_FORMAT_ISO9660_ROCKRIDGE   = (ARCHIVE_FORMAT_ISO9660 | 1)
	ARCHIVE_FORMAT_ZIP                 = 0x50000
	ARCHIVE_FORMAT_EMPTY               = 0x60000
	ARCHIVE_FORMAT_AR                  = 0x70000
	ARCHIVE_FORMAT_AR_GNU              = (ARCHIVE_FORMAT_AR | 1)
	ARCHIVE_FORMAT_AR_BSD              = (ARCHIVE_FORMAT_AR | 2)
	ARCHIVE_FORMAT_MTREE               = 0x80000
	ARCHIVE_FORMAT_RAW                 = 0x90000
	ARCHIVE_FORMAT_XAR                 = 0xA0000
	ARCHIVE_FORMAT_LHA                 = 0xB0000
	ARCHIVE_FORMAT_CAB                 = 0xC0000
	ARCHIVE_FORMAT_RAR                 = 0xD0000
	ARCHIVE_FORMAT_7ZIP                = 0xE0000

class ArchiveFlags(enum.IntEnum):
	ARCHIVE_EXTRACT_OWNER                  = 0x0001
	ARCHIVE_EXTRACT_PERM                   = 0x0002
	ARCHIVE_EXTRACT_TIME                   = 0x0004
	ARCHIVE_EXTRACT_NO_OVERWRITE           = 0x0008
	ARCHIVE_EXTRACT_UNLINK                 = 0x0010
	ARCHIVE_EXTRACT_ACL                    = 0x0020
	ARCHIVE_EXTRACT_FFLAGS                 = 0x0040
	ARCHIVE_EXTRACT_XATTR                  = 0x0080
	ARCHIVE_EXTRACT_SECURE_SYMLINKS        = 0x0100
	ARCHIVE_EXTRACT_SECURE_NODOTDOT        = 0x0200
	ARCHIVE_EXTRACT_NO_AUTODIR             = 0x0400
	ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER     = 0x0800
	ARCHIVE_EXTRACT_SPARSE                 = 0x1000
	ARCHIVE_EXTRACT_MAC_METADATA           = 0x2000
	ARCHIVE_EXTRACT_NO_HFS_COMPRESSION     = 0x4000
	ARCHIVE_EXTRACT_HFS_COMPRESSION_FORCED = 0x8000
	ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS = 0x10000
	ARCHIVE_EXTRACT_CLEAR_NOCHANGE_FFLAGS  = 0x20000

# NOTE: See libarchive/libarchive/archive_entry.h for details
class ArchiveFiletype(enum.IntEnum):
	AE_IFMT   = 0o170000
	AE_IFREG  = 0o100000
	AE_IFLNK  = 0o120000
	AE_IFSOCK = 0o140000
	AE_IFCHR  = 0o020000
	AE_IFBLK  = 0o060000
	AE_IFDIR  = 0o040000
	AE_IFIFO  = 0o010000

# Introduce type aliases
c_archive_p = ctypes.c_void_p
c_archive_entry_p = ctypes.c_void_p

export2python(libarchive, 'archive_error_string', ctypes.c_char_p, [c_archive_p])

# Error handling function
def __miniar_archive_error(result, func, arguments):
    if result >= 0:
        return result
    elif result == ArchiveCode.ARCHIVE_WARN:
        # TODO: Handle warnings
        return result
    else:
        raise ArchiveError(archive_error_string(arguments[0]).decode(sys.stdout.encoding))

def __miniar_check_null(result, func, arguments):
    if not result:
        raise ArchiveError(func.__name__ + ' returned None')

    return result

# TODO: Handle some errors directly

export2python(libarchive, 'archive_read_new', c_archive_p, [], __miniar_check_null)
export2python(libarchive, 'archive_read_support_filter_all', ctypes.c_int, [c_archive_p], __miniar_archive_error)
export2python(libarchive, 'archive_read_support_format_all', ctypes.c_int, [c_archive_p], __miniar_archive_error)
export2python(libarchive, 'archive_read_support_format_raw', ctypes.c_int, [c_archive_p], __miniar_archive_error)
export2python(libarchive, 'archive_read_open_fd', ctypes.c_int, [c_archive_p, ctypes.c_int, ctypes.c_size_t], __miniar_archive_error)
export2python(libarchive, 'archive_read_open_filename', ctypes.c_int, [c_archive_p, ctypes.c_char_p, ctypes.c_size_t], __miniar_archive_error)
export2python(libarchive, 'archive_read_next_header', ctypes.c_int, [c_archive_p, ctypes.POINTER(c_archive_entry_p)], __miniar_archive_error)
export2python(libarchive, 'archive_read_data_block', ctypes.c_int, [c_archive_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_uint64)], __miniar_archive_error)
export2python(libarchive, 'archive_read_close', ctypes.c_int, [c_archive_p], __miniar_archive_error)
export2python(libarchive, 'archive_read_free', ctypes.c_int, [c_archive_p], __miniar_archive_error)

export2python(libarchive, 'archive_write_disk_new', c_archive_p, [], __miniar_check_null)
export2python(libarchive, 'archive_write_disk_set_options', ctypes.c_int, [c_archive_p, ctypes.c_int], __miniar_archive_error)
export2python(libarchive, 'archive_write_disk_set_standard_lookup', ctypes.c_int, [c_archive_p], __miniar_archive_error)

export2python(libarchive, 'archive_write_new', c_archive_p, [], __miniar_check_null)
export2python(libarchive, 'archive_write_add_filter_gzip', ctypes.c_int, [c_archive_p], __miniar_archive_error)
export2python(libarchive, 'archive_write_set_format_ustar', ctypes.c_int, [c_archive_p], __miniar_archive_error)
export2python(libarchive, 'archive_write_open_fd', ctypes.c_int, [c_archive_p, ctypes.c_int], __miniar_archive_error)
export2python(libarchive, 'archive_write_open_filename', ctypes.c_int, [c_archive_p, ctypes.c_char_p], __miniar_archive_error)
export2python(libarchive, 'archive_write_header', ctypes.c_int, [c_archive_p, c_archive_entry_p], __miniar_archive_error)
export2python(libarchive, 'archive_write_data_block', ctypes.c_ssize_t, [c_archive_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint64], __miniar_archive_error)
export2python(libarchive, 'archive_write_finish_entry', ctypes.c_int, [c_archive_entry_p], __miniar_archive_error)
export2python(libarchive, 'archive_write_close', ctypes.c_int, [c_archive_p], __miniar_archive_error)
export2python(libarchive, 'archive_write_free', ctypes.c_int, [c_archive_p], __miniar_archive_error)

export2python(libarchive, 'archive_entry_pathname', ctypes.c_char_p, [c_archive_entry_p], __miniar_check_null)
export2python(libarchive, 'archive_entry_set_pathname', None, [c_archive_entry_p, ctypes.c_char_p])

class ArchiveError(Exception):
    pass

def miniar_open_read(filepath):
    archive = archive_read_new()

    archive_read_support_filter_all(archive)
    archive_read_support_format_all(archive)

    archive_read_open_filename(archive, filepath.encode('ascii'), 10240)

    return archive

def miniar_open_write(path):
    archive = archive_write_new()

    # TODO: Currently only handling of *.tar.gz files is supported.
    archive_add_filter_gzip(archive)
    archive_write_set_format_ustar(archive)

    archive_write_open_filename(archive, path)

    return archive

def miniar_open_extract(flags = None):
    archive = archive_write_disk_new()

    if not flags:
        flags = ArchiveFlags.ARCHIVE_EXTRACT_TIME | ArchiveFlags.ARCHIVE_EXTRACT_PERM \
            | ArchiveFlags.ARCHIVE_EXTRACT_ACL | ArchiveFlags.ARCHIVE_EXTRACT_FFLAGS \
            | ArchiveFlags.ARCHIVE_EXTRACT_SECURE_NODOTDOT | ArchiveFlags.ARCHIVE_EXTRACT_SPARSE

    archive_write_disk_set_options(archive, flags)
    archive_write_disk_set_standard_lookup(archive)

    return archive

def miniar_close_read(archive):
    if archive:
        archive_read_close(archive)
        archive_read_free(archive)

def miniar_close_write(archive):
    if archive:
        archive_write_close(archive)
        archive_write_free(archive)

def miniar_next(archive):
    entry = ctypes.c_void_p()

    err = archive_read_next_header(archive, ctypes.byref(entry))
    if err == ArchiveCode.ARCHIVE_OK or err == ArchiveCode.ARCHIVE_WARN:
        return entry
    elif err == ArchiveCode.ARCHIVE_EOF:
        return None

def miniar_extract(in_archive, out_archive, dest):
    entry = miniar_next(in_archive)
    while entry:
        path = os.path.join(dest, archive_entry_pathname(entry).decode(sys.stdout.encoding))
        miniar_write_data(in_archive, out_archive, entry, path)
        entry = miniar_next(in_archive)

def miniar_write_data(in_archive, out_archive, entry, dest):
    archive_entry_set_pathname(entry, dest.encode('ascii'))

    archive_write_header(out_archive, entry)

    miniar_copy_data(in_archive, out_archive)

    archive_write_finish_entry(out_archive)

def miniar_copy_data(in_archive, out_archive):
    buffer = ctypes.c_void_p()
    size = ctypes.c_size_t()
    offset = ctypes.c_uint64()

    err = archive_read_data_block(in_archive, ctypes.byref(buffer), ctypes.byref(size), ctypes.byref(offset))
    while err == ArchiveCode.ARCHIVE_OK:
        archive_write_data_block(out_archive, buffer, size, offset)
        err = archive_read_data_block(in_archive, ctypes.byref(buffer), ctypes.byref(size), ctypes.byref(offset))

    if err != ArchiveCode.ARCHIVE_EOF:
        raise ArchiveError("Failed to read archive: {}".format(
                archive_error_string(arguments[0]).decode(sys.stdout.encoding)))


def miniar_list(archive):
    files = []

    entry = miniar_next(archive)
    while entry:
        filepath = archive_entry_pathname(entry)
        files.append(filepath.decode(sys.stdout.encoding))
        entry = miniar_next(archive)

    return files

def main():
    try:
        parser = argparse.ArgumentParser()
        group = parser.add_mutually_exclusive_group()
        group.add_argument("-l", "--list", help="list contents of archive", action="store_true")
        group.add_argument("-p", "--print", help="dump archive contents to stdout", action="store_true")
        group.add_argument("-o", "--outdir", help="Sets the output dir", default='.')
        parser.add_argument("-x", "--extract", help="extract the given archive", action="store_true")
        parser.add_argument("archive", help="archive to be used")
        args = parser.parse_args()

        archivePath = os.path.abspath(args.archive)

        if args.list:
            archive = miniar_open_read(archivePath)
            entries = miniar_list(archive)

            for path in entries:
                print("-> {}".format(path))

            miniar_close_read(archive)
        elif args.extract:
            outputPath = os.path.abspath(args.outdir)

            in_archive = miniar_open_read(archivePath)
            out_archive = miniar_open_extract()
            miniar_extract(in_archive, out_archive, outputPath)
            miniar_close_write(out_archive)
            miniar_close_read(in_archive)
    except ArchiveError as e:
        print("Error: {}".format(e))
    except Exception as e:
        print("Error: {}".format(e))
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        import traceback
        traceback.print_exc(file=sys.stdout)

if __name__ == "__main__":
    main()
