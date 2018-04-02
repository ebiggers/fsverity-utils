#!/usr/bin/python
"""Sets up a file for fs-verity."""

from __future__ import print_function

import argparse
import binascii
import ctypes
import hashlib
import io
import math
import os
import subprocess
import sys
import tempfile
import zlib

DATA_BLOCK_SIZE = 4096
HASH_BLOCK_SIZE = 4096
FS_VERITY_MAGIC = b'TrueBrew'
FS_VERITY_SALT_SIZE = 8
FS_VERITY_EXT_ELIDE = 0
FS_VERITY_EXT_PATCH = 1
FS_VERITY_ALG_SHA256 = 1
FS_VERITY_ALG_CRC32 = 2


class CRC32Hash(object):
  """hashlib-compatible wrapper for zlib.crc32()."""

  digest_size = 4

  # Big endian, to be compatible with veritysetup --hash=crc32, which uses
  # libgcrypt, which uses big endian CRC-32.
  class Digest(ctypes.BigEndianStructure):
    _fields_ = [('remainder', ctypes.c_uint32)]

  def __init__(self, remainder=0):
    self.remainder = remainder

  def update(self, string):
    self.remainder = zlib.crc32(bytes(string), self.remainder)

  def digest(self):
    digest = CRC32Hash.Digest()
    digest.remainder = self.remainder
    return serialize_struct(digest)

  def hexdigest(self):
    return binascii.hexlify(self.digest()).decode('ascii')

  def copy(self):
    return CRC32Hash(self.remainder)


class HashAlgorithm(object):

  def __init__(self, code, name, digest_size):
    self.code = code
    self.name = name
    self.digest_size = digest_size

  def create(self):
    if self.name == 'crc32':
      return CRC32Hash()
    else:
      return hashlib.new(self.name)


HASH_ALGORITHMS = [
    HashAlgorithm(FS_VERITY_ALG_SHA256, 'sha256', 32),
    HashAlgorithm(FS_VERITY_ALG_CRC32, 'crc32', 4),
]


class fsverity_header(ctypes.LittleEndianStructure):
  _fields_ = [
      ('magic', ctypes.c_char * 8),  #
      ('maj_version', ctypes.c_uint8),
      ('min_version', ctypes.c_uint8),
      ('log_blocksize', ctypes.c_uint8),
      ('log_arity', ctypes.c_uint8),
      ('meta_algorithm', ctypes.c_uint16),
      ('data_algorithm', ctypes.c_uint16),
      ('flags', ctypes.c_uint32),
      ('reserved1', ctypes.c_uint32),
      ('size', ctypes.c_uint64),
      ('auth_blk_offset', ctypes.c_uint8),
      ('extension_count', ctypes.c_uint8),
      ('salt', ctypes.c_char * FS_VERITY_SALT_SIZE),
      ('reserved2', ctypes.c_char * 22)
  ]


class fsverity_extension(ctypes.LittleEndianStructure):
  _fields_ = [
      ('length', ctypes.c_uint16),  #
      ('type', ctypes.c_uint8),
      ('reserved', ctypes.c_char * 5)
  ]


class fsverity_extension_patch(ctypes.LittleEndianStructure):
  _fields_ = [
      ('offset', ctypes.c_uint64),  #
      # followed by variable-length 'databytes'
  ]


class fsverity_extension_elide(ctypes.LittleEndianStructure):
  _fields_ = [
      ('offset', ctypes.c_uint64),  #
      ('length', ctypes.c_uint64)
  ]


class HeaderOffset(ctypes.LittleEndianStructure):
  _fields_ = [('hdr_offset', ctypes.c_uint32)]


def copy_bytes(src, dst, n):
  """Copies 'n' bytes from the 'src' file to the 'dst' file."""
  if n < 0:
    raise ValueError('Negative copy count: {}'.format(n))
  while n > 0:
    buf = src.read(min(n, io.DEFAULT_BUFFER_SIZE))
    if not buf:
      raise EOFError('Unexpected end of src file')
    dst.write(buf)
    n -= len(buf)


def copy(src, dst):
  """Copies from the 'src' file to the 'dst' file until EOF on 'src'."""
  buf = src.read(io.DEFAULT_BUFFER_SIZE)
  while buf:
    dst.write(buf)
    buf = src.read(io.DEFAULT_BUFFER_SIZE)


def pad_to_block_boundary(f):
  """Pads the file with zeroes to data block boundary."""
  f.write(b'\0' * (-f.tell() % DATA_BLOCK_SIZE))


def ilog2(n):
  l = int(math.log(n, 2))
  if n != 1 << l:
    raise ValueError('{} is not a power of 2'.format(n))
  return l


def serialize_struct(struct):
  """Serializes a ctypes.Structure to a byte array."""
  return bytes(ctypes.string_at(ctypes.pointer(struct), ctypes.sizeof(struct)))


def veritysetup(data_filename, tree_filename, salt, algorithm):
  """Built-in Merkle tree generation algorithm."""
  salted_hash = algorithm.create()
  salted_hash.update(salt)
  hashes_per_block = HASH_BLOCK_SIZE // salted_hash.digest_size
  level_blocks = [os.stat(data_filename).st_size // DATA_BLOCK_SIZE]
  while level_blocks[-1] > 1:
    level_blocks.append(
        (level_blocks[-1] + hashes_per_block - 1) // hashes_per_block)
  hash_block_offset = sum(level_blocks) - level_blocks[0]
  with open(data_filename, 'rb') as datafile:
    with open(tree_filename, 'r+b') as hashfile:
      for level, blockcount in enumerate(level_blocks):
        (i, pending) = (0, bytearray())
        for j in range(blockcount):
          h = salted_hash.copy()
          if level == 0:
            datafile.seek(j * DATA_BLOCK_SIZE)
            h.update(datafile.read(DATA_BLOCK_SIZE))
          else:
            hashfile.seek((hash_block_offset + j) * HASH_BLOCK_SIZE)
            h.update(hashfile.read(HASH_BLOCK_SIZE))
          pending += h.digest()
          if level + 1 == len(level_blocks):
            assert len(pending) == salted_hash.digest_size
            return binascii.hexlify(pending).decode('ascii')
          if len(pending) == HASH_BLOCK_SIZE or j + 1 == blockcount:
            pending += b'\0' * (HASH_BLOCK_SIZE - len(pending))
            hashfile.seek((hash_block_offset - level_blocks[level + 1] + i) *
                          HASH_BLOCK_SIZE)
            hashfile.write(pending)
            (i, pending) = (i + 1, bytearray())
        hash_block_offset -= level_blocks[level + 1]


class Extension(object):
  """An fs-verity patch or elide extension."""

  def __init__(self, offset, length):
    self.offset = offset
    self.length = length
    if self.length < self.MIN_LENGTH:
      raise ValueError('length too small (got {}, need >= {})'.format(
          self.length, self.MIN_LENGTH))
    if self.length > self.MAX_LENGTH:
      raise ValueError('length too large (got {}, need <= {})'.format(
          self.length, self.MAX_LENGTH))
    if self.offset < 0:
      raise ValueError('offset cannot be negative (got {})'.format(self.offset))

  def serialize(self):
    type_buf = self._serialize_impl()
    hdr = fsverity_extension()
    pad = -len(type_buf) % 8
    hdr.length = ctypes.sizeof(hdr) + len(type_buf)
    hdr.type = self.TYPE_CODE
    return serialize_struct(hdr) + type_buf + (b'\0' * pad)

  def __str__(self):
    return '{}(offset {}, length {})'.format(self.__class__.__name__,
                                             self.offset, self.length)


class ElideExtension(Extension):
  """An fs-verity elide extension."""

  TYPE_CODE = FS_VERITY_EXT_ELIDE
  MIN_LENGTH = 1
  MAX_LENGTH = (1 << 64) - 1

  def __init__(self, offset, length):
    Extension.__init__(self, offset, length)

  def apply(self, out_file):
    pass

  def _serialize_impl(self):
    ext = fsverity_extension_elide()
    ext.offset = self.offset
    ext.length = self.length
    return serialize_struct(ext)


class PatchExtension(Extension):
  """An fs-verity patch extension."""

  TYPE_CODE = FS_VERITY_EXT_PATCH
  MIN_LENGTH = 1
  MAX_LENGTH = 255

  def __init__(self, offset, data):
    Extension.__init__(self, offset, len(data))
    self.data = data

  def apply(self, dst):
    dst.write(self.data)

  def _serialize_impl(self):
    ext = fsverity_extension_patch()
    ext.offset = self.offset
    return serialize_struct(ext) + self.data


class BadExtensionListError(Exception):
  pass


class FSVerityGenerator(object):
  """Sets up a file for fs-verity."""

  def __init__(self, in_filename, out_filename, salt, algorithm, **kwargs):
    self.in_filename = in_filename
    self.original_size = os.stat(in_filename).st_size
    self.out_filename = out_filename
    self.salt = salt
    self.algorithm = algorithm
    assert len(salt) == FS_VERITY_SALT_SIZE

    self.extensions = kwargs.get('extensions')
    if self.extensions is None:
      self.extensions = []

    self.builtin_veritysetup = kwargs.get('builtin_veritysetup')
    if self.builtin_veritysetup is None:
      self.builtin_veritysetup = False

    self.tmp_filenames = []

    # Patches and elisions must be within the file size and must not overlap.
    self.extensions = sorted(self.extensions, key=lambda ext: ext.offset)
    for i, ext in enumerate(self.extensions):
      ext_end = ext.offset + ext.length
      if ext_end > self.original_size:
        raise BadExtensionListError(
            '{} extends beyond end of file!'.format(ext))
      if i + 1 < len(
          self.extensions) and ext_end > self.extensions[i + 1].offset:
        raise BadExtensionListError('{} overlaps {}!'.format(
            ext, self.extensions[i + 1]))

  def _open_tmpfile(self, mode):
    f = tempfile.NamedTemporaryFile(mode, delete=False)
    self.tmp_filenames.append(f.name)
    return f

  def _delete_tmpfiles(self):
    for filename in self.tmp_filenames:
      os.unlink(filename)

  def _apply_extensions(self, data_filename):
    with open(data_filename, 'rb') as src:
      with self._open_tmpfile('wb') as dst:
        src_pos = 0
        for ext in self.extensions:
          print('Applying {}'.format(ext))
          copy_bytes(src, dst, ext.offset - src_pos)
          ext.apply(dst)
          src_pos = ext.offset + ext.length
          src.seek(src_pos)
        copy(src, dst)
        return dst.name

  def _generate_merkle_tree(self, data_filename):
    """Generates a file's Merkle tree for fs-verity.

    Args:
       data_filename: file for which to generate the tree.  Patches and/or
           elisions may need to be applied on top of it.

    Returns:
        (root hash as hex, name of the file containing the Merkle tree).

    Raises:
        OSError: A problem occurred when executing the 'veritysetup'
            program to generate the Merkle tree.
    """

    # If there are any patch or elide extensions, apply them to a temporary file
    # and use that to build the Merkle tree instead of the original data.
    if self.extensions:
      data_filename = self._apply_extensions(data_filename)

    # Pad to a data block boundary before building the Merkle tree.
    # Note: elisions may result in padding being needed, even if the original
    # file was block-aligned!
    with open(data_filename, 'ab') as f:
      pad_to_block_boundary(f)

    # File to which we'll output the Merkle tree
    with self._open_tmpfile('wb') as f:
      tree_filename = f.name

    if self.builtin_veritysetup:
      root_hash = veritysetup(data_filename, tree_filename, self.salt,
                              self.algorithm)
    else:
      # Delegate to 'veritysetup' to actually build the Merkle tree.
      cmd = [
          'veritysetup',
          'format',
          data_filename,
          tree_filename,
          '--salt=' + binascii.hexlify(self.salt).decode('ascii'),
          '--no-superblock',
          '--hash={}'.format(self.algorithm.name),
          '--data-block-size={}'.format(DATA_BLOCK_SIZE),
          '--hash-block-size={}'.format(HASH_BLOCK_SIZE),
      ]
      print(' '.join(cmd))
      output = subprocess.check_output(cmd, universal_newlines=True)

      # Extract the root hash from veritysetup's output.
      root_hash = None
      for line in output.splitlines():
        if line.startswith('Root hash'):
          root_hash = line.split(':')[1].strip()
          break
      if root_hash is None:
        raise OSError('Root hash not found in veritysetup output!')
    return root_hash, tree_filename

  def _generate_header(self):
    """Generates the fs-verity header."""
    header = fsverity_header()
    assert ctypes.sizeof(header) == 64
    header.magic = FS_VERITY_MAGIC
    header.maj_version = 1
    header.min_version = 0
    header.log_blocksize = ilog2(DATA_BLOCK_SIZE)
    header.log_arity = ilog2(DATA_BLOCK_SIZE / self.algorithm.digest_size)
    header.meta_algorithm = self.algorithm.code
    header.data_algorithm = self.algorithm.code
    header.size = self.original_size
    header.extension_count = len(self.extensions)
    header.salt = self.salt
    return serialize_struct(header)

  def generate(self):
    """Sets up a file for fs-verity.

    The input file will be copied to the output file, then have the fs-verity
    metadata appended to it.

    Returns:
       (fs-verity measurement, Merkle tree root hash), both as hex.

    Raises:
       IOError: Problem reading/writing the files.
    """

    # Copy the input file to the output file.
    with open(self.in_filename, 'rb') as infile:
      with open(self.out_filename, 'wb') as outfile:
        copy(infile, outfile)
        if outfile.tell() != self.original_size:
          raise IOError('{}: size changed!'.format(self.in_filename))

    try:
      # Generate the file's Merkle tree and calculate its root hash.
      (root_hash, tree_filename) = self._generate_merkle_tree(self.out_filename)

      with open(self.out_filename, 'ab') as outfile:

        # Pad to a block boundary and append the Merkle tree.
        pad_to_block_boundary(outfile)
        with open(tree_filename, 'rb') as treefile:
          copy(treefile, outfile)

        # Append the fs-verity header.
        header = self._generate_header()
        outfile.write(header)

        # Append extension items, if any.
        extensions = bytearray()
        for ext in self.extensions:
          extensions += ext.serialize()
        outfile.write(extensions)

        # Finish the output file by writing the header offset field.
        hdr_offset = HeaderOffset()
        hdr_offset.hdr_offset = len(header) + len(extensions) + ctypes.sizeof(
            hdr_offset)
        outfile.write(serialize_struct(hdr_offset))

        # Compute the fs-verity measurement.
        measurement = self.algorithm.create()
        measurement.update(header)
        measurement.update(extensions)
        measurement.update(binascii.unhexlify(root_hash))
        measurement = measurement.hexdigest()
    finally:
      self._delete_tmpfiles()

    return (measurement, root_hash)


def convert_hash_argument(argstring):
  for alg in HASH_ALGORITHMS:
    if alg.name == argstring:
      return alg
  raise argparse.ArgumentTypeError(
      'Unrecognized algorithm: "{}".  Choices are: {}'.format(
          argstring, [alg.name for alg in HASH_ALGORITHMS]))


def convert_salt_argument(argstring):
  try:
    b = binascii.unhexlify(argstring)
    if len(b) != FS_VERITY_SALT_SIZE:
      raise ValueError
    return b
  except (ValueError, TypeError):
    raise argparse.ArgumentTypeError(
        'Must be a 16-character hex string.  (Got "{}")'.format(argstring))


def convert_patch_argument(argstring):
  try:
    (offset, patchfile) = argstring.split(',')
    offset = int(offset)
  except ValueError:
    raise argparse.ArgumentTypeError(
        'Must be formatted as <offset,patchfile>.  (Got "{}")'.format(
            argstring))
  try:
    with open(patchfile, 'rb') as f:
      data = f.read()
    return PatchExtension(int(offset), data)
  except (IOError, ValueError) as e:
    raise argparse.ArgumentTypeError(e)


def convert_elide_argument(argstring):
  try:
    (offset, length) = argstring.split(',')
    offset = int(offset)
    length = int(length)
  except ValueError:
    raise argparse.ArgumentTypeError(
        'Must be formatted as <offset,length>.  (Got "{}")'.format(argstring))
  try:
    return ElideExtension(offset, length)
  except ValueError as e:
    raise argparse.ArgumentTypeError(e)


def parse_args():
  """Parses the command-line arguments."""
  parser = argparse.ArgumentParser(
      description='Sets up a file for fs-verity (file-based integrity)')
  parser.add_argument(
      'in_filename',
      metavar='<input_file>',
      type=str,
      help='Original content input file')
  parser.add_argument(
      'out_filename',
      metavar='<output_file>',
      type=str,
      help='Output file formatted for fs-verity')
  parser.add_argument(
      '--salt',
      metavar='<hex_string>',
      type=convert_salt_argument,
      default='00' * FS_VERITY_SALT_SIZE,
      help='{}-byte salt, given as a {}-character hex string'.format(
          FS_VERITY_SALT_SIZE, FS_VERITY_SALT_SIZE * 2))
  parser.add_argument(
      '--hash',
      type=convert_hash_argument,
      default='sha256',
      help="""Hash algorithm to use.  Available algorithms: {}.
            Default is sha256.""".format([alg.name for alg in HASH_ALGORITHMS]))
  parser.add_argument(
      '--patch',
      metavar='<offset,patchfile>',
      type=convert_patch_argument,
      action='append',
      dest='extensions',
      help="""Add a patch extension (not recommended).  Data in the region
      beginning at <offset> in the original file and continuing for
      filesize(<patchfile>) bytes will be replaced with the contents of
      <patchfile> for verification purposes, but reads will return the original
      data.""")
  parser.add_argument(
      '--elide',
      metavar='<offset,length>',
      type=convert_elide_argument,
      action='append',
      dest='extensions',
      help="""Add an elide extension (not recommended).  Data in the region
      beginning at <offset> in the original file and continuing for <length>
      bytes will not be verified.""")
  parser.add_argument(
      '--builtin-veritysetup',
      action='store_const',
      const=True,
      help="""Use the built-in Merkle tree generation algorithm rather than
      invoking the external veritysetup program.  They should produce the same
      result.""")
  return parser.parse_args()


def main():
  args = parse_args()
  try:
    generator = FSVerityGenerator(
        args.in_filename,
        args.out_filename,
        args.salt,
        args.hash,
        extensions=args.extensions,
        builtin_veritysetup=args.builtin_veritysetup)
  except BadExtensionListError as e:
    sys.stderr.write('ERROR: {}\n'.format(e))
    sys.exit(1)

  (measurement, root_hash) = generator.generate()

  print('Merkle root hash: {}'.format(root_hash))
  print('fs-verity measurement: {}'.format(measurement))


if __name__ == '__main__':
  main()
