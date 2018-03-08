#!/usr/bin/python

import argparse
import binascii
import os
import shutil
import subprocess
import sys
import tempfile
from ctypes import *

class FSVHeader(Structure):
  _fields_ = [('magic', c_uint8 * 8),
              ('maj_version', c_uint8),
              ('min_version', c_uint8),
              ('log_blocksize', c_uint8),
	      ('log_arity', c_uint8),
	      ('meta_algorithm', c_uint16),
	      ('data_algorithm', c_uint16),
	      ('reserved1', c_uint32),
              ('size', c_uint64),
              ('auth_blk_offset', c_uint8),
              ('extension_count', c_uint8),
              ('salt', c_char * 8),
              ('reserved2', c_char * 22)]

HEADER_SIZE = 64

class FSVExt(Structure):
   _fields_ = [('length', c_uint16),
               ('type', c_uint8),
               ('reserved', c_char * 5)]

class PatchExt(Structure):
  _fields_ = [('offset', c_uint64),
              ('length', c_uint8),
              ('reserved', c_char * 7)]
# Append databytes at the end of the buffer this gets serialized into

class ElideExt(Structure):
  _fields_ = [('offset', c_uint64),
              ('length', c_uint64)]
    
def parse_args():
  parser = argparse.ArgumentParser(description='Build file-based integrity metadata')
  parser.add_argument('--salt', metavar='<hex_string>', type=binascii.unhexlify,
                      help='Hex string, e.g. 01ab')
  parser.add_argument('--tree-file', metavar='<filename>', type=str,
                      help='Filename for tree file (optional)')
  parser.add_argument('input_file', metavar='<file>', type=str,
                      help='Original content input file')
  parser.add_argument('output_file', metavar='<file>', type=str,
                      help='Output file formatted for fs-verity')
  parser.add_argument('--patch_file', metavar='<file>', type=str,
                      help='File containing patch content')
  parser.add_argument('--patch_offset', metavar='<offset>', type=str,
                      help='Offset to which to apply patch')
  parser.add_argument('--elide_offset', metavar='<offset>', type=str,
                      help='Offset of segment to elide')
  parser.add_argument('--elide_length', metavar='<length>', type=str,
                      help='Length of segment to elide')
  return parser.parse_args()

def generate_merkle_tree(args, elided_file):
  if args.tree_file is not None:
    tree_file_name = args.tree_file
  else:
    tree_file = tempfile.NamedTemporaryFile()
    tree_file_name = tree_file.name
    tree_file.close()
  if elided_file is not None:
    file_to_verity = elided_file.name
  else:
    file_to_verity = args.output_file
  cmd = ['veritysetup', 'format', file_to_verity, tree_file_name, '-s', binascii.hexlify(args.salt), '--no-superblock']
  print ' '.join(cmd)
  output = subprocess.check_output(cmd)
  root_hash = ''
  for line in output.split('\n'):
    if line.startswith('Root hash'):
      root_hash = line.split(':')[1].strip()
      break
  else:
    sys.exit('FATAL: root hash is not found')
  with file(tree_file_name, 'r') as tree_file:
    tree_file.seek(0, os.SEEK_SET)
    merkle_tree = tree_file.read()
  return root_hash, merkle_tree

def copy_src_to_dst(args):
  with file(args.output_file, 'w') as dst:
    with file (args.input_file, 'r') as src:
      shutil.copyfileobj(src, dst)

def pad_dst(args):
  with file (args.output_file, 'a') as dst:
    dst.write('\0' * ((4096 - dst.tell()) % 4096))

def append_merkle_tree_to_dst(args, tree):
  with file (args.output_file, 'a') as dst:
    dst.write(tree)

def append_header_to_dst(args, header):
  with file (args.output_file, 'a') as dst:
    dst.write(string_at(pointer(header), sizeof(header)))

class HeaderOffset(Structure):
  _fields_ = [('hdr_offset', c_uint32)]
  
def append_header_reverse_offset_to_dst(args, extensions):
  hdr_offset = HeaderOffset()
  hdr_offset.hdr_offset = HEADER_SIZE + len(extensions) + sizeof(hdr_offset)
  with file (args.output_file, 'a') as dst:
    dst.write(string_at(pointer(hdr_offset), sizeof(hdr_offset)))

def append_extensions_to_dst(args, extensions):
  with file (args.output_file, 'a') as dst:
    dst.write(extensions)

def fill_header_struct(args):
  statinfo = os.stat(args.input_file)
  header = FSVHeader()
  assert sizeof(header) == HEADER_SIZE
  memset(addressof(header), 0, sizeof(header))
  memmove(addressof(header) + FSVHeader.magic.offset, b'TrueBrew', 8)
  header.maj_version = 1
  header.min_version = 0
  header.log_blocksize = 12
  header.log_arity = 7
  header.meta_algorithm = 1  # sha256
  header.data_algorithm = 1  # sha256
  header.reserved1 = 0
  header.size = statinfo.st_size
  header.auth_blk_offset = 0
  header.extension_count = 0
  if args.patch_file is not None and args.patch_offset is not None:
    header.extension_count += 1
  header.salt = args.salt
  return header

def apply_patch(args):
  if args.patch_file is not None and args.patch_offset is not None:
    statinfo = os.stat(args.patch_file)
    patch_file_size = statinfo.st_size
    if patch_file_size > 256:
      print "Invalid patch file size; must be <= 256 bytes: [", patch_file_size, "]"
      return None
    statinfo = os.stat(args.output_file)
    if statinfo.st_size < (int(args.patch_offset) + patch_file_size):
      print "Invalid output file size for patch offset and size"
      return None
    with file (args.patch_file, 'r') as patch_file:
      patch_buf = ""
      original_content = ""
      with file (args.output_file, 'r') as dst:
        dst.seek(int(args.patch_offset), os.SEEK_SET)
        original_content = dst.read(patch_file_size)
        dst.seek(int(args.patch_offset), os.SEEK_SET)
        patch_buf = patch_file.read(patch_file_size)
        dst.close()
      with file (args.output_file, 'w') as dst:
        dst.seek(int(args.patch_offset), os.SEEK_SET)
        dst.write(patch_buf)
        dst.close()
      return original_content
  else:
    return None
                 
def serialize_extensions(args):
  patch_ext_buf = None
  elide_ext_buf = None
  if args.patch_file is not None and args.patch_offset is not None:
    statinfo = os.stat(args.patch_file)
    patch_file_size = statinfo.st_size
    exthdr = FSVExt()
    memset(addressof(exthdr), 0, sizeof(exthdr))
    patch_ext = PatchExt()
    memset(addressof(patch_ext), 0, sizeof(patch_ext))
    aligned_patch_size = ((int(patch_file_size) + int(8 - 1)) / int(8)) * int(8)
    exthdr.length = sizeof(exthdr) + sizeof(patch_ext) + aligned_patch_size;
    exthdr.type = 1  # 1 == patch extension
    patch_ext.offset = int(args.patch_offset)
    print "Patch offset: ", patch_ext.offset
    patch_ext.length = patch_file_size
    print "Patch length: ", patch_ext.length
    patch_ext_buf = create_string_buffer(exthdr.length)
    memset(addressof(patch_ext_buf), 0, sizeof(patch_ext_buf))  # Includes the zero-pad
    memmove(addressof(patch_ext_buf), addressof(exthdr), sizeof(exthdr))
    memmove(addressof(patch_ext_buf) + sizeof(exthdr), addressof(patch_ext), sizeof(patch_ext))
    with file (args.patch_file, 'r') as patch_file:
      memmove(addressof(patch_ext_buf) + sizeof(exthdr) + sizeof(patch_ext), patch_file.read(patch_file_size), patch_file_size)
  if args.elide_offset is not None and args.elide_length is not None:
    exthdr = FSVExt()
    memset(addressof(exthdr), 0, sizeof(exthdr))
    elide_ext = ElideExt()
    memset(addressof(elide_ext), 0, sizeof(elide_ext))
    exthdr.length = sizeof(exthdr) + sizeof(elide_ext)
    exthdr.type = 0  # 0 == elide extension
    elide_ext.offset = int(args.elide_offset)
    print "Elide offset: ", elide_ext.offset
    elide_ext.length = int(args.elide_length)
    print "Elide length: ", elide_ext.length
    elide_ext_buf = create_string_buffer(exthdr.length)
    memset(addressof(elide_ext_buf), 0, sizeof(elide_ext_buf))
    memmove(addressof(elide_ext_buf), addressof(exthdr), sizeof(exthdr))
    memmove(addressof(elide_ext_buf) + sizeof(exthdr), addressof(elide_ext), sizeof(elide_ext))
  return (string_at(patch_ext_buf) if (patch_ext_buf is not None) else "") + (string_at(elide_ext_buf) if (elide_ext_buf is not None) else "")

def restore_patched_content(args, original_content):
  if original_content is not None:
    with file (args.output_file, 'w') as dst:
      dst.seek(int(args.patch_offset), os.SEEK_SET)
      dst.write(original_content)

def elide_dst(args):
  if args.elide_offset is not None and args.elide_length is not None:
    statinfo = os.stat(args.output_file)
    dst_size = statinfo.st_size
    if dst_size < (int(args.elide_offset) + elide_length):
      print "dst_size >= elide region offet+length"
      return None
    elided_file = tempfile.NamedTemporaryFile()
    with file (args.output_file, 'r') as dst:
      elided_file.write(dst.read(int(args.elide_offset)))
      end_of_elided_segment = int(args.elide_offset) + int(args.elide_length)
      dst.seek(end_of_elided_segment, os.SEEK_SET)
      elided_file.write(dst.read(dst_size - end_of_elided_segment))
    return elided_file
  else:
    return None

def main():
  args = parse_args()

  copy_src_to_dst(args)
  pad_dst(args)
  original_content = apply_patch(args)
  elided_file = elide_dst(args)
  root_hash, merkle_tree = generate_merkle_tree(args, elided_file)
  append_merkle_tree_to_dst(args, merkle_tree)
  header = fill_header_struct(args)
  append_header_to_dst(args, header)
  extensions = serialize_extensions(args)
  append_extensions_to_dst(args, extensions)
  restore_patched_content(args, original_content)
  append_header_reverse_offset_to_dst(args, extensions)
  print 'Merkle root hash: [', root_hash, "]"

if __name__ == '__main__':
  main()
