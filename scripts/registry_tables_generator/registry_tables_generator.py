#!/usr/bin/env python3
#
# Copyright 2011 Google Inc. All Rights Reserved.
# Modified by The TrustKit Project Authors to run on Python 3.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Reads a suffix file and generates C files containing the registry tables.

registry_tables_generator.py takes in a public suffix DAT file (see
http://publicsuffix.org/) and emits a C file that contains the tables
needed to efficiently determine if a hostname is a valid public
suffix. Three tables are generated: two tables of trie nodes to
traverse the hostname-parts (see node_table_builder.py for additional
details), and a string table that contains all unique hostname parts
(see string_table_builder.py for additional details). See
http://TODO(bmcquade) for more details.

For example, if we have a DAT file that contains the following
registry suffixes:

ac
com.ac
edu.ac
ad
nom.ad
co.ae
net.ae

we would generate a trie with "ac", "ad", and "ae" at its roots. "ac"
would have children "com" and "edu". "ad" would have one child
"nom". "ae" would have children "co" and "net". We would also generate
a trie of hostname part suffixes that gets converted to a string table
containing the unique hostname part suffixes separated by null bytes:
"ac\0ad\0ae\0com\0edu\0nom\0co\0net". See _BuildHostnameSuffixTrie and
_BuildStringTableSuffixTrie for ascii art examples of these tries.

The resulting C output to represent the trie would look like:

struct TrieNode {
  // Index of the hostname-part in the kStringTable.
  unsigned int component_offset  : 21;

  // Index of the first child node in the kNodeTable or
  // kLeafNodeTable. A value >= kLeafChildOffset is an
  // offset into the kLeafNodeTable. All child nodes are
  // adjacent to one another.
  unsigned int child_node_offset : 14;

  // The number of children for this node.
  unsigned int num_children      : 12;

  // Whether or not this node is a terminal node. Terminal
  // nodes are those that represent the last hostname-part
  // of a public suffix. For instance for the suffix
  // "foo.bar.com", the node for "foo" would be a terminal
  // node.
  unsigned int is_terminal       :  1;
};

// Table that contains the string for all unique hostname-parts.
static const char kStringTable[] = "ac\0ad\0ae\0com\0edu\0nom\0co\0net\0";

// Table that contains all nodes in the trie that have
static const struct TrieNode kNodeTable[] = {
{     0,     3,     2, 1 },  // ac, 2 children "com" and "edu" in leaf table
{     3,     5,     1, 1 },  // ad, 1 child, "nom" in leaf table
{     6,     6,     2, 0 },  // ae, 2 children, "co" and "net" in leaf table
};

// Index into kStringTable for each leaf node.
static const REGISTRY_U16 kLeafNodeTable[] = {
    9,  // com.ac
   13,  // edu.ac
   17,  // nom.ad
   21,  // co.ae
   24,  // net.ae
};
"""
__author__ = 'bmcquade@google.com (Bryan McQuade)'

import sys

import node_table_builder
import string_table_builder
import table_serializer
import test_table_builder
import trie_node


def _ReadRulesFromFile(infile):
  """Read the given dat file and generate a list of all rules.

  Args:
    infile: an open, readable file handle for a publicsuffix.org rules file.
  """
  # Get the idna representation of the rule. See
  # http://en.wikipedia.org/wiki/Internationalized_domain_name for
  # more information.
  return [line.strip().encode('idna').decode('ascii')
          for line in infile
          if line.strip() and not line.strip().startswith('//')]


def _BuildHostnameSuffixTrie(rules):
  r"""Construct a suffix trie of the hostname-parts in each rule.

  For instance, if rules is [ foo.com, bar.com, ac.uk ], we would
  return the following trie:
  ()----(com)-(bar)
    \        \
     \        (foo)
      \
       (uk)-(ac)

  Args:
    rules: list of hostnames
  """
  trie = trie_node.TrieNode()
  for rule in rules:
    hostname_parts = rule.split('.')
    node = trie
    for hostname_part in reversed(hostname_parts):
      node = node.GetOrCreateChild(hostname_part)
    node.SetTerminalNode()
  return trie


def _BuildStringTableSuffixTrie(rules):
  r"""Construct a suffix trie of the strings stored in the string table.

  For instance, if rules is [ foo.com, boo.com, bar.com ], we would
  return the following trie:
  ()-m-o-c
  | \
  |  o-o-f
  |     \
   \     b
    \
     r-a-b

  We use a trie to build the string table, in order to reduce
  duplication of suffixes. For instance for the hostname parts
  'fortmissoula' and 'missoula' we store only 'fortmissoula' and refer
  to 'missoula' as being 'fortmissoula' plus 4 characters. This
  reduces the size of the string table by ~1kB.

  Args:
    rules: list of hostnames
  """
  trie = trie_node.TrieNode()
  for rule in rules:
    hostname_parts = rule.split('.')
    for hostname_part in hostname_parts:
      node = trie
      # NOTE: iterating characters in reverse order assumes that there
      # are no multibyte characters in the stream.
      for char in reversed(hostname_part):
        if ord(char) > 127:
          raise ValueError("Encountered unexpected multibyte character.")
        node = node.GetOrCreateChild(char)
      node.SetTerminalNode()
  return trie


def RegistryTablesGenerator(in_file, out_file, out_test_file):
  """Generate registry suffix string tables, given a publicsuffix.org DAT file.

  Args:
    in_file: publicsuffix.org DAT file
    out_file: file to write registry suffix string tables to
    out_test_file: file to write registry suffix test cases to
  """

  rules = _ReadRulesFromFile(in_file)

  hostname_part_trie = _BuildHostnameSuffixTrie(rules)
  suffix_trie = _BuildStringTableSuffixTrie(rules)

  string_table = string_table_builder.StringTableBuilder()
  node_table = node_table_builder.NodeTableBuilder()
  test_table = test_table_builder.TestTableBuilder()

  node_table.BuildNodeTables(hostname_part_trie)
  string_table.BuildStringTable(hostname_part_trie, suffix_trie)
  test_table.BuildTestTable(rules)

  # Specify the number of bits allocated to each field in the C
  # TrieNode struct, so we can detect overflow during the
  # serialization process. TODO(bmcquade): use this information to
  # also generate the C header file with the necessary struct
  # definitions so we don't duplicate the struct definitions.
  serializer = table_serializer.TableSerializer(component_offset_bits = 21,
                                                child_node_offset_bits = 14,
                                                num_children_bits = 12,
                                                leaf_component_offset_bits = 16)

  out_file.write('/* Size of kStringTable %d */\n' %
                 len(string_table.GetStringTable()))
  out_file.write('/* Size of kNodeTable %d */\n' %
                 len(node_table.GetNodeTable()))
  out_file.write('/* Size of kLeafNodeTable %d */\n' %
                 len(node_table.GetLeafNodeTable()))
  out_file.write('/* Total size %d bytes */\n' % (
      # Each entry in the string table is a char (1 byte).
      len(string_table.GetStringTable()) +
      # Each entry in the node table is 6 bytes:
      # 21 bits + 14 bits + 12 bits + 1 bit = 48 bits = 6 bytes.
      len(node_table.GetNodeTable()) * 6 +
      # Each entry in the leaf node table is 2 bytes (1 uint16).
      len(node_table.GetLeafNodeTable()) * 2))
  out_file.write('\n')

  out_file.write('static const char kStringTable[] =\n%s;\n\n' %
                 serializer.SerializeStringTable(string_table))

  out_file.write('static const struct TrieNode kNodeTable[] = {\n%s\n};\n\n' %
                 serializer.SerializeNodeTable(node_table, string_table))

  out_file.write('static const REGISTRY_U16 kLeafNodeTable[] = {\n%s\n};\n\n' %
                 serializer.SerializeLeafChildNodeTable(node_table,
                                                       string_table))

  out_file.write('static const size_t kLeafChildOffset = %d;\n' %
                 len(node_table.GetNodeTable()))

  out_file.write('static const size_t kNumRootChildren = %d;\n' %
                 len(hostname_part_trie.GetChildren()))

  out_test_file.write('static const struct TestEntry kTestTable[] = {\n%s};\n' %
                      serializer.SerializeTestTable(test_table))


def OpenFileOrReturnNone(filename, mode):
  """Helper that performs file open and handles exceptions."""
  try:
    return open(filename, mode, encoding='utf-8')
  except IOError:
    print('Failed to open %s with mode %s.' % (filename, mode), file=sys.stderr)
  return None


def main(argv):
  """Generate registry suffix string tables, given a publicsuffix.org DAT file.

  Args:
    argv[1]: in_file: the publicsuffix.org DAT file
    argv[2]: out_file: the file to write registry suffix string tables to
    argv[3]: out_test_file: the file to write registry suffix test cases to
  """
  if len(argv) != 4:
    print('Usage: gen_string_table.py in_file out_file, out_test_file',
          file=sys.stderr)
    return 1

  in_filename = argv[1]
  out_filename = argv[2]
  out_test_filename = argv[3]

  in_file = OpenFileOrReturnNone(in_filename, 'r')
  out_file = OpenFileOrReturnNone(out_filename, 'w')
  out_test_file = OpenFileOrReturnNone(out_test_filename, 'w')
  all_files_successful = in_file and out_file and out_test_file

  try:
    if all_files_successful:
      RegistryTablesGenerator(in_file, out_file, out_test_file)
  finally:
    if in_file:
      in_file.close()
    if out_file:
      out_file.close()
    if out_test_file:
      out_test_file.close()

  if not all_files_successful:
    return 1
  else:
    return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv))
