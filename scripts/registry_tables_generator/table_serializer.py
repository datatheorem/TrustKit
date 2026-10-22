#!/usr/bin/python2.4
#
# Copyright 2011 Google Inc. All Rights Reserved.
# Modified by The TrustKit Project Authors to bound leaf table offsets to 16 bits.
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

"""Serializes node and string tables. See class comment for more details."""

__author__ = 'bmcquade@google.com (Bryan McQuade)'


def _GetMaxValueForNumBits(num_bits):
  """Return max value for an unsigned integer of width num_bits."""
  return 2**num_bits - 1


class TableSerializer(object):
  """TableSerializer serializes the table builders to C code."""

  def __init__(self,
               component_offset_bits,
               child_node_offset_bits,
               num_children_bits,
               leaf_component_offset_bits):
    self.max_component_offset = _GetMaxValueForNumBits(
      component_offset_bits)
    self.max_child_node_offset = _GetMaxValueForNumBits(
      child_node_offset_bits)
    self.max_num_children = _GetMaxValueForNumBits(num_children_bits)
    self.max_leaf_component_offset = _GetMaxValueForNumBits(
      leaf_component_offset_bits)

  def SerializeNodeTable(self, node_table_builder, string_table_builder):
    """Generate a C representation of the node table.

    Args:
      node_table_builder: The node table to use when serializing.
      string_table_builder: The string table to use when serializing.
    """
    out = []
    for node in node_table_builder.GetNodeTable():
      component_offset = (
          string_table_builder.GetHostnamePartOffset(node.GetName()))
      num_children = len(node.GetChildren())
      if num_children > 0:
        child_node_offset = node_table_builder.GetChildNodeOffset(node)
      else:
        child_node_offset = 0
      if node.IsTerminalNode():
        is_root = 1
      else:
        is_root = 0
      if (component_offset > self.max_component_offset or
          child_node_offset > self.max_child_node_offset or
          num_children > self.max_num_children):
          raise OverflowError(
              'Values %d %d %d out of range.' %
              (component_offset, child_node_offset, num_children))
      out.append(r'  { %5d, %5d, %5d, %d },  /* %s */' % (
          component_offset,
          child_node_offset,
          num_children,
          is_root,
          node.GetIdentifier('.')))
    return '\n'.join(out)

  def SerializeLeafChildNodeTable(self,
                                  node_table_builder,
                                  string_table_builder):
    """Generate a C representation of the leaf node table.

    Args:
      node_table_builder: The node table to use when serializing.
      string_table_builder: The string table to use when serializing.
    """
    out = []
    for node in node_table_builder.GetLeafNodeTable():
      component_offset = (
        string_table_builder.GetHostnamePartOffset(node.GetName()))
      if component_offset > self.max_leaf_component_offset:
          raise OverflowError(
              'component_offset %d out of range.' % component_offset)
      out.append(r'%5d,  /* %s */' % (
          component_offset, node.GetIdentifier('.')))
    return '\n'.join(out)

  @staticmethod
  def SerializeStringTable(string_table_builder):
    """Generate a C representation of the string table.

    Args:
      string_table_builder: the string table to use when serializing.
    """
    last_newline = 0
    out = ['"']
    for char in string_table_builder.GetStringTable():
      if ord(char) > 127:
        raise ValueError("Encountered unexpected multibyte character.")
      if char == '\0':
        if len(out) - last_newline >= 60:
          space_char = '\n'
        else:
          space_char = ' '
        # To prevent the compiler from interpreting subsequent
        # characters as part of the hex code, we break the string
        # literal.
        #
        # E.g. [?feet] --> ["\x3f" "feet"] instead of ["\x3ffeet"]
        out.extend(['\\', '0', '"', space_char, '"'])
        if space_char == '\n':
          last_newline = len(out) - 1
      else:
        out.append(char)
    out.append('"')
    return ''.join(out)

  @staticmethod
  def SerializeTestTable(test_table_builder):
    """Generate a C representation of the test table.

    Args:
      test_table_builder: The test table to use when serializing.
    """
    out = []
    for host, registry, is_exception_rule in test_table_builder.GetTestTable():
      parts = [ 'www', host ]
      parts.extend(registry.split('.'))
      out.append(r'{ "%s", %d, %d },' % ('.'.join(parts),
                                         len(registry),
                                         is_exception_rule))
    return '\n'.join(out)
