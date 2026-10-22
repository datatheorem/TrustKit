#!/usr/bin/python2.4
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

"""Builds the string table. See class comment for more details."""

__author__ = 'bmcquade@google.com (Bryan McQuade)'

class StringTableBuilder(object):
  """Builds a string table of hostname parts from the given suffix trie.

  StringTableBuilder constructs the string table and provides an API
  to find the index of a hostname-part within the string table.

  The string table is an array of null-separated unique string
  suffixes, combined with a map that allows for efficient lookup of
  the offset of a string suffix within the array.
  """
  def __init__(self):
    # The generated string table containing one character per element,
    # e.g. for "com\0edu\0au\0 the table would contain: ['c', 'o',
    # 'm', '\0', 'e', 'd', 'u', '\0', 'a', 'u', '\0'].
    self._string_table = []

    # Map from a hostname-part (e.g. 'com' or 'edu') to its offset in
    # the string table.
    self._hostname_part_map = {}

  def BuildStringTable(self, hostname_part_node, root_suffix_node):
    """Constructs the string table using the specified tries.

    Args:
      hostname_part_node: TrieNode for the hostname part being added to
                          the string table.
      root_suffix_node: Root TrieNode containing all unique hostname part
                        string suffixes.
    """
    children = hostname_part_node.GetChildren()

    # Iterate over all of the children in the hostname part node, and
    # add each to the string table.
    for child in children:
      node = root_suffix_node
      # NOTE: iterating characters in reverse order assumes that there
      # are no multibyte characters in the stream.
      for char in reversed(child.GetName()):
        if ord(char) > 127:
          raise ValueError("Encountered unexpected multibyte character.")

        # Get the node associated with the character. Since
        # root_suffix_node was already populated with all of the
        # hostname-parts, this should always succeed. If there is no
        # child node for the given character, it's an error, and
        # GetChild will raise a ValueError.
        node = node.GetChild(char)
      self._EmitHostnamePart(node)

    # Now recursively add all of the children of the
    # hostname_part_node to the string table.
    for child in children:
      self.BuildStringTable(child, root_suffix_node)

  def GetStringTable(self):
    """Return the generated string table."""
    return self._string_table

  def GetHostnamePartOffset(self, name):
    """Get the offset of the given hostname-part in the string table."""
    return self._hostname_part_map[name]

  def _EmitHostnamePart(self, node):
    """Emit the hostname-part for the node to the string table.

    Args:
      node: The string suffix node to emit. Each node in the chain
            contains a single character to be emitted.
    """

    # Find the most shallow leaf under this node and emit it
    # instead. By emitting only leaves, we compress hostname-parts
    # that are themselves suffixes of other hostname-parts. For
    # instance, we do not emit 'missoula' because it is a suffix of
    # another hostname-part 'fortmissoula'. We can instead emit
    # 'fortmissoula' and refer to 'missoula' as the offset of
    # 'fortmissoula' plus 4 characters. This reduces the size of the
    # string table by ~1kB.
    node = StringTableBuilder._FindMostShallowLeafNode(node)

    hostname_part = node.GetIdentifier()
    if hostname_part in self._hostname_part_map:
      # This hostname part has already been emitted during a previous
      # invocation, so there is nothing more to do.
      return

    # Store the offset of the hostname part we're about to emit.
    self._hostname_part_map[hostname_part] = len(self._string_table)

    # Append the characters for this hostname_part to the string table
    # as well as a trailing null byte.
    self._string_table.extend(hostname_part)
    self._string_table.append('\0')

    # Next, walk up the parent chain, looking for additional terminal
    # nodes. For each terminal node, create an entry in the
    # hostname_parts map. Since each parent that is a terminal node is
    # a suffix of the hostname_part we just added (e.g. if we just
    # added 'hello' then our parent is 'ello', the next parent is
    # 'llo', etc), the index in the hostname_part map should point
    # into the string we just added to the string table. For instance
    # if we just added 'hello' at index 500 and 'llo' is a terminal
    # node, we should add an entry for 'llo' at index 502.

    # Remember the index of the hostname_part just added, as well as
    # its length, so we can add parent terminal nodes relative to it.
    leaf_hostname_part_index = self._hostname_part_map[hostname_part]
    leaf_hostname_part_len = len(hostname_part)

    parent = node.GetParent()
    while True:
      if parent.IsTerminalNode():
        hostname_part = parent.GetIdentifier()
        if hostname_part not in self._hostname_part_map:
          offset = leaf_hostname_part_len - len(hostname_part)
          self._hostname_part_map[hostname_part] = (
              leaf_hostname_part_index + offset)
      if parent.IsRoot():
        break
      parent = parent.GetParent()

  @staticmethod
  def _FindMostShallowLeafNode(node):
    """Return the most shallow leaf TrieNode under the the given node.

    Returns the given node if that node is a leaf node.

    Args:
      node: The TrieNode to begin searching from.
    """
    # Suppress warning "Object (best) has no attribute (GetParentChain)"
    __pychecker__ = 'no-objattrs'

    if not node.HasChildren():
      return node

    candidates = (StringTableBuilder._FindMostShallowLeafNode(child)
                  for child in node.GetChildren())

    # Construct a generator that produces pairs of
    # (candidate_parent_chain_len, candidate_node).
    cost_candidate_pairs = ((len(candidate.GetParentChain()), candidate)
                            for candidate in candidates)

    # Return the candidate node with the smallest chain length.
    return min(cost_candidate_pairs, key=lambda pair: pair[0])[1]
