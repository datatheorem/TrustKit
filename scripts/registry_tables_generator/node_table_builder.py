#!/usr/bin/python2.4
#
# Copyright 2011 Google Inc. All Rights Reserved.
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

"""Builds node tables. See class comment for more details."""

__author__ = 'bmcquade@google.com (Bryan McQuade)'

def _NodeHasAllLeafChildren(node):
  """Determines whether the given node's children are all leaf nodes.

  Note that a node with no children does *not* have all leaf children.
  """
  if not node.HasChildren():
    return False

  for child in node.GetChildren():
    if child.HasChildren():
      return False
  return True


def _ComputeLeafChildCacheKey(node):
  """Computes a key that uniquely identifies the node, or None if no key."""
  if not _NodeHasAllLeafChildren(node):
    # We do not compute cache keys for nodes that have children, since
    # there is a low hitrate for such duplicates and since the cache
    # keys would be substantially more complex.
    raise ValueError('Node has non-leaf children.')
  return tuple([n.GetName() for n in node.GetChildren()])


class _NodeTable(object):
  """Stores a table of TrieNodes and provides efficent lookup of node offset."""

  def __init__(self, cache_key_func=None):
    """Instantiates a new _NodeTable.

    Args:
      cache_key_func: The function to use to compute the cache key for
                      the given node, if any. If unspecified, no cache
                      is used.
    """
    # Table of TrieNodes, in breadth-first order, with siblings
    # ordered lexicographically. For instance the hostnames
    # 'foo.com.au' and 'edu.au' would be ordered in the table as: [
    # 'au', 'com', 'edu', 'foo' ].
    self._nodes = []

    # Map from a node's hostname identifier (e.g. 'edu.au') to the
    # offset of that node's first child in the _nodes member. Enables
    # fast lookup of the index of a node's children.
    self._first_child_offset_map = {}

    # Used to find duplicate entries that can be reused to save space,
    # instead of adding the same entries multiple times.
    self._cache = {}

    # Function used to uniquely identify nodes in the cache.
    self._cache_key_func = cache_key_func

  def GetNodeList(self):
    """Get the list of nodes populated by calls to AddChildren()."""
    return self._nodes

  def GetFirstChildOffset(self, node):
    """Get the offset of this node's first child in the table."""
    identifier = node.GetIdentifier('.')
    if identifier not in self._first_child_offset_map:
      raise ValueError('No offset for specified node.')
    return self._first_child_offset_map[node.GetIdentifier('.')]

  def AddChildren(self, node):
    """Add the children of this node to the appropriate table."""
    cache_key = None
    if self._cache_key_func:
      cache_key = self._cache_key_func(node)
      if cache_key in self._cache:
        identifier = node.GetIdentifier('.')
        self._first_child_offset_map[identifier] = self._cache[cache_key]
        return

    # Cache miss. Add the children to this _NodeTable.
    self._DoAddChildren(node)
    if cache_key:
      self._cache[cache_key] = self.GetFirstChildOffset(node)

  def _DoAddChildren(self, node):
    """Add this node's children to the node table."""
    children = node.GetChildren()
    offset_of_children = len(self._nodes)
    self._first_child_offset_map[node.GetIdentifier('.')] = offset_of_children
    for child in children:
      self._nodes.append(child)


class NodeTableBuilder(object):
  """Builds node tables that allow for trie-based lookup of registry suffixes.

  NodeTableBuilder builds a table-based representation of the registry
  suffix trie. We construct two different node tables: the 'main' node
  table, and the leaf child node table. The leaf child node table
  contains nodes whose siblings are all leaf children in the trie. The
  leaf child table exists separately from the main table only because
  many nodes fit this criteria (all siblings are leaves) and these
  nodes can be represented more efficiently than nodes in the main
  table (2 bytes per node, instead of 5 bytes per node).
  """

  def __init__(self):
    self._node_table = _NodeTable()
    self._leaf_child_node_table = _NodeTable(_ComputeLeafChildCacheKey)

  def BuildNodeTables(self, node):
    """Constructs the node tables for the given root trie node."""
    if _NodeHasAllLeafChildren(node):
      self._leaf_child_node_table.AddChildren(node)
    elif node.HasChildren():
      self._node_table.AddChildren(node)
      children = node.GetChildren()
      for child in children:
        self.BuildNodeTables(child)

  def GetNodeTable(self):
    """Return the generated node table."""
    return self._node_table.GetNodeList()

  def GetLeafNodeTable(self):
    """Return the generated leaf node table."""
    return self._leaf_child_node_table.GetNodeList()

  def GetChildNodeOffset(self, node):
    """Return the index of the node's first child.

    If the node has only leaf children, the index will be offset by
    the number of nodes in the non-leaf table, as this allows us to
    differentiate between references to the node table and the leaf
    table.
    """
    if _NodeHasAllLeafChildren(node):
      return (len(self._node_table.GetNodeList()) +
              self._leaf_child_node_table.GetFirstChildOffset(node))
    else:
      return self._node_table.GetFirstChildOffset(node)
