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

"""Simple trie node. See class comment for more details."""

__author__ = 'bmcquade@google.com (Bryan McQuade)'

class TrieNode(object):
  """TrieNode: a simple node class that can be used to represent a trie.

  Each node in a trie of TrieNodes is assigned a string name, except
  for the root node which has no name. TrieNode can be used to
  represent all of the hostname-parts in the public suffix list (where
  each node contains a hostname-part, e.g. 'com' or 'co' or 'uk'), or
  to efficiently store all common suffixes of the hostname parts
  (where each node contains a single character, e.g. if we have
  hostname parts 'com' and 'dom', we would have a root TrieNode 'm'
  with one child 'o', which has two children 'c' and 'd').
  """

  def __init__(self, parent=None, name=None):
    """Instantiates a new TrieNode.

    Args:
      parent: The parent TrieNode, or None if this is a root node.
      name: The name of this TrieNode. Should be None if this is a root node.
    """
    self._parent = parent
    self._name = name
    self._children = {}
    self._is_terminal = False
    if (not self._parent) != (not self._name):
      raise ValueError("Mismatched parent and name attributes.")

  def GetName(self):
    """Return the name of this node, or raise LookupError if this is a root."""
    if not self._name:
      raise AttributeError("No name for node.")
    return self._name

  def GetParent(self):
    """Return the parent TrieNode, or None if this is a root."""
    if self.IsRoot():
      raise AttributeError("No parent for node.")
    return self._parent

  def GetParentChain(self):
    """Return a list of the names of all parent nodes, including this node.

    Order is from this node to the root."""
    chain = []
    node = self
    while not node.IsRoot():
      parent = node.GetParent()
      chain.append(node.GetName())
      node = parent
    return chain

  def GetIdentifier(self, separator=''):
    """Return a string identifier for this node.

    The name of each node in the parent chain is joined using the
    specified separator.

    Args:
      separator: The separator to use when joining node names.
    """
    return separator.join(self.GetParentChain())

  def AddChild(self, name):
    """Add a child with the specified name.

    Raises ValueError if this node already has a child with the
    specified name.

    Args:
      name: The name of the node.
    """
    if name in self._children:
      raise ValueError(name)
    node = TrieNode(self, name)
    self._children[name] = node

  def GetChild(self, name):
    """Return the child TrieNode with the specified name.

    Raises ValueError if this node does not have a child with the
    specified name.

    Args:
      name: The name of the node.
    """
    if name not in self._children:
      raise ValueError(name)
    return self._children[name]

  def GetOrCreateChild(self, name):
    """Return the child with the specified name, creating it if necessary.

    Args:
      name: The name of the node.
    """
    if name not in self._children:
      self.AddChild(name)
    return self.GetChild(name)

  def HasChildren(self):
    """Return a boolean indicating whether this node has children."""
    return len(self._children) > 0

  def GetChildren(self):
    """Return a list of all children, lexicographically sorted by name."""
    return sorted(self._children.values(), key=lambda n: n.GetName())

  def IsRoot(self):
    """Return whether this node is a root (i.e. it has no parent)."""
    return not self._parent

  def IsTerminalNode(self):
    """Return a boolean indicating whether this node is a terminal node.

    A terminal node is one that represents the end of a sequence of
    nodes in the trie. For instance if the sequences "a,b,c" and "a,b"
    are added to the trie, "b" and "c" are terminal nodes, since they
    are both at the end of their sequences.
    """
    return self._is_terminal

  def SetTerminalNode(self):
    """Mark this node as a terminal node."""
    self._is_terminal = True

