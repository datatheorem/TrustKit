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

"""Builds the test tables. See class comment for more details."""

__author__ = 'bmcquade@google.com (Bryan McQuade)'


class TestTableBuilder(object):
  """Builds a list of test cases based on the public suffix list."""

  def __init__(self):
    self._test_table = []

  def BuildTestTable(self, rules):
    """Generates tuples that contains a test entry hostname,registry.

    Each test hostname has a registry, which is the part of a hostname
    that cookies cannot be set on, as well as a hostname, which is the
    part that comes before the registry. For instance example.co.uk
    would have a host 'example' and a registry 'co.uk'. Most entries
    will use a default host, except for exception rules, which use the
    exception as the host (since cookies can be set on exception
    rules).
    """
    for rule in rules:
      parts = rule.split('.')
      first = parts[0]
      host = 'example'
      if first == '*':
        # Special case: if the first part is '*', generate two tests,
        # one with 'wc' as the first part, another with 'wildcard' as
        # the first part. We use strings of differing lengths to make
        # sure there is no string length specific parsing of
        # wildcards.
        parts[0] = 'wildcard'
        registry = '.'.join(parts)
        self._test_table.append((host, registry, 0))
        parts[0] = 'wc'
        registry = '.'.join(parts)
        self._test_table.append((host, registry, 0))
        continue

      is_exception_rule = 0
      if first[0] == '!':
        # This is an exception rule. Strip the leading exclamation and
        # use the remaining part as the hostname. Everything after is
        # the registry.
        host = first[1:]
        registry = '.'.join(parts[1:])
        is_exception_rule = 1
      else:
        registry = '.'.join(parts)

      self._test_table.append((host, registry, is_exception_rule))

  def GetTestTable(self):
    """Return the test table of (host, registry) tuples."""
    return self._test_table
