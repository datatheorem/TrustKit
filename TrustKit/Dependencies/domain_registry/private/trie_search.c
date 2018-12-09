/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "tsk_assert.h"
#include "string_util.h"
#include "trie_search.h"

#include <stdlib.h>
#include <string.h>

/*
 * Helper macro that chooses the node half-way between the start and
 * end nodes. Used for binary search.
 */
#define MIDDLE(start, end) ((start) + ((((end) - (start)) + 1) / 2));

/*
 * Global data structures used to perform the search. Should be
 * populated once at startup by a call to SetRegistryTables.
 */
static const char* g_string_table = NULL;
static const struct TrieNode* g_node_table = NULL;
static size_t g_num_root_children = 0;
static const REGISTRY_U16* g_leaf_node_table = NULL;
static size_t g_leaf_node_table_offset = 0;

/*
 * Create an "exception" version of the given component. For instance
 * if component is "foo", will return "!foo". The caller is
 * responsible for freeing the returned memory.
 */
static char* StrDupExceptionComponent(const char* component) {
  /*
   * TODO(bmcquade): could use thread-local storage of sufficient size
   * to avoid this allocation. This should be invoked infrequently
   * enough that it's probably fine for us to perform the allocation.
   */
  const size_t component_len = strlen(component);
  char* exception_component = malloc(component_len + 2);
  if (exception_component == NULL) {
    return NULL;
  }
  memcpy(exception_component + 1, component, component_len);
  exception_component[0] = '!';
  exception_component[component_len + 1] = 0;
  return exception_component;
}

/*
 * Performs a binary search looking for value, between the nodes start
 * and end, inclusive. Would normally have static linkage but is made
 * public for testing.
 */
static const struct TrieNode* FindNodeInRange(
    const char* value,
    const struct TrieNode* start,
    const struct TrieNode* end) {
  DCHECK(value != NULL);
  DCHECK(start != NULL);
  DCHECK(end != NULL);
  if (start > end) return NULL;
  while (1) {
    const struct TrieNode* candidate;
    const char* candidate_str;
    int result;

    DCHECK(start <= end);
    candidate = MIDDLE(start, end);
    candidate_str = g_string_table + candidate->string_table_offset;
    result = HostnamePartCmp(value, candidate_str);
    if (result == 0) return candidate;
    if (result > 0) {
      if (end == candidate) return NULL;
      start = candidate + 1;
    } else {
      if (start == candidate) return NULL;
      end = candidate - 1;
    }
  }
}

/*
 * Performs a binary search looking for value, between the nodes start
 * and end, inclusive. Would normally have static linkage but is made
 * public for testing.
 */
static const char* FindLeafNodeInRange(
    const char* value,
    const REGISTRY_U16* start,
    const REGISTRY_U16* end) {
  DCHECK(value != NULL);
  DCHECK(start != NULL);
  DCHECK(end != NULL);
  if (start > end) return NULL;
  while (1) {
    const REGISTRY_U16* candidate;
    const char* candidate_str;
    int result;
    DCHECK(start <= end);
    candidate = MIDDLE(start, end);
    candidate_str = g_string_table + *candidate;
    result = HostnamePartCmp(value, candidate_str);
    if (result == 0) return candidate_str;
    if (result > 0) {
      if (end == candidate) return NULL;
      start = candidate + 1;
    } else {
      if (start == candidate) return NULL;
      end = candidate - 1;
    }
  }
}

/*
 * Searches to find a registry node with the given component
 * identifier and the given parent node. If parent is null, searches
 * starting from the root node.
 */
const struct TrieNode* FindRegistryNode(const char* component,
                                        const struct TrieNode* parent) {
  const struct TrieNode* start;
  const struct TrieNode* end;
  const struct TrieNode* current;
  const struct TrieNode* exception;

  DCHECK(g_string_table != NULL);
  DCHECK(g_node_table != NULL);
  DCHECK(g_leaf_node_table != NULL);
  DCHECK(component != NULL);

  if (IsInvalidComponent(component)) {
    return NULL;
  }
  if (parent == NULL) {
    /* If parent is NULL, start the search at the root node. */
    start = g_node_table;
    end = start + (g_num_root_children - 1);
  } else {
    if (HasLeafChildren(parent) != 0) {
      /*
       * If the parent has leaf children, FindRegistryLeafNode should
       * have been called instead.
       */
      DCHECK(0);
      return NULL;
    }

    /* We'll be searching the specified parent node's children. */
    start = g_node_table + parent->first_child_offset;
    end = start + ((int) parent->num_children - 1);
  }
  current = FindNodeInRange(component, start, end);
  if (current != NULL) {
    /* Found a match. Return it. */
    return current;
  }

  /*
   * We didn't find an exact match, so see if there's a wildcard
   * match. From http://publicsuffix.org/format/: "The wildcard
   * character * (asterisk) matches any valid sequence of characters
   * in a hostname part. (Note: the list uses Unicode, not Punycode
   * forms, and is encoded using UTF-8.) Wildcards may only be used to
   * wildcard an entire level. That is, they must be surrounded by
   * dots (or implicit dots, at the beginning of a line)."
   */
  current = FindNodeInRange("*", start, end);
  if (current != NULL) {
    /*
     * If there was a wildcard match, see if there is a wildcard
     * exception match, and prefer it if so. From
     * http://publicsuffix.org/format/: "An exclamation mark (!) at
     * the start of a rule marks an exception to a previous wildcard
     * rule. An exception rule takes priority over any other matching
     * rule.".
     */
    char* exception_component = StrDupExceptionComponent(component);
    if (exception_component == NULL) {
      return NULL;
    }
    exception = FindNodeInRange(exception_component,
                                start,
                                end);
    free(exception_component);
    if (exception != NULL) {
      current = exception;
    }
  }
  return current;
}

const char* FindRegistryLeafNode(const char* component,
                                 const struct TrieNode* parent) {
  size_t offset;
  const REGISTRY_U16* leaf_start;
  const REGISTRY_U16* leaf_end;
  const char* match;
  const char* exception;

  DCHECK(g_string_table != NULL);
  DCHECK(g_node_table != NULL);
  DCHECK(g_leaf_node_table != NULL);
  DCHECK(component != NULL);
  DCHECK(parent != NULL);
  DCHECK(HasLeafChildren(parent) != 0);

  if (parent == NULL) {
    return NULL;
  }
  if (HasLeafChildren(parent) == 0) {
    return NULL;
  }
  if (IsInvalidComponent(component)) {
    return NULL;
  }

  offset = parent->first_child_offset - g_leaf_node_table_offset;
  leaf_start = g_leaf_node_table + offset;
  leaf_end = leaf_start + ((int) parent->num_children - 1);
  match = FindLeafNodeInRange(component,
                              leaf_start,
                              leaf_end);
  if (match != NULL) {
    return match;
  }

  /*
   * We didn't find an exact match, so see if there's a wildcard
   * match. From http://publicsuffix.org/format/: "The wildcard
   * character * (asterisk) matches any valid sequence of characters
   * in a hostname part. (Note: the list uses Unicode, not Punycode
   * forms, and is encoded using UTF-8.) Wildcards may only be used to
   * wildcard an entire level. That is, they must be surrounded by
   * dots (or implicit dots, at the beginning of a line)."
   */
  match = FindLeafNodeInRange("*", leaf_start, leaf_end);
  if (match != NULL) {
    /*
     * There was a wildcard match, so see if there is a wildcard
     * exception match, and prefer it if so. From
     * http://publicsuffix.org/format/: "An exclamation mark (!) at
     * the start of a rule marks an exception to a previous wildcard
     * rule. An exception rule takes priority over any other matching
     * rule.".
     */
    char* exception_component = StrDupExceptionComponent(component);
    if (exception_component == NULL) {
      return NULL;
    }
    exception = FindLeafNodeInRange(exception_component,
                                    leaf_start,
                                    leaf_end);
    free(exception_component);
    if (exception != NULL) {
      match = exception;
    }
  }
  return match;
}

const char* GetHostnamePart(size_t offset) {
  DCHECK(g_string_table != NULL);
  return g_string_table + offset;
}

int HasLeafChildren(const struct TrieNode* node) {
  if (node == NULL) { return 0; }
  if (node->first_child_offset < g_leaf_node_table_offset) return 0;
  return 1;
}

void SetRegistryTables(const char* string_table,
                       const struct TrieNode* node_table,
                       size_t num_root_children,
                       const REGISTRY_U16* leaf_node_table,
                       size_t leaf_node_table_offset) {
  g_string_table = string_table;
  g_node_table = node_table;
  g_num_root_children = num_root_children;
  g_leaf_node_table = leaf_node_table;
  g_leaf_node_table_offset = leaf_node_table_offset;
}
