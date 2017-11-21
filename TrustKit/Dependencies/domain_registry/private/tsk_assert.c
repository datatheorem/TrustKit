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

#include "../domain_registry.h"
#include <stdio.h>
#include <stdlib.h>

static void DefaultAssertHandler(const char* file, int line, const char* cond_str) {
    fprintf(stderr, "%s:%d. CHECK failed: %s\n", file, line, cond_str);
    abort();
}

static DomainRegistryAssertHandler g_assert_hander = DefaultAssertHandler;

void DoAssert(const char* file,
              int line,
              const char* condition_str,
              int condition) {
  if (condition == 0) {
    g_assert_hander(file, line, condition_str);
  }
}

void SetDomainRegistryAssertHandler(DomainRegistryAssertHandler handler) {
  g_assert_hander = handler;
}
