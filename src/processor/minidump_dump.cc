// Copyright 2006 Google LLC
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google LLC nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// minidump_dump.cc: Print the contents of a minidump file in somewhat
// readable text.
//
// Author: Mark Mentovai

#ifdef HAVE_CONFIG_H
#include <config.h>  // Must come first
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common/path_helper.h"
#include "common/scoped_ptr.h"
#include "google_breakpad/processor/minidump.h"
#include "processor/logging.h"

namespace {

using google_breakpad::Minidump;
using google_breakpad::MinidumpThreadNameList;
using google_breakpad::MinidumpAssertion;
using google_breakpad::MinidumpBreakpadInfo;
using google_breakpad::MinidumpCrashpadInfo;
using google_breakpad::MinidumpException;
using google_breakpad::MinidumpMemoryInfoList;
using google_breakpad::MinidumpMemoryList;
using google_breakpad::MinidumpMiscInfo;
using google_breakpad::MinidumpModule;
using google_breakpad::MinidumpModuleList;
using google_breakpad::MinidumpSystemInfo;
using google_breakpad::MinidumpThreadList;

struct Options {
  Options()
      : minidumpPath(),
        hexdump(false),
        hexdump_width(16),
        modules_debug_info(false),
        platform_info(false) {}

  string minidumpPath;
  bool hexdump;
  unsigned int hexdump_width;
  bool modules_debug_info;
  bool platform_info;
};

static void DumpRawStream(Minidump *minidump,
                          uint32_t stream_type,
                          const char *stream_name,
                          int *errors) {
  uint32_t length = 0;
  if (!minidump->SeekToStreamType(stream_type, &length)) {
    return;
  }

  printf("Stream %s:\n", stream_name);

  if (length == 0) {
    printf("\n");
    return;
  }
  std::vector<char> contents(length);
  if (!minidump->ReadBytes(&contents[0], length)) {
    ++*errors;
    BPLOG(ERROR) << "minidump.ReadBytes failed";
    return;
  }
  size_t current_offset = 0;
  while (current_offset < length) {
    size_t remaining = length - current_offset;
    // Printf requires an int and direct casting from size_t results
    // in compatibility warnings.
    uint32_t int_remaining = remaining;
    printf("%.*s", int_remaining, &contents[current_offset]);
    char *next_null = reinterpret_cast<char*>(
        memchr(&contents[current_offset], 0, remaining));
    if (next_null == NULL)
      break;
    printf("\\0\n");
    size_t null_offset = next_null - &contents[0];
    current_offset = null_offset + 1;
  }
  printf("\n\n");
}

static bool PrintMinidumpDump(const Options& options) {
  Minidump minidump(options.minidumpPath,
                    options.hexdump);
  if (!minidump.Read()) {
    BPLOG(ERROR) << "minidump.Read() failed";
    return false;
  }

  if (options.modules_debug_info) {
    const MinidumpModuleList* modules = minidump.GetModuleList();

    if (modules != nullptr) {
      const unsigned int modules_n = modules->module_count();

      for (unsigned int i = 0; i < modules_n; ++i) {
        const MinidumpModule* module = modules->GetModuleAtIndex(i);

        if (module != nullptr) {
          printf("%s;%s;%s;%s\n", module->code_file().c_str(),
                 module->code_identifier().c_str(),
                 module->debug_file().c_str(),
                 module->debug_identifier().c_str());
        }
      }

      return true;
    }

    return false;
  }

  if (options.platform_info) {
    const MinidumpSystemInfo* sys_info = minidump.GetSystemInfo();

    if (sys_info != nullptr) {
      const MDRawSystemInfo* sys_info_raw = sys_info->system_info();
      char sys_ver[32] = {0};

      if (sys_info_raw != nullptr) {
        sprintf(sys_ver, "%u.%u.%u", sys_info_raw->major_version,
                sys_info_raw->minor_version, sys_info_raw->build_number);
      }

      printf("%s;%s;%s\n", sys_info->GetOS().c_str(), sys_ver,
             sys_info->GetCPU().c_str());
      return true;
    }

    return false;
  }

  minidump.Print();

  int errors = 0;

  MinidumpThreadList *thread_list = minidump.GetThreadList();
  if (!thread_list) {
    ++errors;
    BPLOG(ERROR) << "minidump.GetThreadList() failed";
  } else {
    thread_list->Print();
  }

  MinidumpThreadNameList *thread_name_list = minidump.GetThreadNameList();
  if (thread_name_list) {
    thread_name_list->Print();
  }

  // It's useful to be able to see the full list of modules here even if it
  // would cause minidump_stackwalk to fail.
  MinidumpModuleList::set_max_modules(UINT32_MAX);
  MinidumpModuleList *module_list = minidump.GetModuleList();
  if (!module_list) {
    ++errors;
    BPLOG(ERROR) << "minidump.GetModuleList() failed";
  } else {
    module_list->Print();
  }

  MinidumpMemoryList *memory_list = minidump.GetMemoryList();
  if (!memory_list) {
    ++errors;
    BPLOG(ERROR) << "minidump.GetMemoryList() failed";
  } else {
    memory_list->Print();
  }

  MinidumpException *exception = minidump.GetException();
  if (!exception) {
    BPLOG(INFO) << "minidump.GetException() failed";
  } else {
    exception->Print();
  }

  MinidumpAssertion *assertion = minidump.GetAssertion();
  if (!assertion) {
    BPLOG(INFO) << "minidump.GetAssertion() failed";
  } else {
    assertion->Print();
  }

  MinidumpSystemInfo *system_info = minidump.GetSystemInfo();
  if (!system_info) {
    ++errors;
    BPLOG(ERROR) << "minidump.GetSystemInfo() failed";
  } else {
    system_info->Print();
  }

  MinidumpMiscInfo *misc_info = minidump.GetMiscInfo();
  if (!misc_info) {
    ++errors;
    BPLOG(ERROR) << "minidump.GetMiscInfo() failed";
  } else {
    misc_info->Print();
  }

  MinidumpBreakpadInfo *breakpad_info = minidump.GetBreakpadInfo();
  if (!breakpad_info) {
    // Breakpad info is optional, so don't treat this as an error.
    BPLOG(INFO) << "minidump.GetBreakpadInfo() failed";
  } else {
    breakpad_info->Print();
  }

  MinidumpMemoryInfoList *memory_info_list = minidump.GetMemoryInfoList();
  if (!memory_info_list) {
    ++errors;
    BPLOG(ERROR) << "minidump.GetMemoryInfoList() failed";
  } else {
    memory_info_list->Print();
  }

  MinidumpCrashpadInfo *crashpad_info = minidump.GetCrashpadInfo();
  if (crashpad_info) {
    // Crashpad info is optional, so don't treat absence as an error.
    crashpad_info->Print();
  }

  DumpRawStream(&minidump,
                MD_LINUX_CMD_LINE,
                "MD_LINUX_CMD_LINE",
                &errors);
  DumpRawStream(&minidump,
                MD_LINUX_ENVIRON,
                "MD_LINUX_ENVIRON",
                &errors);
  DumpRawStream(&minidump,
                MD_LINUX_LSB_RELEASE,
                "MD_LINUX_LSB_RELEASE",
                &errors);
  DumpRawStream(&minidump,
                MD_LINUX_PROC_STATUS,
                "MD_LINUX_PROC_STATUS",
                &errors);
  DumpRawStream(&minidump,
                MD_LINUX_CPU_INFO,
                "MD_LINUX_CPU_INFO",
                &errors);
  DumpRawStream(&minidump,
                MD_LINUX_MAPS,
                "MD_LINUX_MAPS",
                &errors);

  return errors == 0;
}

//=============================================================================
static void
Usage(int argc, char *argv[], bool error) {
  FILE *fp = error ? stderr : stdout;

  fprintf(fp,
          "Usage: %s [options...] <minidump>\n"
          "Dump data in a minidump.\n"
          "\n"
          "Options:\n"
          "  <minidump> should be a minidump.\n"
          "  -x:\t Display memory in a hexdump like format\n"
          "  -M:\t Display modules and debug information\n"
          "  -P:\t Display platform information\n"
          "  -h:\t Usage\n",
          google_breakpad::BaseName(argv[0]).c_str());
}

//=============================================================================
static void
SetupOptions(int argc, char *argv[], Options *options) {
  int ch;

  while ((ch = getopt(argc, (char* const*)argv, "xMPh")) != -1) {
    switch (ch) {
      case 'x':
        options->hexdump = true;
        break;
      case 'M':
        options->modules_debug_info = true;
        break;
      case 'P':
        options->platform_info = true;
        break;
      case 'h':
        Usage(argc, argv, false);
        exit(0);

      default:
        Usage(argc, argv, true);
        exit(1);
        break;
    }
  }

  if ((argc - optind) != 1) {
    fprintf(stderr, "%s: Missing minidump file\n", argv[0]);
    exit(1);
  }

  options->minidumpPath = argv[optind];
}

}  // namespace

int main(int argc, char *argv[]) {
  Options options;
  BPLOG_INIT(&argc, &argv);
  SetupOptions(argc, argv, &options);
  return PrintMinidumpDump(options) ? 0 : 1;
}
