/*
 * C
 *
 * Copyright 2022 MicroEJ Corp. All rights reserved.
 * This library is provided in source code for use, modification and test, subject to license terms.
 * Any modification of the source code will break MicroEJ Corp. warranties on the whole library.
 */

/**
 * @file
 * @brief LLMJVM implementation over POSIX.
 * @author MicroEJ Developer Team
 * @version 1.0.0
 * @date 11 April 2018
 */

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <MJVM_MONITOR_types.h>
#include <LLTRACE.h>
#include <sni.h>
#include <MJVM_MONITOR.h>

#if MICROEJ_VEE_METHOD_TRACE == 1

#include <sys/mman.h>
#include <elf.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dlfcn.h>

struct Elf32_File {
struct Elf32_File   *f_next;
const char *f_path;
Elf32_Sym  *f_symtab;
char       *f_strtab;
size_t      f_symcnt;
} *head;

struct Elf32_File* loadelf(const char *path) {
	struct Elf32_File *fp;
	Elf32_Ehdr *header;
	Elf32_Shdr *sections;
	Elf32_Sym *symtab;
	size_t len, symcnt;
	int fd;
	char *strtab;

	fp = malloc(sizeof(struct Elf32_File));
	if (fp == NULL) {
		return NULL;
	}
	fp->f_next = head;
	fp->f_path = path;

	// Read the ELF header.
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		return NULL;
	}

	struct stat st;
	fstat(fd, &st);
	off_t fileLen = st.st_size;

	const char * buffer = mmap(NULL, fileLen, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buffer == MAP_FAILED) {
		return NULL;
	}

	header = (Elf32_Ehdr*) buffer;
	if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0 || header->e_ident[EI_CLASS] != ELFCLASS32) {
		return NULL;
	}

	// Read the section headers.
	sections = (Elf32_Shdr *)(buffer + header->e_shoff);

	// Find and read the .symtab section.
	int i = 0;
	for (i = 0; i < header->e_shnum; i++) {
		if (sections[i].sh_type == SHT_SYMTAB) {
		break;
		}
	}
	if (i == header->e_shnum) {
		return NULL;
	}
	symtab = (Elf32_Sym *)(buffer + sections[i].sh_offset);
	symcnt = sections[i].sh_size / sizeof(symtab[0]);

	// Find and read the .strtab section.
	i = sections[i].sh_link;
	strtab = (char *)(buffer + sections[i].sh_offset);

	fp->f_symtab = symtab;
	fp->f_strtab = strtab;
	fp->f_symcnt = symcnt;

	head = fp;
	return fp;
}

int elfaddr(const void *addr, Dl_info *info) {
	if (dladdr(addr, info) == 0) return 0;
	const char *path = info->dli_fname;

	struct Elf32_File *fp = NULL;
	// Did we already open this file?
	for (fp = head; fp != NULL; fp = head->f_next) {
		if (strcmp(path, fp->f_path) == 0){
		break;
		}
	}
	if (fp == NULL) {
		fp = loadelf(path);
		if (fp == NULL) {
		return 0;
		}
	}

	Elf32_Sym *found = NULL;
	for (int i = 0; i < fp->f_symcnt; i++) {
		Elf32_Sym *sym = &fp->f_symtab[i];
		if (fp->f_strtab[sym->st_name] == '\0') continue;
		if (sym->st_value == (Elf32_Addr)addr) {
		found = sym;
		break;
		}
	}
	if (found == NULL) {
		return 0;
	}
	info->dli_sname = &fp->f_strtab[found->st_name];
	info->dli_saddr = (void *)(found->st_value);
	return 1;
}

#elif MICROEJ_VEE_METHOD_TRACE == 2

#include "barectf-platform-linux-fs.h"
#include "barectf.h"

struct barectf_platform_linux_fs_ctx *platform_ctx;
struct barectf_default_ctx *ctx;

extern int _java_Ljava_lang_Thread_method_callWrapper_V;
extern int _java_Ljava_lang_Thread_method_clinitWrapper_I_V;
extern int _java_Ljava_lang_Thread_method_runWrapper_V;
extern int _java_Ljava_lang_MainThread_method_run_V;

void LLMJVM_MONITOR_IMPL_initialize(bool auto_start) {
	if(auto_start == true){
		LLTRACE_start();
	}

    platform_ctx = barectf_platform_linux_fs_init(512, "./channel0_0", 0, 0, 0);
    ctx = barectf_platform_linux_fs_get_barectf_ctx(platform_ctx);
}

void LLMJVM_MONITOR_IMPL_on_shutdown(void) {
	if (platform_ctx != NULL) {
		/* Finalize (free) the platform context */
		barectf_platform_linux_fs_fini(platform_ctx);
	}
}
#endif

void LLMJVM_MONITOR_IMPL_on_invoke_method(int32_t method_start_address){
#if MICROEJ_VEE_METHOD_TRACE == 1
	Dl_info info;
	if (elfaddr((void *)method_start_address, &info)) {
		printf("Invoke method %s\n", info.dli_sname);
		return;
	}
#elif MICROEJ_VEE_METHOD_TRACE == 2
	if ((method_start_address !=  &_java_Ljava_lang_Thread_method_callWrapper_V) && (method_start_address != &_java_Ljava_lang_Thread_method_clinitWrapper_I_V) && (method_start_address != &_java_Ljava_lang_Thread_method_runWrapper_V) &&(method_start_address != &_java_Ljava_lang_MainThread_method_run_V)) {
		barectf_trace_func_entry(ctx, method_start_address, method_start_address,SNI_getCurrentJavaThreadID());
	}
	return;
#endif
	printf("Invoke method @A:0x%X@\n", method_start_address);
}

void LLMJVM_MONITOR_IMPL_on_return_method(int32_t method_start_address){
#if MICROEJ_VEE_METHOD_TRACE == 1
	Dl_info info;
	if (elfaddr((void *)method_start_address, &info)) {
		printf("Return from method %s\n", info.dli_sname);
		return;
	}
#elif MICROEJ_VEE_METHOD_TRACE == 2
	if ((method_start_address !=  &_java_Ljava_lang_Thread_method_callWrapper_V) && (method_start_address != &_java_Ljava_lang_Thread_method_clinitWrapper_I_V) && (method_start_address != &_java_Ljava_lang_Thread_method_runWrapper_V) &&(method_start_address != &_java_Ljava_lang_MainThread_method_run_V)) {
		barectf_trace_func_exit(ctx, method_start_address, method_start_address,SNI_getCurrentJavaThreadID());
	}
	return;
#endif
	printf("Return from method @A:0x%X@\n", method_start_address);
}
