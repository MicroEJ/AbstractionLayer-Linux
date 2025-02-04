/**
 * C
 *
 * Copyright 2014-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */


/**
 * @file
 * @brief Signal handler for MicroEJ.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 * @date 26 June 2023
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif

#ifdef __cplusplus
	extern "C" {
#endif

//this include will define __UCLIBC__ if we are on the uClibc
#include <features.h>

#ifndef __UCLIBC__
#include <execinfo.h>
#endif

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

#include "LLMJVM.h"

/* This structure mirrors the one found in /usr/include/asm/ucontext.h */
typedef struct _sig_ucontext {
	unsigned long     uc_flags;
	struct ucontext   *uc_link;
	stack_t           uc_stack;
	struct sigcontext uc_mcontext;
	sigset_t          uc_sigmask;
} sig_ucontext_t;

static void crit_err_hdlr(int sig_num, siginfo_t * info, void * ucontext)
{
#ifndef __UCLIBC__
	void *             array[50];
	char **            messages;
	int                size, i;
#endif
	void *             caller_address;
	sig_ucontext_t *   uc;

	uc = (sig_ucontext_t *)ucontext;

	/* Get the address at the time the signal was raised */
#if defined(__i386__) // gcc specific
	caller_address = (void *) uc->uc_mcontext.eip; // EIP: x86 specific
#elif defined(__x86_64__) // gcc specific
	caller_address = (void *) uc->uc_mcontext.rip; // RIP: x86_64 specific
#elif defined(__mips__) // gcc specific
	caller_address = (void *) uc->uc_mcontext.sc_pc; // SC_PC: MIPS specific
#elif defined(__arm__) // gcc specific
	caller_address = (void *) uc->uc_mcontext.arm_pc; // ARM_PC: ARM specific
#else
#error Unsupported architecture. // TODO: Add support for other arch.
#endif

	fprintf(stdout, "signal %d (%s), address is %p from %p\n",
			sig_num, strsignal(sig_num), info->si_addr,
			(void *)caller_address);

#ifndef __UCLIBC__
	size = backtrace(array, 50);

	/* overwrite sigaction with caller's address */
	array[1] = caller_address;

	messages = backtrace_symbols(array, size);

	/* skip first stack frame (points here) */
	for (i = 1; i < size && messages != NULL; ++i)
	{
		fprintf(stdout, "[bt]: (%d) %s\n", i, messages[i]);
	}

	free(messages);

#else
	//uClibc does not manage backtrace* functions.
	fprintf(stdout, "[bt]: %p\n", caller_address);
#endif


	LLMJVM_dump();

	exit(EXIT_FAILURE);
}

static void microej_core_engine_dump_hdlr(int sig_num, siginfo_t * info, void * ucontext){

	LLMJVM_dump();
}

static void microej_signal_handler_init(int signum, void (*handler)(int, siginfo_t *, void *))
{
	struct sigaction sigact;

	sigact.sa_sigaction = handler;
	sigact.sa_flags = SA_RESTART | SA_SIGINFO;

	if (sigaction(signum, &sigact, (struct sigaction *)NULL) != 0)
	{
		fprintf(stderr, "error setting signal handler for %d (%s)\n", signum, strsignal(signum));

		exit(EXIT_FAILURE);
	}
}

void microej_segfault_handler_init(void)
{
	microej_signal_handler_init(SIGSEGV, crit_err_hdlr);
}

void microej_usr1_signal_handler_init(void)
{
	microej_signal_handler_init(SIGUSR1, microej_core_engine_dump_hdlr);
}

#ifdef __cplusplus
	}
#endif
