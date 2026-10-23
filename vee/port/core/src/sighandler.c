/**
 * C
 *
 * Copyright 2014-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief Signal handler for MicroEJ.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 * @date 26 June 2023
 */

#ifdef __cplusplus
extern "C" {
#endif

//this include will define __UCLIBC__ if we are on the uClibc
#include <features.h>

#ifndef __UCLIBC__
#include <execinfo.h>
#endif

/* cppcheck-suppress misra-c2012-21.5 ; this file installs the SIGSEGV and SIGUSR1 handlers of the VEE Port, which needs
 * <signal.h>. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

#include "LLMJVM.h"
#include "sighandler.h"

/* This structure mirrors the one found in /usr/include/asm/ucontext.h */
typedef struct _sig_ucontext {
	unsigned long uc_flags;
	struct ucontext *uc_link;
	stack_t uc_stack;
	struct sigcontext uc_mcontext;
	sigset_t uc_sigmask;
} sig_ucontext_t;

static void crit_err_hdlr(int sig_num, siginfo_t *info, void *ucontext) {
#ifndef __UCLIBC__
	void *array[50];
	int size;
#endif
	void *caller_address;
	sig_ucontext_t *uc;

	/* cppcheck-suppress misra-c2012-11.5 ; POSIX gives an SA_SIGINFO handler the context of the interrupted thread as a
	 * pointer to void, so reading a register requires this conversion. */
	uc = (sig_ucontext_t *)ucontext;

	/* Get the address at the time the signal was raised */
#if defined(__i386__) // gcc specific
	/* cppcheck-suppress misra-c2012-11.6 ; the saved instruction pointer is an integer, and %p and
	 * backtrace_symbols_fd() take it as a pointer. */
	caller_address = (void *)uc->uc_mcontext.eip;  // EIP: x86 specific
#elif defined(__x86_64__) // gcc specific
	caller_address = (void *)uc->uc_mcontext.rip;  // RIP: x86_64 specific
#elif defined(__mips__) // gcc specific
	caller_address = (void *)uc->uc_mcontext.sc_pc;  // SC_PC: MIPS specific
#elif defined(__arm__) // gcc specific
	caller_address = (void *)uc->uc_mcontext.arm_pc;  // ARM_PC: ARM specific
#else
#error Unsupported architecture. // TODO: Add support for other arch.
#endif

	/*
	 * Reported with fprintf, not with the VEE Port logger: this runs in a signal handler, where
	 * the message pool of the logger and its backends are not async-signal-safe.
	 */
	(void)fprintf(stdout, "signal %d (%s), address is %p from %p\n",
	              sig_num, strsignal(sig_num), info->si_addr,
	              (void *)caller_address);

#ifndef __UCLIBC__
	size = backtrace(array, 50);

	/* overwrite sigaction with caller's address */
	array[1] = caller_address;

	/* skip first stack frame (points here) */
	if (size > 1) {
		backtrace_symbols_fd(&array[1], size - 1, STDOUT_FILENO);
	}

#else
	//uClibc does not manage backtrace* functions.
	(void)fprintf(stdout, "[bt]: %p\n", caller_address);
#endif

	LLMJVM_dump();

	_exit(EXIT_FAILURE);
}

static void microej_core_engine_dump_hdlr(int sig_num, siginfo_t *info, void *ucontext) {
	(void)sig_num;
	(void)info;
	(void)ucontext;
	LLMJVM_dump();
}

static int microej_signal_handler_init(int signum, void (*handler)(int, siginfo_t *, void *)) {
	struct sigaction sigact = { 0 };

	int result = sigemptyset(&sigact.sa_mask);
	if (0 == result) {
		sigact.sa_sigaction = handler;
		sigact.sa_flags = SA_RESTART | SA_SIGINFO;
		result = sigaction(signum, &sigact, NULL);
	}

	if (0 != result) {
		(void)fprintf(stderr, "error setting signal handler for %d (%s)\n", signum, strsignal(signum));
	}
	return result;
}

int microej_segfault_handler_init(void) {
	return microej_signal_handler_init(SIGSEGV, crit_err_hdlr);
}

int microej_usr1_signal_handler_init(void) {
	return microej_signal_handler_init(SIGUSR1, microej_core_engine_dump_hdlr);
}

#ifdef __cplusplus
}
#endif
