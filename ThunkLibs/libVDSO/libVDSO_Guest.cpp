
/*
$info$
tags: thunklibs|VDSO
desc: Linux VDSO thunking
$end_info$
*/

#include <stdio.h>
#include <cstring>

#include <sched.h>
#include <sys/time.h>
#include <time.h>

#include "common/Guest.h"

#include "thunks.inl"
#include "function_packs.inl"
#include "function_packs_public.inl"

extern "C" {
time_t __vdso_time(time_t *tloc) __attribute__((alias("fexfn_pack_time")));
int __vdso_gettimeofday(struct timeval *tv, struct timezone *tz) __attribute__((alias("fexfn_pack_gettimeofday")));
int __vdso_clock_gettime(clockid_t, struct timespec *) __attribute__((alias("fexfn_pack_clock_gettime")));
int __vdso_clock_getres(clockid_t, struct timespec *) __attribute__((alias("fexfn_pack_clock_getres")));
int __vdso_getcpu(uint32_t *, uint32_t *) __attribute__((alias("fexfn_pack_getcpu")));
}