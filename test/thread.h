
#include <stdint.h>
#include <errno.h>

#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <rpmalloc.h>

#ifdef __cplusplus
extern "C" {
#endif

struct thread_arg {
	int (*fn)(void*);
	void* arg;
};
typedef struct thread_arg thread_arg;

extern void assert_expected(size_t res, size_t expected, const char *file, unsigned int line, const char *expr, const char *expected_str);

#define CHK_EXPECTED(a, b) assert_expected(a, b, __FILE__, __LINE__, #a, #b)

extern uintptr_t
thread_run(thread_arg* arg);

extern void
thread_exit(uintptr_t value);

extern uintptr_t
thread_join(uintptr_t handle);

extern void
thread_sleep(int milliseconds);

extern void
thread_yield(void);

#ifdef __cplusplus
}
#endif
