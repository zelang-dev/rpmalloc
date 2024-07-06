/* Test program for atomicity from https://en.cppreference.com/w/c/language/atomic */

#include <rpmalloc.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <thread.h>
#include <test.h>

atomic_int acnt = 0;
int cnt = 0;

int f(void *thr_data) {
    (void)thr_data;
    int n;
    for (n = 0; n < 1000; ++n) {
        ++cnt;
        // ++acnt;
        // for this example, relaxed memory order is sufficient, e.g.
        atomic_fetch_add_explicit(i32, &acnt, 1, memory_order_relaxed);
    }
    return 0;
}
#define THREAD_COUNT 10

int main(void) {
    intptr_t thread[THREAD_COUNT];
    thread_arg targ[THREAD_COUNT];
    int i, counter = 1;
    while (1) {
        for (i = 0; i < THREAD_COUNT; ++i) {
            targ[i].fn = f;
            targ[i].arg = NULL;
            /* Start a child thread that modifies gLocalVar */
            thread[i] = thread_run(&targ[i]);
        }

        for (i = 0; i < 10; ++i) {
            thread_join(thread[i]);
        }

        if (acnt != cnt) {
            assert(acnt > cnt);
            break;
        }

        counter++;
    }

    printf("Found atomicity, took %d tries!\n", counter);
    printf("The atomic counter is %u\n", acnt);
    printf("The non-atomic counter is %u\n", cnt);

    return 0;
}
