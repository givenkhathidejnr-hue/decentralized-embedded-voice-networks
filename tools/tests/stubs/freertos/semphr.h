#pragma once
#include <pthread.h>
#include <stdlib.h>
#include <assert.h>
typedef pthread_mutex_t *SemaphoreHandle_t;
static inline SemaphoreHandle_t xSemaphoreCreateRecursiveMutex(void) {
    SemaphoreHandle_t p=malloc(sizeof(*p)); assert(p);
    pthread_mutexattr_t attr; pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(p,&attr); pthread_mutexattr_destroy(&attr); return p;
}
static inline SemaphoreHandle_t xSemaphoreCreateMutex(void) { return xSemaphoreCreateRecursiveMutex(); }
static inline void xSemaphoreTakeRecursive(SemaphoreHandle_t p,unsigned t) { (void)t; assert(!pthread_mutex_lock(p)); }
static inline void xSemaphoreGiveRecursive(SemaphoreHandle_t p) { assert(!pthread_mutex_unlock(p)); }
#define xSemaphoreTake xSemaphoreTakeRecursive
#define xSemaphoreGive xSemaphoreGiveRecursive
