#ifndef _NETIOWRAP_H
#define _NETIOWRAP_H

#include <config.h>
#include <sys/types.h>

int Send(const void *buf, size_t len, int flags);
int Recv(void *buf, size_t len, int flags);

#endif
