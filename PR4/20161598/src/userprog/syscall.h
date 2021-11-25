#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "filesys/off_t.h"

typedef int pid_t;

struct file
{
	struct inode *inode;
	off_t pos;
	bool deny_write;
};

struct lock syn_lock;

void syscall_init (void);

void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
int read(int fd, void* buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void accessingUserMemory(const void* vaddr);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

//Additional System Calls
int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);
#endif /* userprog/syscall.h */
