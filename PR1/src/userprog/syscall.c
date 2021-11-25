#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "process.h"
#include "pagedir.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  //by systemm call number
  int syscallNum = *(uint32_t*)(f->esp);
  
  //case SYS_HALT:
  if(syscallNum == 0)
	halt(); /* Halt the operating system. */
  //case SYS_EXIT:
  else if(syscallNum ==1){
		accessingUserMemory(f->esp+4);
		exit(*(uint32_t*)(f->esp+4));	/* Terminate this process. */
  }
  //case  SYS_EXEC:
  else if(syscallNum == 2){
		accessingUserMemory(f->esp+4);
        f->eax = exec((const char*)*(uint32_t*)(f->esp+4)); /* Start another process. */
  }
  //case SYS_WAIT:
  else if(syscallNum ==3){
		accessingUserMemory(f->esp+4);
		f->eax = wait((tid_t)*(uint32_t*)(f->esp+4)); /* Wait for a child process to die. */
  }
  //case SYS_CREATE:
  else if(syscallNum ==4){
    /* Create a file. */
  }
  //case SYS_REMOVE:
  else if(syscallNum ==5){
		/* Delete a file. */
  }
  //case SYS_OPEN:
   else if(syscallNum ==6){
			/* Open a file. */
   }
  //SYS_FILESIZE:
  else if(syscallNum ==7){
 		/* Obtain a file's size. */
  }
  //SYS_READ
  else if(syscallNum ==8){
		for(int k = 0 ;k <3; k ++)
			accessingUserMemory(f->esp+20+k);
		read((int)*(uint32_t*)(f->esp+20), (void*)*(uint32_t*)(f->esp+24),(unsigned)*((uint32_t*)(f->esp+28)));
        /* Read from a file. */
	}
  //SYS_WRITE
  else if(syscallNum ==9){
		accessingUserMemory(f->esp+4);
		f->eax = write((int)*(uint32_t*)(f->esp+20), (void*)*(uint32_t*)(f->esp+24), (unsigned)*((uint32_t*)(f->esp+28)));
	/* Write to a file. */
  }
  //case SYS_SEEK:
  else if(syscallNum ==10){
  /* Change position in a file. */
  }
  //case SYS_TELL:
  else if(syscallNum ==11){
		/* Report current position in a file. */
  }
  //case SYS_CLOSE:  
  else if(syscallNum ==12){
		/* Close a file. */
  }
 
  /* Project 3 and optionally project 4. */
  //case SYS_MMAP:
  else if(syscallNum ==13){
			/* Map a file into memory. */
  }
  //case SYS_MUNMAP: 
  else if(syscallNum ==14){
			/* Remove a memory mapping. */
  }
  /* Project 4 only. */
  //case SYS_CHDIR: 
  else if(syscallNum ==15){
		/* Change the current directory. */
  }
  //case SYS_MKDIR: 
  else if(syscallNum ==16){
				/* Create a directory. */
  }
  //case SYS_READDIR: 
  else if(syscallNum ==17){
  /* Reads a directory entry. */
  }
  //case SYS_ISDIR: 
  else if(syscallNum ==18){
		/* Tests if a fd represents a directory. */
  }
  //case SYS_INUMBER: 
  else if(syscallNum ==19){
			/* Returns the inode number for a fd. */
  }
  //case SYS_FIBO
  else if(syscallNum ==20){
		accessingUserMemory(f->esp+4);
		//printf("fibo in \n");
		f->eax = fibonacci(*(int*)(f->esp+4));
		
  }
  //case SYS_MAX_OF_FOUR_INT 
  else if(syscallNum ==21){
		for(int k = 0; k<4;k++)
			accessingUserMemory(f->esp+24+4*k);
		//printf("Max handler %p\n", f->esp);
		//hex_dump((f->esp),(f->esp), 200, 1);
		f->eax = max_of_four_int(*(int*)(f->esp+24), *(int*)(f->esp+28), *(int*)(f->esp+32), *(int*)(f->esp+36));
  }
  
  //printf ("system call!\n");
  //thread_exit ();
}

void accessingUserMemory(const void *vaddr)
{
	//check pointer to kernel address space
	if(!is_user_vaddr(vaddr))
		exit(-1);
	else
	{
		//check unmapped virtual memory
		struct thread *cur = thread_current();
		if(pagedir_get_page(cur->pagedir, vaddr)==NULL)
			exit(-1);

	}

}

void halt(void)
{
	shutdown_power_off();
}

void exit(int status)
{
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_current()->exit_status = status;
	thread_exit();
}

pid_t exec(const char* cmd_line)
{
	return process_execute(cmd_line);
}

int wait(pid_t pid)
{
	return process_wait(pid);
}
int read(int fd, void* buffer, unsigned size)
{
	int i = 0 ;
	bool termi = false;
	//STDIN
	if(fd == 0)
	{
		for(i = 0 ; i < size;i++)
		{
			if(((char*)buffer)[i] == '\0')
			{
				termi = true;
				break;
			}
		}
	}

	if(termi)
		return i;
	else
		return size;
}

int write(int fd, const void* buffer, unsigned size)
{
	//STDOUT
	if(fd == 1)
	{
		putbuf((char*)buffer, size);
		return size;
	}
	return -1;
}

int fibonacci(int n)
{
	if(n<=2)
		return 1;
	else
		return (fibonacci(n-1) + fibonacci(n-2) );
}

int max_of_four_int(int a, int b, int c, int d)
{
	//printf("%d %d %d %d\n", a,b,c,d);
	int max = 0;
	max = a;
	
	//a&b comparison
	if(a<b)
		max = b;
	//max(a,b) & c comparison
	if(max<c)
		max = c;
	//max(a,b,c) & d comparison
	if(max < d)
		max = d;
	
	return max;
}
