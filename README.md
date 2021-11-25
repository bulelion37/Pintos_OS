Pintos Project (Operating System)
====================

This codes consist of 4 folder. 
-------------------------------

### 1. Project 1
##### Establish a Pintos environment that can run the User Program.
##### Implement the system call function of halt, wait, exit, exit, read(stdin), write(stdout), fibonacci, max_of_our_int.
##### Implement a function that prevents the user program from accessing invalid memory areas (Kernel address space, Unmapped virtual memory, null pointer).

### 2. Project 2
##### Implement system calls related to file systems of Create, Remove, Open, Close, Filesize, Read, Write, See, and Tell.
##### If one process is within a critical section, implement Synchronization that prevents other processes from entering the critical section

### 3. Project 3
##### Implemented as busy-waiting so that inefficient Alarm Clock can be operated in a way that does not use busy-waiting.
##### Priority scheduling is implemented so that scheduling can be performed in consideration of the priority of threads.
##### If the priority scheduling is performed, a process with low priority may cause starvation in which the priority is not scheduled, so aging is implemented to prevent this.

### 4. Project 4
##### Make Pintos program that can respond appropriately and stably, not ended by Page Fault. 
##### Implement Disk Swap so that pages can be swapped out and swapped in if there are insufficient physical memory to allocate to the process.
##### Implement a stack growth to deal with page faults occurring at addresses corresponding to stack access.
