# Linux_Sync_Http_Server
This repo contains a series of different implementations of a http-server by using mechanism including multi-processing, multi-threading, thread-pool, thread-blocking-queue, etc

Multi-processing http server & Interprocess communication through shared memory  (part2,3,4)
simultaneously is to create additional child processes with the fork() system call. Each time a new connection is accepted, instead of processing the request within the same process, we create a new child process by calling fork() and let it handle the request.

Multi-threading http server(part5)
POSIX threads provide a light-weight alternative to child processes. Instead of creating child processes to handle multiple HTTP requests simultaneously, we will create a new POSIX thread for each HTTP request.

Thread-Pool(part6)
Instead of creating a new thread for each new client connection, pre-create a fixed number of worker threads in the beginning. Each of the pre-created worker threads will act like the original skeleton web server – i.e., each thread will be in a for(;;) loop, repeatedly calling accept()

Thread-locking-queue(part7)
Modify the code so that only the main thread calls accept(). The main thread puts the client socket descriptor into a blocking queue, and wakes up the worker threads which have been blocked waiting for client requests to handle
