/*
 * http-server.c
 */

#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), bind(), and connect() */
#include <sys/wait.h>   /* for wait() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include <time.h>       /* for time() */
#include <netdb.h>      /* for gethostbyname() */
#include <signal.h>     /* for signal() */
#include <sys/stat.h>   /* for stat() */
#include <errno.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <dirent.h>

#define MAXPENDING 5    /* Maximum outstanding connection requests */

#define DISK_IO_BUF_SIZE 4096


/*
 * A data structure to hold request processing statistics.
 */
struct stats {
    sem_t    semaphore;
    uint32_t requests; /* Total number of requests received */
    uint32_t resp_2xx; /* Total number of 2xx responses sent */
    uint32_t resp_3xx; /* Total number of 3xx responses sent */
    uint32_t resp_4xx; /* Total number of 4xx responses sent */
    uint32_t resp_5xx; /* Total number of 5xx responses sent */
};

static int print_stat = 0;
static struct stats *statistics = NULL;

static void die(const char *message)
{
    perror(message);
    exit(1);
}


/*
 * Lock the data structure.
 *
 * This function locks the data structure by calling sem_wait on its
 * semaphore. If the value of the semaphore is 0 then the function blocks.
 */
static void lock(struct stats *s)
{
    int rv;

again:
    rv = sem_wait(&s->semaphore);
    if (rv == -1) {
        if (errno == EINTR) goto again;
        die("Fatal error while locking statistics counters");
    }
}


/*
 * Unlock the data structure.
 *
 * Call sem_post on the data structure's semaphore. The data structure must
 * have been previously locked with lock.
 */
static void unlock(struct stats *s)
{
    int rv;

    rv = sem_post(&s->semaphore);
    if (rv == -1) {
        die("Error while unlocking statistics counters");
    }
}


/*
 * Create a listening socket bound to the given port.
 */
static int createServerSocket(unsigned short port)
{
    int servSock;
    struct sockaddr_in servAddr;

    /* Create socket for incoming connections */
    if ((servSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        die("socket() failed");

    /* Construct local address structure */
    memset(&servAddr, 0, sizeof(servAddr));       /* Zero out structure */
    servAddr.sin_family = AF_INET;                /* Internet address family */
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
    servAddr.sin_port = htons(port);              /* Local port */

    /* Bind to the local address */
    if (bind(servSock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)
        die("bind() failed");

    /* Mark the socket so it will listen for incoming connections */
    if (listen(servSock, MAXPENDING) < 0)
        die("listen() failed");

    return servSock;
}

/*
 * A wrapper around send() that does error checking and logging.
 * Returns -1 on failure.
 *
 * This function assumes that buf is a null-terminated string, so
 * don't use this function to send binary data.
 */
ssize_t Send(int sock, const char *buf)
{
    size_t len = strlen(buf);
    ssize_t res = send(sock, buf, len, 0);
    if (res != len) {
        perror("send() failed");
        return -1;
    }
    else
        return res;
}

/*
 * HTTP/1.0 status codes and the corresponding reason phrases.
 */

static struct {
    int status;
    char *reason;
} HTTP_StatusCodes[] = {
    { 200, "OK" },
    { 201, "Created" },
    { 202, "Accepted" },
    { 204, "No Content" },
    { 301, "Moved Permanently" },
    { 302, "Moved Temporarily" },
    { 304, "Not Modified" },
    { 400, "Bad Request" },
    { 401, "Unauthorized" },
    { 403, "Forbidden" },
    { 404, "Not Found" },
    { 500, "Internal Server Error" },
    { 501, "Not Implemented" },
    { 502, "Bad Gateway" },
    { 503, "Service Unavailable" },
    { 0, NULL } // marks the end of the list
};

static inline const char *getReasonPhrase(int statusCode)
{
    int i = 0;
    while (HTTP_StatusCodes[i].status > 0) {
        if (HTTP_StatusCodes[i].status == statusCode)
            return HTTP_StatusCodes[i].reason;
        i++;
    }
    return "Unknown Status Code";
}


/*
 * Send HTTP status line followed by a blank line.
 */
static void sendStatusLine(int clntSock, int statusCode)
{
    char buf[1000];
    const char *reasonPhrase = getReasonPhrase(statusCode);

    // print the status line into the buffer
    sprintf(buf, "HTTP/1.0 %d ", statusCode);
    strcat(buf, reasonPhrase);
    strcat(buf, "\r\n");

    // We don't send any HTTP header in this simple server.
    // We need to send a blank line to signal the end of headers.
    strcat(buf, "\r\n");

    // For non-200 status, format the status line as an HTML content
    // so that browers can display it.
    if (statusCode != 200) {
        char body[1000];
        sprintf(body,
                "<html><body>\n"
                "<h1>%d %s</h1>\n"
                "</body></html>\n",
                statusCode, reasonPhrase);
        strcat(buf, body);
    }

    /* Increase the corresponding statistics counter */
    lock(statistics);
    if (statusCode >= 200 && statusCode < 300) {
        statistics->resp_2xx++;
    } else if (statusCode >= 300 && statusCode < 400) {
        statistics->resp_3xx++;
    } else if (statusCode >= 400 && statusCode < 500) {
        statistics->resp_4xx++;
    } else if (statusCode >= 500 && statusCode < 600) {
        statistics->resp_5xx++;
    }
    unlock(statistics);

    // send the buffer to the browser
    Send(clntSock, buf);
}


/* Handle a request for the special statistics URL
 * Returns the HTTP status code that was sent to the browser
 */
static int handleStatisticsRequest(
         const char *webRoot, const char *requestURI, int clntSock)
{
    int statusCode;
    static char buf[4096];

    statusCode = 200;
    sendStatusLine(clntSock, statusCode);

    lock(statistics);
    snprintf(buf, sizeof(buf),
"<html><body>\n"
"<h1>Server Statistics</h1>\n"
"<table border=\"1\">\n"
"<tr><td>Requests</td><td>%d</td></tr>\n"
"<tr><td>2xx</td><td>%d</td></tr>\n"
"<tr><td>3xx</td><td>%d</td></tr>\n"
"<tr><td>4xx</td><td>%d</td></tr>\n"
"<tr><td>5xx</td><td>%d</td></tr>\n"
"</table>\n"
"</body></html>\n",
        statistics->requests, statistics->resp_2xx, statistics->resp_3xx,
        statistics->resp_4xx, statistics->resp_5xx);
    unlock(statistics);
    Send(clntSock, buf);
    return statusCode;
}


/*
 * Handle a request for a directory listing
 */
static int handleDirRequest(char *file, int clntSock)
{
    DIR *dir;
    int statusCode;
    static char buf[512];
    struct dirent *ent;

    dir = opendir(file);
    if (dir == NULL) {
        // Return 404 Not Found if the directory cannot be opened
        statusCode = 404;
        sendStatusLine(clntSock, statusCode);
        goto end;
    }

    // Send a 200 OK back to the client
    statusCode = 200;
    sendStatusLine(clntSock, statusCode);

    snprintf(buf, sizeof(buf),
"<html><body>\n"
"<h1>Directory Listing</h1>\n"
"<table border=\"1\">\n");
    Send(clntSock, buf);
    do {
        ent = readdir(dir);
        snprintf(buf, sizeof(buf), "<tr><td>%s</td></tr>\n", ent->d_name);
        Send(clntSock, buf);
    } while (ent != NULL);

    snprintf(buf, sizeof(buf),
"</table></body></html>\n");
    Send(clntSock, buf);

    closedir(dir);
end:
    return statusCode;
}


/*
 * Handle a request for the output of a process
 */
static int handleProcRequest(char *file,  int clntSock)
{
    ssize_t n;
    pid_t pid;
    static char buf[512];
    int statusCode, i, out[2];

    if (pipe(out) != 0)
        die("Cannot create pipe");

    pid = fork();
    if (pid == -1) {
        die("Cannot create child process");
    } else if (pid > 0) {
        close(out[1]);

        // Send a 200 OK back to the client
        statusCode = 200;
        sendStatusLine(clntSock, statusCode);

        // Receive the output of the child via the pipe and send it to the
        // client over the client socket.
        do {
            n = read(out[0], buf, sizeof(buf));
            if (n > 0) {
                if (send(clntSock, buf, n, 0) != n) {
                    // send() failed.
                    // We log the failure, break out of the loop,
                    // and let the server continue on with the next request.
                    perror("\nsend() failed");
                    break;
                }
            }
        } while(n > 0);

        return statusCode;
    }

    // We're in the child process

    // Connect the standard input and output, i.e., file descriptors 0, 1, 2
    // to the pipe by first closing them and then calling dup on the pipe file
    // descriptor. Dup duplicates the file descriptor using the lowest
    // file descriptor number available.
    for(i = 0; i < 3; i++) {
        close(i);
        if (dup(out[1]) != i)
            die("Can't reconnect standard input/output");
    }

    // Replace the current process image with /bin/ls.
    char *args[] = {"ls", "-al", file, NULL};
    if (execv("/bin/ls", args) == -1)
        perror("Cannot execute /bin/ls");
    return 0;
}


/*
 * Handle static file requests.
 * Returns the HTTP status code that was sent to the browser.
 */
static int handleFileRequest(
        const char *webRoot, const char *requestURI, int clntSock)
{
    int statusCode;
    FILE *fp = NULL;

    // Compose the file path from webRoot and requestURI.
    // If requestURI ends with '/', append "index.html".

    char *file = (char *)malloc(strlen(webRoot) + strlen(requestURI) + 100);
    if (file == NULL)
        die("malloc failed");
    strcpy(file, webRoot);
    strcat(file, requestURI);
    if (file[strlen(file)-1] == '/') {
        strcat(file, "index.html");
    }

    // See if the requested file is a directory.
    struct stat st;
    if (stat(file, &st) == 0 && S_ISDIR(st.st_mode)) {
        statusCode = handleDirRequest(file, clntSock);
        goto func_end;
    }

    // If unable to open the file, send "404 Not Found".

    fp = fopen(file, "rb");
    if (fp == NULL) {
        statusCode = 404; // "Not Found"
        sendStatusLine(clntSock, statusCode);
        goto func_end;
    }

    // Otherwise, send "200 OK" followed by the file content.

    statusCode = 200; // "OK"
    sendStatusLine(clntSock, statusCode);

    // send the file
    size_t n;
    char buf[DISK_IO_BUF_SIZE];
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (send(clntSock, buf, n, 0) != n) {
            // send() failed.
            // We log the failure, break out of the loop,
            // and let the server continue on with the next request.
            perror("\nsend() failed");
            break;
        }
    }
    // fread() returns 0 both on EOF and on error.
    // Let's check if there was an error.
    if (ferror(fp))
        perror("fread failed");

func_end:

    // clean up
    free(file);
    if (fp)
        fclose(fp);

    return statusCode;
}


static void sigchldHandler(int sig)
{
   pid_t pid;

    // Keep picking up child return values until there are no more finished
    // children left or until waitpid returns an error.
    while(1) {
        pid = waitpid(-1, NULL, WNOHANG);
        if (pid <= 0)
            break;
    }
}
static void sigusrHandler(int sig){
    print_stat = 1;
}




int main(int argc, char *argv[])
{
    // Ignore SIGPIPE so that we don't terminate when we call
    // send() on a disconnected socket.
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        die("signal() failed");

    if (argc != 3) {
        fprintf(stderr, "usage: %s <server_port> <web_root>\n", argv[0]);
        exit(1);
    }

    // Install a handler for the SIGCHLD signal so that we can pick up return
    // values of children that finished processing their requests.
    if (signal(SIGCHLD, sigchldHandler) == SIG_ERR)
        die("Cannot install SIGCHLD handler");

    unsigned short servPort = atoi(argv[1]);
    const char *webRoot = argv[2];

    /*
    const char *mdbHost = argv[3];
    unsigned short mdbPort = atoi(argv[4]);

    int mdbSock = createMdbLookupConnection(mdbHost, mdbPort);
    FILE *mdbFp = fdopen(mdbSock, "r");
    if (mdbFp == NULL)
        die("fdopen failed");
    */
    struct sigaction sigact;
    if(signal(SIGCHLD,sigchldHandler) == SIG_ERR)
        die("fail to install signal handler");
    sigact.sa_handler = sigusrHandler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    if(sigaction(SIGUSR1,&sigact,NULL) != 0)
        die("fail to install handler");



    int servSock = createServerSocket(servPort);

    statistics = mmap(NULL, sizeof(struct stats), PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANON, -1, 0);
    if (statistics == MAP_FAILED)
        die("Cannot created shared memory statistics");
    if (sem_init(&statistics->semaphore, 1, 1) != 0)
        die("Cannot create statistics semaphore");

    pid_t pid;
    char line[1000];
    char requestLine[1000];
    int statusCode;
    struct sockaddr_in clntAddr;

    for (;;) {

        /*
         * wait for a client to connect
         */

        // initialize the in-out parameter
        unsigned int clntLen = sizeof(clntAddr);
        int clntSock = accept(servSock, (struct sockaddr *)&clntAddr, &clntLen);
        if (clntSock == -1) {
            if (errno == EINTR) {
                // Signal interrupted accept, try again
                if(print_stat == 1){
                    print_stat = 0;
                    lock(statistics);
                    printf("Statistics: Requests: %d 2xx: %d 3xx: %d 4x: %d 5xx: %d\n",statistics->requests,statistics
                            ->resp_2xx,statistics->resp_3xx,statistics->resp_4xx,statistics->resp_5xx);
                    unlock(statistics);
                }
                continue;
            }
            die("accept() failed");
        }

        pid = fork();
        if (pid == -1) {
            die("Error while creating child process");
        } else if (pid > 0) {
            // We're in the parent process after fork. Close the client socket
            // and go back to accept more connections.
            close(clntSock);
            continue;
        }

        /*
         * When we get here, we're in the child process. Here we close the
         * server socket and process and requests received over the client
         * socket. */
        close(servSock);

        FILE *clntFp = fdopen(clntSock, "r");
        if (clntFp == NULL)
            die("fdopen failed");

        /*
         * Let's parse the request line.
         */

        char *method      = "";
        char *requestURI  = "";
        char *httpVersion = "";

        if (fgets(requestLine, sizeof(requestLine), clntFp) == NULL) {
            // socket closed - there isn't much we can do
            statusCode = 400; // "Bad Request"
            goto loop_end;
        }

        char *token_separators = "\t \r\n"; // tab, space, new line
        method = strtok(requestLine, token_separators);
        requestURI = strtok(NULL, token_separators);
        httpVersion = strtok(NULL, token_separators);
        char *extraThingsOnRequestLine = strtok(NULL, token_separators);

        lock(statistics);
        statistics->requests++;
        unlock(statistics);

        // check if we have 3 (and only 3) things in the request line
        if (!method || !requestURI || !httpVersion ||
                extraThingsOnRequestLine) {
            statusCode = 501; // "Not Implemented"
            sendStatusLine(clntSock, statusCode);
            goto loop_end;
        }

        // we only support GET method
        if (strcmp(method, "GET") != 0) {
            statusCode = 501; // "Not Implemented"
            sendStatusLine(clntSock, statusCode);
            goto loop_end;
        }

        // we only support HTTP/1.0 and HTTP/1.1
        if (strcmp(httpVersion, "HTTP/1.0") != 0 &&
            strcmp(httpVersion, "HTTP/1.1") != 0) {
            statusCode = 501; // "Not Implemented"
            sendStatusLine(clntSock, statusCode);
            goto loop_end;
        }

        // requestURI must begin with "/"
        if (!requestURI || *requestURI != '/') {
            statusCode = 400; // "Bad Request"
            sendStatusLine(clntSock, statusCode);
            goto loop_end;
        }

        // make sure that the requestURI does not contain "/../" and
        // does not end with "/..", which would be a big security hole!
        int len = strlen(requestURI);
        if (len >= 3) {
            char *tail = requestURI + (len - 3);
            if (strcmp(tail, "/..") == 0 ||
                    strstr(requestURI, "/../") != NULL)
            {
                statusCode = 400; // "Bad Request"
                sendStatusLine(clntSock, statusCode);
                goto loop_end;
            }
        }

        /*
         * Now let's skip all headers.
         */

        while (1) {
            if (fgets(line, sizeof(line), clntFp) == NULL) {
                // socket closed prematurely - there isn't much we can do
                statusCode = 400; // "Bad Request"
                goto loop_end;
            }
            if (strcmp("\r\n", line) == 0 || strcmp("\n", line) == 0) {
                // This marks the end of headers.
                // Break out of the while loop.
                break;
            }
        }

        /*
         * At this point, we have a well-formed HTTP GET request.
         * Let's handle it.
         */

        if (strcmp(requestURI, "/statistics") == 0) {
            /* A request for the HTTP server's statistics report */
            statusCode = handleStatisticsRequest(webRoot, requestURI, clntSock);
        } else {
            /* Everything else is treated as a file request */
            statusCode = handleFileRequest(webRoot, requestURI, clntSock);
        }

        /*
        char *mdbURI_1 = "/mdb-lookup";
        char *mdbURI_2 = "/mdb-lookup?";

        if (strcmp(requestURI, mdbURI_1) == 0 ||
                strncmp(requestURI, mdbURI_2, strlen(mdbURI_2)) == 0) {
            // mdb-lookup request
            statusCode = handleMdbRequest(requestURI, mdbFp, mdbSock, clntSock);
        }
        else {
            // static file request
            statusCode = handleFileRequest(webRoot, requestURI, clntSock);
        }
        */

loop_end:

        /*
         * Done with client request.
         * Log it, close the client socket.
         */

        fprintf(stderr, "%s (%d) \"%s %s %s\" %d %s\n",
                inet_ntoa(clntAddr.sin_addr),
                getpid(),
                method,
                requestURI,
                httpVersion,
                statusCode,
                getReasonPhrase(statusCode));

        // close the client socket
        fclose(clntFp);

        // We're in the child process and finished processing the request.
        // Terminate the child process.
        exit(EXIT_SUCCESS);
    } // for (;;)

    sem_close(&statistics->semaphore);
    munmap(statistics, sizeof(struct stat));

    return 0;
}
