# Computer_Networks_Project_2
Project 2 - HTTPS Download Accelerator
Instructions
HTTPS download accelerator using "Range" requests

Type of Project: Group of two students (or individual, if preferred)
Language: C
Points: 20 points
Submission: via eLC

Submission Guidelines:
Submit via ELC, as usual. Submit ONLY the source code (e.g., no object files). Include a Makefile, so that the code can be compiled simply by executing make. Also, make sure to name the output of the compiler, i.e., the program file name, as http_downloader. All files need to be under the same main directory called LastNameFirstName-http_downloader (do not create subdirectories). Besides the code and Makefile, the directory should also contain a file called StudentGroup.txt containing the name and email addresses of the students who collaborated on this project. Compress the directory into a tar.gz file called LastNameFirstName-http_downloader.tar.gz and submit it via eLC. Each student will have to submit their own project, even if they worked in a group. However, only one submission per group will actually be evaluated. Students in the same group MUST submit the same version of the code (i.e., identical tar.gz files). 

NOTE: Project submissions that do not follow the guidelines risk to receive 0 points. Please follow the directions closely and ask for clarifications in class, as needed.

Project Description:
In this project, you are required to write a program that takes in input (on the command line) the URL of an object to be downloaded via HTTPS (using HTTP v1.1), and the number of connections through which different parts of the object will be retrieved using the "Range" option. The downloaded parts need to be re-stitched to compose the original file.

Usage: ./http_downloader -u HTTPS_URL -n NUM_PARTS -o OUTPUT_FILE


For example (notice that the line below is an actual example of how your program must be launched)

$ ./http_downloader -u "https://www.tcpdump.org/release/libpcap-1.10.5.tar.xz" -o libpcap.tar.xz -n 5

will open 5 TCP+TLS connections to www.tcpdump.org on port 443, and retrieve the .tar.xz file in 5 parts of approximately equal length. Finally, the program will put the parts together and write the output into a file called libpcap.tar.xz. You should name the files containing the parts of downloaded content as part_i, where i is an index. In the example above, the program will output the parts into 5 different files called part_1, part_2, ..., part_5, along with the reconstructed output file. DO NOT delete the part_i files after you are done recomposing the original file.
Save all downloaded files into the same director ./ from which the program is launched (do not create any subdirs).

To make sure your software downloads and correctly reassembles objects from the web, you can use md5sum to compare your result with the original file downloaded using a browser (or wget or curl), for example.

NOTE: You don't need to worry about handling Server "errors" (e.g., redirections, unavailable Range option, etc.). I will only test your software on objects retrieved from websites that support the Range option, and for which no special error handling is required. Of course, make sure to use HTTP/1.1 and that your HTTPS connection are successful and requests are correctly formatted, otherwise they will fail even the simpler tests.

IMPORTANT: To divide the object to be retrieved into approximately equal parts, you first need to retrieve the length of the object without retrieving the object itself. Notice also that the when the object's total size is not divisible by the number of parts, the last part file (part_n) will need to include all remainder bytes. E.g., given an object of size 10,005 bytes and n=10, the first 9 part files will have size 1000 bytes, while part_10 will have size 1005 bytes.

TESTING YOUR CODE
As an example, you can use the following URLs to test your code:

https://www.tcpdump.org/release/libpcap-1.10.5.tar.xz
https://arxiv.org/static/browse/0.3.4/images/arxiv-logo-one-color-white.svg
https://upload.wikimedia.org/wikipedia/commons/thumb/d/d2/Common_ringed_plover_%28Charadrius_hiaticula%29_Oppdal.jpg/960px-Common_ringed_plover_%28Charadrius_hiaticula%29_Oppdal.jpg
Make sure that when you recompose the output from the different parts, the md5sums matches the md5 digest for the original objects. For example:


a28595037c185df646108c94499d61ca  960px-Common_ringed_plover_(Charadrius_hiaticula)_Oppdal.jpg
3d67f8b17db94a00a05636616fb0489b  libpcap-1.10.5.tar.xz
9b87a633f4532e20a09330a8417ef0db  arxiv-logo-one-color-white.svg

I strongly recommend that you to also test your code on other URLs chosen by yourself, and try to determine if there are any websites that support the Range option but cause problems to your code.

You must open multiple connections in parallel, and let different threads handle each of these parallel connections. To split the download in multiple threads you can use the following functions:

#include <pthread.h>

int pthread_create(pthread_t *restrict thread, const pthread_attr_t *restrict attr, void *(*start_routine)(void*), void *restrict arg);
int pthread_join(pthread_t thread, void **value_ptr);

On your VM, you might need to install make and gcc, if you have not yet done so, using apt install.

To use TLS, you should use the OpenSSL library, which you can install with apt install libssl-dev.

As a hint, the sequence of steps to wrap a TCP socket into a TLS connection can be the following (in pseudo-code steps):

open_client-side_tcp_connection // use socket API -- this is mandatory!
init_ssl_ctx // use OpenSSL library to initialize TLS context
SSL_new // new TLS session
SSL_set_tlsext_host_name  // sets the TLS SNI
SSL_set_fd // wrap the TCP socket descriptor into a TLS session
// Send and receive HTTP/1.1 requests/responses here, using the TLS session
SSL_free // close TLS session
SSL_CTX_free // close TLS context
close // close TCP socket
For details about socket programming in C you may want to refer to this online guide and this textbook: "TCP/IP Sockets in C: Practical Guide for Programmers" by Michael J. Donahoo and Kenneth L. Calvert.

To parse command line arguments you may want to use Getopt.
