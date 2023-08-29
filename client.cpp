#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string>
#include <iostream>
#include <mutex>
#include <thread>



#include <arpa/inet.h>

#define PORT "3490" // the port client will be connecting to 

#define MAXDATASIZE 1024 // max number of bytes we can get at once 

using namespace std;

mutex print_mtx;
bool exit_flag = false;

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void client_print(string msg){
	print_mtx.lock();
	cout << msg << endl;;
	print_mtx.unlock();
}

void send_msg(int socket_fd){
	string userInput;
	while(1){
		//client_print("You: ");
		getline(std::cin, userInput);
		send(socket_fd, userInput.c_str(), userInput.length(),0);
		if(strcmp(userInput.c_str(),"#quit")==0){  
			close(socket_fd);
			exit_flag = true;
            exit(0);
		}
	}
}

void recv_msg(int socket_fd){
	char msg[MAXDATASIZE];
    while (1){
		memset(msg, 0, sizeof(msg));

        int str_len = recv(socket_fd, msg, MAXDATASIZE, 0);
        if (str_len == -1 && !exit_flag){
			//client_print("ERROR: server closed unexpectedly\n");
            exit(-1);
        }
		client_print(msg);
    }
}

int main(int argc, char *argv[])
{
	int sockfd;  
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
    string  hostname, port, request, username;
       
       
    hostname = argv[1];
	port =  argv[2];
	username = argv[3];
       
    printf("logged in as %s, trying to connect ...\n",username.c_str());
       

       
	if(argc != 4) {
	    fprintf(stderr,"input format: ./server server_ip server_port username\n");
	    exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(hostname.data(), port.data(), &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("client: connect");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s on port %s \n", s,port.c_str());

	freeaddrinfo(servinfo); // all done with this structure

	send(sockfd, username.data(), username.size(),0);
	client_print("============= Welcome to the chatroom ===============\n");
	memset(buf, '\0', MAXDATASIZE);

	string response;
	thread snd(send_msg, sockfd);
    thread rcv(recv_msg, sockfd);
    
    snd.join();
    rcv.join();
    
    close(sockfd);

	return 0;
}

