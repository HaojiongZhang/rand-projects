#include <iostream>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <string>
#include <mutex>
#include <unordered_set>




#define MAX_LEN 1024
#define MAXDATASIZE 1000
#define BACKLOG 10	 // how many pending connections queue will hold

using namespace std;

mutex broadcast_mtx; 
mutex client_mtx;
mutex print_mtx;
vector<pair<int, string>> clientList;





void broadcast(string msg, int sender_fd);
void server_print(string msg);
int remove_client(int target_fd);


void sigchld_handler(int s)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void server_print(string msg){
		//lock_guard<mutex> guard(print_mtx);
		cout << msg;
}

class ThreadPool {
public:
	

    ThreadPool(int numThreads) : stop_(false) {
        for (int i = 0; i < numThreads; ++i) {
            threadPool_.emplace_back(&ThreadPool::workerThread, this);
        }
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            stop_ = true;
        }

        condition_.notify_all();

        for (auto& thread : threadPool_) {
            thread.join();
        }
    }

    void addClientSocket(int clientSocket) {
        std::unique_lock<std::mutex> lock(queueMutex_);
        clientQueue_.push(clientSocket);
        condition_.notify_one();
    }

	void add_client(int client_fd, string client_name){
		client_mtx.lock();
		clientList.push_back(make_pair(client_fd, client_name));
		client_mtx.unlock();
	}

	int handleSocket(int socket_fd){

		// intializing client data
		char name[MAX_LEN],msg[MAX_LEN];
		recv(socket_fd,name,sizeof(name),0);
		add_client(socket_fd, name);

		string greeting_msg=string(name)+string(" has joined");
		broadcast(greeting_msg, socket_fd);
		
		string user_msg;
		while(1){
			memset(msg, 0, sizeof(msg));
			if( recv(socket_fd,msg,sizeof(msg),0) <= 0){
				string err_msg = string("Error: ") + name + string(" has quit unexpectedly\n");
				server_print(err_msg);
				return -1;
			}


			if(strcmp(msg,"#quit")==0){  				//user disconnect
				string leave_msg = string(name) + string(" has left the chatroom\n");
				broadcast(leave_msg, socket_fd);
				server_print(leave_msg);
				remove_client(socket_fd);
				break;
			}else{
				user_msg = name + string(": ") + (string)msg;
				broadcast(user_msg, socket_fd);
			}
		}
		
		return 0;
	}

	

	void broadcast(string msg, int sender_fd){
		broadcast_mtx.lock();
		for(auto it : clientList){
			if(it.first != sender_fd){
				send(it.first, msg.c_str(), msg.length(), 0);
			}
		}
		broadcast_mtx.unlock();
		
	}

	int remove_client(int target_fd){

		client_mtx.lock();
		string client_name;
		auto it = std::find_if(clientList.begin(), clientList.end(),
							[target_fd](const std::pair<int, std::string>& p) {
								return p.first == target_fd;
							});

		if (it != clientList.end()) {
			client_name = it->second;
			clientList.erase(it);
		} else {
			return -1;
		}
		close(target_fd); // Close the client socket when done
		client_mtx.unlock();
		return 1;
	}

private:
    void workerThread() {
        while (true) {
            int clientSocket = -1;

            {
                std::unique_lock<std::mutex> lock(queueMutex_);
                condition_.wait(lock, [this]() { return stop_ || !clientQueue_.empty(); });

                if (stop_ && clientQueue_.empty()) {
                    return;
                }

                clientSocket = clientQueue_.front();
                clientQueue_.pop();
            }

            // ... handle client communication ...
			handleSocket(clientSocket);
			
        }
    }

    std::vector<std::thread> threadPool_;
    std::queue<int> clientQueue_;
    std::mutex queueMutex_;
    std::condition_variable condition_;
    bool stop_;
};

int main(int argc, char *argv[]) {

	if(argc != 3) {
	    fprintf(stderr,"input format: ./server port roomsize\n");
	    exit(1);
	}


    int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;
	string portnum,response, filepath;

	portnum = argv[1];
    int numThreads = 10;
	try {
        numThreads = stoi(argv[2]);
    	
    } catch (const std::exception& e) {
            server_print("room size defaulted to 10!\n");
    }
	ThreadPool threadPool(numThreads);


	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, argv[1], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (::bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		return 2;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}
	struct sockaddr_in localAddress;
    socklen_t addrLen = sizeof(localAddress);
    getsockname(sockfd, (struct sockaddr*)&localAddress, &addrLen);

    // Convert the binary IP address to a string
    char ipBuffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(localAddress.sin_addr), ipBuffer, INET_ADDRSTRLEN);

    // Print the IP address and port
    std::cout << "Server is running on IP address: " << ipBuffer << ", port: " << ntohs(localAddress.sin_port) << std::endl;


	printf("server: waiting for connections...\n");

	string server_msg;
	while(1) {  // main accept() loop
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),
			s, sizeof s);

		server_msg = "Server: got connection from " + (string)s + "\n";
		server_print(server_msg);

		if(clientList.size() <= numThreads){
			server_print("Server: added to threadpool");
			threadPool.addClientSocket(new_fd);
		}else{
			server_msg = "Server: chatroom is full, disconnecting connection!\n";
			server_print(server_msg);
			send(new_fd, server_msg.c_str(), server_msg.length()+1, 0);
		}
		
	}

	
    return 0;
}
