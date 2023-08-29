CXX = g++
COMPILERFLAGS = -g -Wall -Wextra -Wno-sign-compare -pthread -std=c++11


SERVEROBJECTS = obj/server.o
CLIENTOBJECTS = obj/client.o

.PHONY: all clean

all : obj server client

server: $(SERVEROBJECTS)
	$(CXX) $(COMPILERFLAGS) $^ -o $@ 

client: $(CLIENTOBJECTS)
	$(CXX) $(COMPILERFLAGS) $^ -o $@

clean :
	$(RM) obj/*.o server client

obj/%.o: src/%.cpp
	$(CXX) $(COMPILERFLAGS) -c -o $@ $<
obj:
	mkdir -p obj
