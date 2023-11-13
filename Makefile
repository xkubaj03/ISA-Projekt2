# VUT FIT ISA Projekt DNS Resolver
# Autor: Josef Kuba
# Login: xkubaj03
CC=g++
CFLAGS=-pedantic -Wall -Wextra -g -std=c++11
LDFLAGS=-lpcap
NAME=dns
SRC=$(wildcard src/*.cpp)
HDR=$(wildcard include/*.hpp)
OBJ=$(SRC:.cpp=.o)

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	-rm -f src/*.o

%.o: %.cpp $(HDR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-rm -f $(NAME) $(OBJ)