CC=g++
CFLAGS=-pedantic -Wall -Wextra -g -std=c++11
LDFLAGS=-lpcap
NAME=dns

all: $(NAME)

$(NAME): $(NAME).cpp
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	-rm -f $(NAME)