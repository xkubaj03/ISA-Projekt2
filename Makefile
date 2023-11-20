# VUT FIT ISA Projekt DNS Resolver
# Autor: Josef Kuba
# Login: xkubaj03
CC=g++
CFLAGS=-pedantic -Wall -Wextra -g -std=c++14
LDFLAGS=-lpcap
NAME=dns
TEST_SRC=$(wildcard tests/*.cpp)
TEST_OBJ=$(patsubst tests/%.cpp,obj/%.o,$(TEST_SRC))
TEST_BIN=$(TEST_OBJ:.o=)

SRC=$(wildcard src/*.cpp)
OBJ=$(patsubst src/%.cpp,obj/%.o,$(SRC))
HDR=$(wildcard include/*.hpp)

.PHONY: all clean test

all: $(NAME) test

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

obj/%.o: src/%.cpp $(HDR)
	@mkdir -p obj
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_BIN)
	@for test in $(TEST_BIN); do \
        ./$$test; \
    done

obj/%.o: tests/%.cpp $(HDR)
	@mkdir -p obj
	$(CC) $(CFLAGS) $(shell pkg-config --cflags gtest) -c $< -o $@

%: obj/%.o
	$(CC) $(CFLAGS) $(shell pkg-config --cflags gtest) $< -o $@ $(LDFLAGS) $(shell pkg-config --libs gtest)

clean:
	-rm -f $(NAME) $(OBJ) $(TEST_BIN)
	-rmdir obj
