.PHONY: clean all

CC = g++
BIN_DIR = ./bin
SRC_DIR = ./src
INCLUDE_DIR = ./include
OBJ_DIR = ./obj
THIRD_PARTY_DIR = ./third_party
THIRD_INCLUDE_DIR = $(THIRD_PARTY_DIR)/include
THIRD_LIB_DIR = $(THIRD_INCLUDE_DIR)/libs
CFLAGS = -Wall -std=c++20 -I $(INCLUDE_DIR) -I $(THIRD_INCLUDE_DIR)
LDFLAGS = -L$(THIRD_LIB_DIR) -lbotan-3
DEBUG_FLAGS = -g -D _DEBUG -O0

COMPILE_MODE ?= debug
LD_MODE ?= dynamic
ifeq ($(COMPILE_MODE), release)
	DEBUG_FLAGS = -fwhole-program -flto -O2
endif

ifeq ($(LD_MODE), static)
	LD_MODE += -static
endif

TARGET = botan_client
SRC_FILES = $(shell find $(SRC_DIR) -name '*.cc')
OBJ_FILES = $(patsubst %.cc, %.o, $(SRC_FILES))


all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	@mkdir -p $(BIN_DIR)
	$(CC) $(patsubst %.o, $(OBJ_DIR)/%.o, $^) -o $(BIN_DIR)/$(TARGET) $(CFLAGS) $(DEBUG_FLAGS) $(LDFLAGS)

#asymmetric/rsa.o: $(SRC_DIR)/$@.cc
#	@mkdir -p $(OBJ_DIR)/$(dir $<)
#	$(CC) -o $(OBJ_DIR)/$@ $(CFLAGS) $(DEBUG_FLAGS) -c $<

%.o: %.cc
	@mkdir -p $(OBJ_DIR)/$(dir $<)
	$(CC) -o $(OBJ_DIR)/$@ $(CFLAGS) $(DEBUG_FLAGS) -c $<

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)