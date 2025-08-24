# Makefile 

CC = gcc

OPTIMIZATION_FLAGS = -O3 -march=native -mavx2 -mfma -flto -static
WARNING_FLAGS = -Wall -Wextra
LINKER_FLAGS = -pthread -lm

CFLAGS = $(OPTIMIZATION_FLAGS) $(WARNING_FLAGS) $(LINKER_FLAGS)

TARGET = HashNyx

CRACKER_SRCS = HashNyx.c HashNyx_thread.c utils.c wandian.c bloom.c md5_avx2.c sha1_avx2.c sha256_avx2.c ripemd160_avx2.c keccak_avx2.c hash_set.c
CRACKER_OBJS = $(CRACKER_SRCS:.c=.o)

BLOOM_TOOL = HashNyx_bloom
BLOOM_TOOL_SRCS = HashNyx_bloom.c bloom.c utils.c
BLOOM_TOOL_OBJS = $(BLOOM_TOOL_SRCS:.c=.o)

.PHONY: all clean tools

all: $(TARGET)

tools: $(BLOOM_TOOL)

$(TARGET): $(CRACKER_OBJS)
	$(CC) $(OPTIMIZATION_FLAGS) $(LINKER_FLAGS) -o $@ $^ && rm -f $(CRACKER_OBJS)

$(BLOOM_TOOL): $(BLOOM_TOOL_OBJS)
	$(CC) $(OPTIMIZATION_FLAGS) $(LINKER_FLAGS) -o $@ $^ && rm -f $(BLOOM_TOOL_OBJS)

%.o: %.c
	$(CC) $(OPTIMIZATION_FLAGS) $(WARNING_FLAGS) -pthread -c -o $@ $<

clean:
	rm -f $(TARGET) $(BLOOM_TOOL) $(CRACKER_OBJS) $(BLOOM_TOOL_OBJS)
