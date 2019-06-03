TARGET = udp_proxy

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

CC = gcc
INCLUDES = -I./libev/include
LDFLAGS = -L./libev/lib -lev -lm -lpthread
CFLAGS = -g -Wall -O2

$(TARGET) : $(OBJS)
	$(CC) $^ $(LDFLAGS) $(LIBS) -o $@

%.o : %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

.PHONY : clean
clean:
	rm -rf $(OBJS) $(TARGET)
