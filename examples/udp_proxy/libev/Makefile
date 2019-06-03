TARGET = libev.so

SRCS = ev.c event.c
OBJS = $(SRCS:.c=.o)

EVINCPATH = `pwd`/include/
EVLIBPATH = `pwd`/lib/

CC = gcc
INCLUDES = -I.
LIBS = -L.
CFLAGS = -g -O2 -DHAVE_CONFIG_H -MT ev.lo -MD -MP -MF .deps/ev.Tpo -fPIC -DPIC
LDFLAGS = -shared  -fPIC -DPIC  -lm -O2
#gcc -DHAVE_CONFIG_H -I. -g -O3 -MT ev.lo -MD -MP -MF .deps/ev.Tpo -c ev.c  -fPIC -DPIC -o .libs/ev.o

#gcc -DHAVE_CONFIG_H -I. -g -O3 -MT event.lo -MD -MP -MF .deps/event.Tpo -c event.c  -fPIC -DPIC -o event.o

#libtool: link: gcc -shared  -fPIC -DPIC  .libs/ev.o .libs/event.o   -lm  -O3   -Wl,-soname -Wl,libev.so.4 -o .libs/libev.so.4.0.0
#libtool: link: (cd ".libs" && rm -f "libev.so.4" && ln -s "libev.so.4.0.0" "libev.so.4")
#libtool: link: (cd ".libs" && rm -f "libev.so" && ln -s "libev.so.4.0.0" "libev.so")
#libtool: link: ar cru .libs/libev.a  ev.o event.o

$(TARGET) : $(OBJS)
	$(CC) $(LDFLAGS) $^ $(INCLUDES) $(LIBS) -o $@
	ar cru libev.a  $^
	cp -f ev.h $(EVINCPATH)
	cp -f libev.a $(EVLIBPATH)

%.o : %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

.PHONY : clean
clean:
	rm -rf ./lib/* ./include/*
	rm -rf $(OBJS) libev.so libev.a $(TARGET)
