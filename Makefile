#DEBUG_BUILD = yes
BIN = c_ipv6_helper
RM = rm
CC = gcc

CFLAGS = -Wall -Werror -Wextra 

DBGBLD = DEBUG_BUILD
ifdef $(DBGBLD)
CFLAGS += -g
else
CFLAGS += -O3
endif

src = $(wildcard *.c)
obj = $(src:.c=.o)

c_ipv6_helper: $(obj)
	$(CC) $^ -o $(BIN) 

%.o: %.c
	$(CC) $(CFLAGS) -c $<

.PHONY : clean
clean:
	$(RM) -f $(BIN) a.out *~ *.o
