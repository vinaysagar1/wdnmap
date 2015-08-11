# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	= wd_nmap

CLEANFILES = $(PROGS) *.o
NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(NMAP_SRC)/sys # -I/home/luigi/FreeBSD/head/sys -I../sys
CFLAGS += -Wextra
CFLAGS += -DNO_PCAP

LDFLAGS += -lpthread
LDFLAGS += -lrt	# needed on linux, does not harm on BSD

all: $(PROGS)

wd_nmap: wd_nmap.o
	$(CC) $(CFLAGS) -o wd_nmap wd_nmap.o

clean:
	-@rm -rf $(CLEANFILES)
