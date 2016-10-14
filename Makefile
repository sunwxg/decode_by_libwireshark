CFLAGS+= -std=c99 -g -Wall
CFLAGS+= `pkg-config --cflags glib-2.0`
CFLAGS+= -I./include/wireshark
CFLAGS+= -I./include/wireshark/wiretap
CFLAGS+= -I./include
LDFLAGS= -L./libs -lwiretap -lwireshark -lwsutil -lglib-2.0
LDFLAGS+= -Wl,-rpath,./libs

TARGET=myshark
SRC=$(wildcard *.c)

SRC_WIRESHARK?=~/person/wireshark-1.12.8

default:
	@gcc ${CFLAGS} -o ${TARGET} ${SRC} ${LDFLAGS}

debug:
	@libtool --silent --tag=CC --mode=link \
	gcc ${CFLAGS} ${INCLUDE} -o ${TARGET} ${SRC} \
	${SRC_WIRESHARK}/epan/libwireshark.la \
	${SRC_WIRESHARK}/wiretap/libwiretap.la \
	-lwsutil -lglib-2.0

.PHONY: clean

clean:
	@rm -rf myshark .libs

