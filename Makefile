CFLAGS+= -std=c99 -g -Wall
INCLUDE= -I/usr/include/glib-2.0
INCLUDE+= -I/usr/lib/x86_64-linux-gnu/glib-2.0/include
INCLUDE+= -I/usr/include/wireshark -I/usr/include/wireshark/wiretap
INCLUDE+= -I./include
LDFLAGS= -lwiretap -lwireshark -lwsutil -lglib-2.0

TARGET=myshark
SRC=$(wildcard *.c)

SRC_WIRESHARK?=~/person/wireshark-1.12.8

default:
	@gcc ${CFLAGS} ${INCLUDE} -o ${TARGET} ${SRC} ${LDFLAGS}

debug:
	@libtool --silent --tag=CC --mode=link \
	gcc ${CFLAGS} ${INCLUDE} -o ${TARGET} ${SRC} \
	${SRC_WIRESHARK}/epan/libwireshark.la \
	${SRC_WIRESHARK}/wiretap/libwiretap.la \
	-lwsutil -lglib-2.0

.PHONY: clean

clean:
	@rm -rf myshark .libs

