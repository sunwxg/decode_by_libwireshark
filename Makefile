WIRESHARK_VERSION=2.4.4

CFLAGS+= -std=c99 -g -Wall
CFLAGS+= `pkg-config --cflags glib-2.0`
CFLAGS+= -I./wireshark-2.4.4
#CFLAGS+= -I/usr/include
#CFLAGS+= -I./
#CFLAGS+= -I./include
#CFLAGS+= -I./include/wireshark
#CFLAGS+= -I./include/wireshark/wiretap
#LDFLAGS= -L./libs
LDFLAGS= -lwiretap -lwireshark -lwsutil -lglib-2.0
#LDFLAGS+= -Wl,-rpath,./libs

TARGET=myshark
SRC=$(wildcard *.c)

default:
	@gcc ${CFLAGS} -o ${TARGET} ${SRC} ${LDFLAGS}

source:
	wget https://www.wireshark.org/download/src/wireshark-${WIRESHARK_VERSION}.tar.xz
	tar xvf wireshark-${WIRESHARK_VERSION}.tar.xz
	@rm wireshark-${WIRESHARK_VERSION}.tar.xz
	@cp wireshark-${WIRESHARK_VERSION}/frame_tvbuff.c .

.PHONY: clean

clean:
	@rm -rf myshark .libs

