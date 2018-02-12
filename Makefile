WIRESHARK_VERSION=2.4.4

CFLAGS+= -std=c99 -g -Wall
CFLAGS+= `pkg-config --cflags glib-2.0`
CFLAGS+= -I./wireshark-${WIRESHARK_VERSION}
CFLAGS+= -I./
LDFLAGS= -lwiretap -lwireshark -lwsutil -lglib-2.0
#LDFLAGS+= -Wl,-rpath,./libs

TARGET=myshark
SRC=$(wildcard *.c)

default:
	@gcc ${CFLAGS} -o ${TARGET} ${SRC} ${LDFLAGS}

source:
	wget https://www.wireshark.org/download/src/all-versions/wireshark-${WIRESHARK_VERSION}.tar.xz
	tar xf wireshark-${WIRESHARK_VERSION}.tar.xz
	@rm wireshark-${WIRESHARK_VERSION}.tar.xz
	@cp wireshark-${WIRESHARK_VERSION}/frame_tvbuff.c .

.PHONY: clean

clean:
	@rm -rf myshark

