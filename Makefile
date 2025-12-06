# Makefile for http_downloader
CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -pedantic -std=c11
LDFLAGS := -lssl -lcrypto -lpthread

TARGET  := http_downloader
SRC     := http_downloader.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) part_* *.o *.a *.tar.xz *.svg *.jpg

