CC=gcc
CFLAGS=-c -g
LDFLAGS=-lcrypto

SOURCES=main.c aes.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=main

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
		$(CC) $(OBJECTS) $(LDFLAGS) -o $@

.c.o:
		$(CC) $(CFLAGS) -o $@ $<

clean:
		rm -f $(OBJECTS) $(EXECUTABLE)
