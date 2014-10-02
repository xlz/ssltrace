SOURCES=ssltrace.c openssl.c nss.c gnutls.c
HEADERS=ssltrace.h nssimpl.h
OBJECTS=$(SOURCES:.c=.o)
OUTPUT=ssltrace.so
CFLAGS=-g -fvisibility=hidden -fPIC -Wall -D_GNU_SOURCE -I/usr/include/nspr

all: $(SOURCES) $(HEADERS) $(OUTPUT) Makefile
	
$(OUTPUT): $(OBJECTS)
	$(CC) -shared $(CFLAGS) $(OBJECTS) -o $@ -ldl

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(OUTPUT)
