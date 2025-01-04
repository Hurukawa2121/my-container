CC      = gcc
CFLAGS  = -Wall -Werror -g
LDFLAGS = -lcap -lseccomp

INCLUDES = -I./include

SOURCES_MAIN   = src/main.c src/child.c src/container.c src/resources.c src/userns.c
OBJECTS_MAIN   = $(SOURCES_MAIN:.c=.o)
TARGET_MAIN    = container_app

SOURCES_TEST   = test/main.c test/resources.c
OBJECTS_TEST   = $(SOURCES_TEST:.c=.o)
TARGET_TEST    = test_app

.PHONY: all clean test

all: $(TARGET_MAIN) $(TARGET_TEST)

$(TARGET_MAIN): $(OBJECTS_MAIN)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TARGET_TEST): $(OBJECTS_TEST) src/resources.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

test: $(TARGET_TEST)
	./$(TARGET_TEST)

clean:
	rm -f $(OBJECTS_MAIN) $(TARGET_MAIN)
	rm -f $(OBJECTS_TEST)  $(TARGET_TEST)
