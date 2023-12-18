TARGET = client
CC = gcc
CFLAGS = -Wall -Wextra -pedantic

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
