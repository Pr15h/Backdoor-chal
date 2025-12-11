CC = gcc
CFLAGS = -static -O0 -g
SRCS = main_with_jit.c bytecode_builder.c magic_expand.c vm.c jit.c
TARGET = crackme
LDLIBS = -lcrypto

all: run

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDLIBS)

strip: $(TARGET)
	strip --strip-all $(TARGET)

run: strip
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all strip run clean
