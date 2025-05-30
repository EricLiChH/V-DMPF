CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS = -lssl -lcrypto

# Directories
SRCDIR = src
INCDIR = include
OBJDIR = obj

# Source files
SOURCES = $(SRCDIR)/dpf.c $(SRCDIR)/dmpf.c $(SRCDIR)/common.c $(SRCDIR)/mmo.c
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Test program
TEST_TARGET = test_dmpf
TEST_SOURCE = test_dmpf.c

# Default target
all: $(TEST_TARGET)

# Create object directory
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Compile object files
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

# Build test program
$(TEST_TARGET): $(OBJECTS) $(TEST_SOURCE) | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(INCDIR) $(TEST_SOURCE) $(OBJECTS) -o $@ $(LDFLAGS)

# Clean build files
clean:
	rm -rf $(OBJDIR)
	rm -f $(TEST_TARGET)

# Run tests
test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TEST_TARGET)

.PHONY: all clean test debug 