CC = gcc
OBJS = Server.c
TARGET = server

#compile and execute
all: $(TARGET) EXE

.PHONY : all

$(TARGET) : $(OBJS)
	$(CC) $(OBJS) -o $@ -lcrypto -lssl
	
EXE : $(TARGET)
	./$(TARGET) $(PORT)
	
#clean all object files and executable file TARGET
.PHONY: clean

clean:
	rm -f *.o
	rm -f $(TARGET)
	
#debug
.PHONY: debug

debug: $(OBJS)
	$(CC) -g $(OBJS) -lcrypto -lssl

	
	
