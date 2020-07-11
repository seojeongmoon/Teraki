CC = gcc
OBJS = Server.c
TARGET = server

#compile and execute
all: $(TARGET) EXE

.PHONY : all

$(TARGET) : $(OBJS)
	$(CC) -o $@ $(OBJS)
	
EXE : $(TARGET)
	./$(TARGET)
	
#clean all object files and executable file TARGET
.PHONY: clean

clean:
	rm -f *.o
	rm -f $(TARGET)
	
#debug
.PHONY: debug

debug: $(OBJS)
	$(CC) -o -d $@ $(OBJS)

	
	
