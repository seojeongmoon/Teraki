CC = gcc
OBJS = Client.c
TARGET = client

#compile and execute
all: $(TARGET) EXE

.PHONY : all

$(TARGET) : $(OBJS)
	$(CC) -o $@ $(OBJS)
	
EXE : $(TARGET)
	./$(TARGET) $(F_NAME) 

# $(S_ADDR)
	
#clean all object files and executable file TARGET
.PHONY: clean

clean:
	rm -f *.o
	rm -f $(TARGET)
	
#debug
.PHONY: debug

debug: $(OBJS)
	$(CC) -o -d $@ $(OBJS)