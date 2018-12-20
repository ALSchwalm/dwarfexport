CXX ?= g++
CXXFLAGS=-m32 -fPIC -shared -Wall -Wextra -std=c++11
LDFLAGS+=-static-libgcc -static-libstdc++
LIBS=-lida lib/libelf32.a lib/libdwarf32.a
INCLUDES=-I$(IDASDK_PATH)/include -I$(IDA_PATH)/plugins/hexrays_sdk/include

DWARFEXPORT_SRC = $(wildcard src/*.cpp)

all: bin/dwarfexport.plx bin/dwarfexport.plx64

bin/dwarfexport.plx: $(DWARFEXPORT_SRC)
	$(CXX) $(LDFLAGS) $(DWARFEXPORT_SRC) $(CXXFLAGS) \
	-L. \
	-L$(IDA_PATH) \
	$(INCLUDES) \
	-D__LINUX__ -D__X64__ $(LIBS) -o bin/dwarfexport.plx

bin/dwarfexport.plx64: $(DWARFEXPORT_SRC)
	$(CXX) $(LDFLAGS) $(DWARFEXPORT_SRC) $(CXXFLAGS) \
	-L. \
	-L$(IDA_PATH) \
	$(INCLUDES) \
	-D__LINUX__ -D__X64 -D__EA64__ $(LIBS) -o bin/dwarfexport.plx64

clean:
	rm -f bin/dwarfexport.plx bin/dwarfexport.plx64
