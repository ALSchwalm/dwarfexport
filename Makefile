

CXX ?= g++
IDASDK_PATH ?= /home/adam/Repos/idasdk695
IDA_PATH ?= /home/adam/ida-6.95
CXXFLAGS=-m32 -fPIC -shared -Wall -Wextra -std=c++11
LDFLAGS+=-static-libgcc -static-libstdc++
LIBS=-lelf -lida lib/libdwarf32.a
INCLUDES=-I$(IDASDK_PATH)/include -I$(IDA_PATH)/plugins/hexrays_sdk/include

DWARFEXPORT_SRC = $(wildcard src/*.cpp)

all: dwarfexport.plx dwarfexport.plx64

dwarfexport.plx: $(DWARFEXPORT_SRC)
	$(CXX) $(LDFLAGS) $(DWARFEXPORT_SRC) $(CXXFLAGS) \
	-L. \
	-L$(IDA_PATH) \
	$(INCLUDES) \
	-D__LINUX__ $(LIBS) -o bin/dwarfexport.plx

dwarfexport.plx64: $(DWARFEXPORT_SRC)
	$(CXX) $(LDFLAGS) $(DWARFEXPORT_SRC) $(CXXFLAGS) \
	-L. \
	-L$(IDA_PATH) \
	$(INCLUDES) \
	-D__LINUX__ -D__EA64__ $(LIBS) -o bin/dwarfexport.plx64

clean:
	rm -f bin/dwarfexport.plx bin/dwarfexport.plx64
