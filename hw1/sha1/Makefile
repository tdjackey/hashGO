CROSS =
CXX   = $(CROSS)g++
RM    = rm -f

all: test_sha1

test_sha1: test_sha1.cpp sha1.cpp sha1.hpp
	$(CXX) -std=c++11 -o $@ test_sha1.cpp sha1.cpp

check: test_sha1
	./test_sha1

clean:
	$(RM) demo_sha1 test_sha1
