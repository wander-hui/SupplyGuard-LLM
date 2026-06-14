# SupplyGuard-LLM C/C++ 演示工程
# 供 CodeQL 建库: codeql database create ... --command "make"
CXX ?= g++
CXXFLAGS ?= -g -O0 -std=c++11
LDFLAGS ?= -ldl

all: vuln

vuln: vuln.cpp
	$(CXX) $(CXXFLAGS) -o vuln vuln.cpp $(LDFLAGS)

clean:
	rm -f vuln

.PHONY: all clean
