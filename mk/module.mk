CXX64 ?= x86_64-w64-mingw32-g++
STRIP64 ?= x86_64-w64-mingw32-strip
OUTDIR ?= ../_bin/AdaptiHound
CPPFLAGS += -I../_include
CXXFLAGS += -std=c++17 -fno-exceptions -fno-rtti -fno-threadsafe-statics -fno-weak -Os -Wall -Wextra -Werror -DBOF -fno-builtin -fno-stack-protector -mno-stack-arg-probe
SOURCE := src/entry.cpp
TARGET := $(OUTDIR)/$(MODULE).x64.o
DEPFILE := $(TARGET:.o=.d)

.PHONY: all bof clean
all: bof
bof: $(TARGET)

$(TARGET): Makefile $(SOURCE) ../mk/module.mk
	@mkdir -p "$(OUTDIR)"
	$(CXX64) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -MF "$(DEPFILE)" -MT "$@" -c $(SOURCE) -o "$@"
	$(STRIP64) --strip-unneeded "$@"

-include $(DEPFILE)

clean:
	rm -f "$(TARGET)" "$(DEPFILE)"
