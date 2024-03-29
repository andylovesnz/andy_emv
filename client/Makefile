#-----------------------------------------------------------------------------
# This code is licensed to you under the terms of the GNU GPL, version 2 or,
# at your option, any later version. See the LICENSE.txt file for the text of
# the license.
#-----------------------------------------------------------------------------
include ../common/Makefile.common

CC=gcc
CXX=g++
#COMMON_FLAGS = -m32

VPATH = ../common
OBJDIR = obj

LDLIBS = -L/opt/local/lib -L/usr/local/lib -lusb -lreadline -lpthread
LDFLAGS = $(COMMON_FLAGS)
CFLAGS = -std=c99 -I. -I../include -I../common -I/opt/local/include -Wall -Wno-unused-function $(COMMON_FLAGS) -g -O4

ifneq (,$(findstring MINGW,$(platform)))
CXXFLAGS = -I$(QTDIR)/include -I$(QTDIR)/include/QtCore -I$(QTDIR)/include/QtGui
QTLDLIBS = -L$(QTDIR)/lib -lQtCore4 -lQtGui4
MOC = $(QTDIR)/bin/moc
else ifeq ($(platform),Darwin)
CXXFLAGS = -I/Library/Frameworks/QtGui.framework/Versions/Current/Headers -I/Library/Frameworks/QtCore.framework/Versions/Current/Headers
QTLDLIBS = -framework QtGui -framework QtCore
MOC = moc 
LUAPLATFORM = macosx
else
CXXFLAGS = $(shell pkg-config --cflags QtCore QtGui 2>/dev/null) -Wall -O4
QTLDLIBS = $(shell pkg-config --libs QtCore QtGui 2>/dev/null)
MOC = $(shell pkg-config --variable=moc_location QtCore)
LDLIBS +=  -ldl

# Below is a variant you can use if you have problems compiling with QT5 on ubuntu. see http://www.proxmark.org/forum/viewtopic.php?id=1661 for more info. 
#MOC = /usr/lib/x86_64-linux-gnu/qt4/bin/moc
endif


ifneq ($(QTLDLIBS),)
QTGUI = $(OBJDIR)/proxgui.o $(OBJDIR)/proxguiqt.o $(OBJDIR)/proxguiqt.moc.o
CFLAGS += -DHAVE_GUI
LINK.o = $(LINK.cpp)
else
QTGUI = guidummy.o
endif

CMDSRCS = \
			nonce2key/crapto1.c\
			nonce2key/crypto1.c\
			nonce2key/nonce2key.c\
			mifarehost.c\
			crc16.c \
			iso14443crc.c \
			iso15693tools.c \
			data.c \
			graph.c \
			ui.c \
			util.c \
			cmddata.c \
			cmdhf.c \
			cmdhf14a.c \
			cmdhf14b.c \
			cmdhf15.c \
			cmdhfepa.c \
			cmdhflegic.c \
			cmdhficlass.c \
			cmdhfmf.c \
			cmdhw.c \
			cmdlf.c \
			cmdlfhid.c \
			cmdlfem4x.c \
			cmdlfhitag.c \
			cmdlfti.c \
			cmdparser.c \
			cmdmain.c \
			cmdlft55xx.c \
			cmdlfpcf7931.c


CMDOBJS = $(CMDSRCS:%.c=$(OBJDIR)/%.o)

RM = rm -f
BINS = proxmark3 flasher #snooper cli
CLEAN = cli cli.exe flasher flasher.exe proxmark3 proxmark3.exe snooper snooper.exe $(CMDOBJS) $(OBJDIR)/*.o *.o *.moc.cpp

all: $(BINS)

all-static: LDLIBS:=-static $(LDLIBS)
all-static: snooper cli flasher
	
proxmark3: LDLIBS+=$(QTLDLIBS)
proxmark3: $(OBJDIR)/proxmark3.o $(CMDOBJS) $(OBJDIR)/uart.o $(QTGUI)
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -o $@

snooper: $(OBJDIR)/snooper.o $(CMDOBJS) $(OBJDIR)/uart.o $(OBJDIR)/guidummy.o
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -o $@

cli: $(OBJDIR)/cli.o $(CMDOBJS) $(OBJDIR)/uart.o $(OBJDIR)/guidummy.o
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -o $@

flasher: $(OBJDIR)/flash.o $(OBJDIR)/flasher.o $(OBJDIR)/uart.o
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -o $@

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

proxguiqt.moc.cpp: proxguiqt.h
	$(MOC) -o$@ $^

clean:
	$(RM) $(CLEAN)
	cd ../liblua && make clean

tarbin: $(BINS)
	$(TAR) $(TARFLAGS) ../proxmark3-$(platform)-bin.tar $(BINS:%=client/%)

# must be run as root
install_kext: Info.plist
	mkdir -p /System/Library/Extensions/Proxmark3.kext/Contents
	cp Info.plist /System/Library/Extensions/Proxmark3.kext/Contents
	chown -R root:wheel /System/Library/Extensions/Proxmark3.kext
	chmod 755 /System/Library/Extensions/Proxmark3.kext /System/Library/Extensions/Proxmark3.kext/Contents
	chmod 644 /System/Library/Extensions/Proxmark3.kext/Contents/Info.plist
	rm -rf /System/Library/Caches/com.apple.kext.caches
	touch /System/Library/Extensions
	@echo "*** You may need to reboot for the kext to take effect."

.PHONY: all clean
