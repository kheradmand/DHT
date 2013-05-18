#################################################
##              In the name of GOD
##
## Copyright (C) 2009-2012 Behnam Momeni.
## All rights reserved.
##
## This file is part of the Partov project.
##
#################################################

COMPILER = g++
FLAGS = -Wall -g -Ibase -Iuser
LIBS = -lpthread -lcrypto

TARGET = peer.out

BASE_SOURCES = base/main.cpp \
	base/cf.cpp \
	base/interface.cpp \
	base/machine.cpp \
	base/frame.cpp

# DO NOT LIST .H FILES HERE! JUST .C AND .CPP FILES
USER_SOURCES = user/sm.cpp \
	user/OstreamManip.cpp \
	user/PacketParser.cpp \
	user/DHTNodeInfo.cpp \
	user/DHTNode.cpp
	
BASE_OBJ = ${BASE_SOURCES:.cpp=.o}
BASE_OBJECTS = ${BASE_OBJ:.c=.o}

USER_OBJ = ${USER_SOURCES:.cpp=.o}
USER_OBJECTS = ${USER_OBJ:.c=.o}

OBJECTS = ${BASE_OBJECTS} ${USER_OBJECTS}

all: ${TARGET}

${TARGET}: ${OBJECTS}
	${COMPILER} ${FLAGS} -o ${TARGET} ${OBJECTS} ${LIBS}

clean:
	tmpfolder=`echo /tmp/CF-clean-$$$$.removed` && mkdir -p $$tmpfolder && touch a && mv -t $$tmpfolder/ a `for a in ${OBJECTS} ${TARGET} *~ base/*~ user/*~ ; do if [ -e $$a ]; then echo $$a; fi; done`

.cpp.o:
	${COMPILER} ${FLAGS} -c $< -o $@
.c.o:
	${COMPILER} ${FLAGS} -c $< -o $@
