HEADERS       = server.h \
    cipher.h
SOURCES       = server.cpp \
                cipher.cpp \
                main.cpp
QT           += network widgets sql

INCLUDEPATH += "C:/Program Files/OpenSSL-Win64/include"

LIBS += "C:/Program Files/OpenSSL-Win64/lib/libcrypto.lib"
LIBS += "C:/Program Files/OpenSSL-Win64/lib/libssl.lib"



