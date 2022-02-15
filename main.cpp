#include <QApplication>

#include "server.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QGuiApplication::setApplicationDisplayName(Server::tr("Local TCP Server"));
    Server server;
    server.show();
    return app.exec();
}
