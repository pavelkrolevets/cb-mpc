#include "handlers.h"
#include "httplib.h"

int main(int argc, char **argv) {
  int port;
  int id;
  for (int i = 1; i < argc; i++) {
    if (i + 1 != argc) {
      if (strcmp(argv[i], "-port") == 0) {
        sscanf(argv[i + 1], "%d", &port);
        i++;
      }
      if (strcmp(argv[i], "-id") == 0) {
        sscanf(argv[i + 1], "%d", &id);
        i++;
      }
    }
  }
  httplib::Server srv;
  generate_key_handler(srv, id);
  std::cout << "server port: " << port << " id: " << id << std::endl;
  srv.listen("0.0.0.0", port);
  return 0;
}