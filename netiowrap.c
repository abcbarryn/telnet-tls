#include <config.h>

#include <telnet_locl.h>

int Send(const void *buf, size_t len, int flags)
{
#ifdef STARTTLS
    if(ssl)
	return ssl_write(buf, len);
    else
#endif
	return send(net, buf, len, flags);
}

int Recv(void *buf, size_t len, int flags)
{
#ifdef STARTTLS
    if(ssl)
	return ssl_read(buf,len);
    else
#endif
	return recv(net, buf, len, flags);
}
