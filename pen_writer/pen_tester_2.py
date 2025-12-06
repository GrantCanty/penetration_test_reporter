import socket
import validators


def ip_lookup(addr):
    if validators.url(addr):
    
        ip_list = []
        ais = socket.getaddrinfo(addr, 0,0,0,0)
        for result in ais:
            ip_list.append(result[-1][0])
            ip_list = list(set(ip_list))
    
        return ip_list
    return None