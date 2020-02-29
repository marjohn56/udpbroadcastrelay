VERSION=1.0

udpbroadcastrelay: main.c
	$(CC) $(CFLAGS) -g main.c -o udpbroadcastrelay

clean:
	rm -f udpbroadcastrelay

all:
        $(CC) $(CFLAGS) -g main.c -o udpbroadcastrelay
        cp udpbroadcastrelay /usr/local/sbin/
        chmod 755 /usr/local/sbin/udpbroadcastrelay
