violin: main.c
	gcc $(CFLAGS) -g -o violin main.c -lssl -lcrypto

clean: 
	rm -f violin
