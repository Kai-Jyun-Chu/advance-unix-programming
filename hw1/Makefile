all: libzpoline.so.1 libzpoline.so.2 libzpoline.so

libzpoline.so.1: trampoline.c
	gcc -fPIC -shared -g -o libzpoline.so.1 trampoline.c

libzpoline.so.2: step2.c
	gcc -fPIC -shared -g -o libzpoline.so.2 step2.c

libzpoline.so: step3.c
	gcc -fPIC -shared -g -o libzpoline.so step3.c -lcapstone

logger.so: logger.c
	gcc -fPIC -shared -g -o logger.so logger.c
clean:
	rm -f libzpoline.so.1 libzpoline.so.2 libzpoline.so



