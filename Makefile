CC=gcc
EC=-lpcap
CFLAGS=-W

bin/analyser : obj/analyser.o obj/en_tetes.o
	$(CC) -o bin/analyser obj/analyser.o obj/en_tetes.o $(EC)

obj/analyser.o : src/analyser.c
	$(CC) -o obj/analyser.o -c src/analyser.c $(CFLAGS)

obj/en_tetes.o : src/en_tetes.c headers/en_tetes.h
	$(CC) -o obj/en_tetes.o -c src/en_tetes.c $(CFLAGS)
clean :
	rm bin/*
	rm obj/*
