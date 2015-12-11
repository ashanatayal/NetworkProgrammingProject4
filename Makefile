CC = gcc

FLAGS = -g 

CFLAGS = ${FLAGS} -I/home/courses/cse533/Stevens/unpv13e/lib

LIBUNP_NAME = /home/courses/cse533/Stevens/unpv13e/libunp.a

LIBS = ${LIBUNP_NAME} -lpthread

all: arp_astayal tour_astayal
 	
arp_astayal: arp.o get_hw_addrs.o
	${CC} ${FLAGS} -o arp_astayal arp.o get_hw_addrs.o ${LIBS}

arp.o: arp.c
	${CC} ${CFLAGS} -c arp.c

# ping: ping.o get_hw_addrs.o
	# ${CC} ${FLAGS} -o ping ping.o get_hw_addrs.o ${LIBS}
	
# ping.o: ping.c
	# ${CC} ${CFLAGS} -c ping.c

tour_astayal: tour.o get_hw_addrs.o
	${CC} ${FLAGS} -o tour_astayal tour.o get_hw_addrs.o ${LIBS}
tour.o: tour.c
	${CC} ${CFLAGS} -c tour.c	
	
get_hw_addrs.o: get_hw_addrs.c
	${CC} ${CFLAGS} -c get_hw_addrs.c

clean:
	rm arp_astayal arp.o tour_astayal tour.o

	
