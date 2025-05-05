CPP = g++
LD_FLAGS = -lbpf
C_FLAGS = -Wno-write-strings

all: user clean_on_compile

user: ./main.cpp xdp_loader helpers actions cli
	${CPP} ${C_FLAGS} main.cpp XDP_Loader.o helpers.o actions.o cli.o -o main ${LD_FLAGS}

xdp_loader: ./header/XDP_Loader.h
	${CPP} -c ./src/XDP_Loader.cpp -o XDP_Loader.o

helpers: ./header/helpers.h
	${CPP} -c ./src/helpers.cpp -o helpers.o

actions: ./header/actions.h 
	${CPP} -c ./src/actions.cpp -o actions.o

cli: ./header/cli.h
	${CPP} -c ./src/cli.cpp -o cli.o

clean_on_compile:
	rm -rf *.o

clean:
	rm -rf *.o main