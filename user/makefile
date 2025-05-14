CPP = g++
LD_FLAGS = -lbpf
C_FLAGS = -Wno-write-strings

xdpfw: user clean_on_compile

user: ./main.cpp xdp_loader helpers actions cli
	${CPP} ${C_FLAGS} main.cpp XDP_Loader.o helpers.o actions.o cli.o -o xdpfw ${LD_FLAGS}

xdp_loader: ./header/XDP_Loader.h ./src/XDP_Loader.cpp
	${CPP} -c ./src/XDP_Loader.cpp -o XDP_Loader.o

helpers: ./header/helpers.h ./src/helpers.cpp
	${CPP} -c ./src/helpers.cpp -o helpers.o

actions: ./header/actions.h ./src/actions.cpp
	${CPP} -c ./src/actions.cpp -o actions.o

cli: ./header/cli.h ./src/cli.cpp
	${CPP} -c ./src/cli.cpp -o cli.o

clean_on_compile:
	rm -rf *.o

clean:
	rm -rf *.o xdpfw