CPP = g++
LD_FLAGS = -lbpf
C_FLAGS = -Wno-write-strings

all: test clean_on_compile

test: ./main.cpp xdp_loader helpers actions base64 test_class
	${CPP} ${C_FLAGS} main.cpp XDP_Loader.o base64.o test_class.o helpers.o actions.o -o test ${LD_FLAGS}

xdp_loader: ../user/header/XDP_Loader.h ../user/src/XDP_Loader.cpp
	${CPP} -c ../user/src/XDP_Loader.cpp -o XDP_Loader.o

helpers: ../user/header/helpers.h ../user/src/helpers.cpp
	${CPP} -c ../user/src/helpers.cpp -o helpers.o

actions: ../user/header/actions.h ../user/src/actions.cpp 
	${CPP} -c ../user/src/actions.cpp -o actions.o

base64: ./header/Base64.h ./src/Base64.cpp
	${CPP} -c ./src/Base64.cpp -o base64.o -lboost

test_class: ./header/Test_Class.h ./src/Test_Class.cpp
	${CPP} -c ./src/Test_Class.cpp -o test_class.o

clean_on_compile:
	rm -rf *.o

clean:
	rm -rf *.o test