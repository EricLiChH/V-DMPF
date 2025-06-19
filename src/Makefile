TARGET = test
CFLAGS = -g -O0
CXXFLAGS = -g -O0 -std=c++17
LDFLAGS = -lcrypto -lssl -lm -lstdc++

$(TARGET): test.o libdpf.a
	g++ $^ -o $@ $(LDFLAGS)

test.o: test.c ../include/dpf.h
	gcc $(CFLAGS) -c $< -o $@ $(LDFLAGS)

libdpf.a: dpf.o vdpf.o mmo.o common.o sha256.o dmpf.o big_state.o
	ar rcs $@ $^

dpf.o: dpf.c ../include/dpf.h
	gcc $(CFLAGS) -c -o $@ $< $(LDFLAGS)

mmo.o: mmo.c ../include/mmo.h 
	gcc $(CFLAGS) -c -o $@ $< $(LDFLAGS)

vdpf.o: vdpf.c ../include/vdpf.h
	gcc $(CFLAGS) -c -o $@ $< $(LDFLAGS)

dmpf.o: dmpf.cc ../include/dmpf.h
	g++ $(CXXFLAGS) -c -I../include -o $@ $< $(LDFLAGS)

big_state.o: big_state.cc ../include/dpf.h ../include/mmo.h ../include/common.h
	g++ $(CXXFLAGS) -c -I../include -o $@ $< $(LDFLAGS)

big_state: big_state.cc ../obj/dpf.o ../obj/common.o ../obj/mmo.o
	g++ -g -O0 -Wall -Wextra -std=c++17 -I../include $^ -o $@ -lssl -lcrypto

clean:
	rm -f *.o *.a $(TARGET) big_state
