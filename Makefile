TARGET = test
CFLAGS = -g -O0
CXXFLAGS = -g -O0 -std=c++17
LDFLAGS = -lcrypto -lssl -lm -lstdc++

$(TARGET): src/test.o libdpf.a
	g++ $^ -o $@ $(LDFLAGS)

src/test.o: src/test.c include/dpf.h
	gcc $(CFLAGS) -Iinclude -c $< -o $@ $(LDFLAGS)

libdpf.a: src/dpf.o src/vdpf.o src/mmo.o src/common.o src/sha256.o src/dmpf.o src/big_state.o
	ar rcs $@ $^

src/dpf.o: src/dpf.c include/dpf.h
	gcc $(CFLAGS) -Iinclude -c -o $@ $< $(LDFLAGS)

src/mmo.o: src/mmo.c include/mmo.h 
	gcc $(CFLAGS) -Iinclude -c -o $@ $< $(LDFLAGS)

src/vdpf.o: src/vdpf.c include/vdpf.h
	gcc $(CFLAGS) -Iinclude -c -o $@ $< $(LDFLAGS)

src/dmpf.o: src/dmpf.cc include/dmpf.h
	g++ $(CXXFLAGS) -Iinclude -c -o $@ $< $(LDFLAGS)

src/big_state.o: src/big_state.cc include/dpf.h include/mmo.h include/common.h
	g++ $(CXXFLAGS) -Iinclude -c -o $@ $< $(LDFLAGS)

src/common.o: src/common.c include/common.h
	gcc $(CFLAGS) -Iinclude -c -o $@ $< $(LDFLAGS)

src/sha256.o: src/sha256.c include/sha256.h
	gcc $(CFLAGS) -Iinclude -c -o $@ $< $(LDFLAGS)

big_state: src/big_state.cc src/dpf.o src/common.o src/mmo.o
	g++ -g -O0 -Wall -Wextra -std=c++17 -Iinclude $^ -o $@ -lssl -lcrypto

clean:
	rm -f src/*.o *.a $(TARGET) big_state 