
OE_SDK_PATH ?= /opt/openenclave

SRC_DIR=$(shell pwd)/src
BUILD_DIR=$(shell pwd)/build
INC_DIR=$(shell pwd)/include

KEY_DIR=$(shell pwd)/keys


TARGET=$(BUILD_DIR)/host $(BUILD_DIR)/enclave.signed
DEFINES=


$(shell mkdir -p $(BUILD_DIR))
$(shell mkdir -p $(BUILD_DIR)/enclave-directory)
$(shell mkdir -p $(BUILD_DIR)/host-directory)


HOST_CFLAGS=$(shell pkg-config $(OE_SDK_PATH)/share/pkgconfig/oehost-gcc.pc --cflags)
HOST_LIBS=$(shell pkg-config $(OE_SDK_PATH)/share/pkgconfig/oehost-gcc.pc --libs)
ENC_CFLAGS=$(shell pkg-config $(OE_SDK_PATH)/share/pkgconfig/oeenclave-gcc.pc --cflags)
ENC_LIBS=$(shell pkg-config $(OE_SDK_PATH)/share/pkgconfig/oeenclave-gcc.pc --libs)

all: $(TARGET)

$(BUILD_DIR)/host-directory/project_t.h $(BUILD_DIR)/host-directory/project_u.h $(BUILD_DIR)/enclave-directory/project_t.c $(BUILD_DIR)/enclave-directory/project_t.h: $(SRC_DIR)/project.edl
	$(OE_SDK_PATH)/bin/oeedger8r --trusted-dir $(BUILD_DIR)/enclave-directory --untrusted-dir $(BUILD_DIR)/host-directory $(SRC_DIR)/project.edl	


$(BUILD_DIR)/host.o: $(SRC_DIR)/host.c $(BUILD_DIR)/host-directory/project_u.h
	$(CC) -c $(HOST_CFLAGS) $< -o $@ -I$(BUILD_DIR)/host-directory
$(BUILD_DIR)/project_u.o: $(BUILD_DIR)/host-directory/project_u.c $(BUILD_DIR)/host-directory/project_u.h
	$(CC) -c $(HOST_CFLAGS) $< -o $@ -I$(BUILD_DIR)/host-directory

	

$(BUILD_DIR)/enclave.o: $(SRC_DIR)/enclave.c $(BUILD_DIR)/enclave-directory/project_t.h
	$(CC) -c $(ENC_CFLAGS) $< -o $@ -I$(BUILD_DIR)/enclave-directory
$(BUILD_DIR)/project_t.o: $(BUILD_DIR)/enclave-directory/project_t.c $(BUILD_DIR)/enclave-directory/project_t.h
	$(CC) -c $(ENC_CFLAGS) $< -o $@ -I$(BUILD_DIR)/enclave-directory



$(BUILD_DIR)/host: $(BUILD_DIR)/host.o $(BUILD_DIR)/project_u.o
	$(CC) $^ -o $@ $(HOST_LIBS)

$(KEY_DIR)/private.pem:
	cd $(KEY_DIR); sh $(KEY_DIR)/gen_key.sh

$(BUILD_DIR)/enclave.signed: $(BUILD_DIR)/enclave.o $(BUILD_DIR)/project_t.o $(KEY_DIR)/private.pem
	$(CC) $(BUILD_DIR)/enclave.o $(BUILD_DIR)/project_t.o -o $(BUILD_DIR)/enclave $(ENC_LIBS)
	$(OE_SDK_PATH)/bin/oesign sign --enclave-image $(BUILD_DIR)/enclave --config-file $(SRC_DIR)/enc.conf --key-file $(KEY_DIR)/private.pem




run:
	$(BUILD_DIR)/host $(BUILD_DIR)/enclave.signed


clean:
	rm -rf build

clean-keys: clean
	rm -f $(KEY_DIR)/private.pem
	rm -f $(KEY_DIR)/public.pem
