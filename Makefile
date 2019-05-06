
OE_SDK_PATH ?= /opt/openenclave

SRC_DIR=$(shell pwd)/src
APPS_DIR=$(shell pwd)/apps
JS_DIR=$(shell pwd)/js
BUILD_DIR=$(shell pwd)/build
INC_DIR=$(shell pwd)/include

KEY_DIR=$(shell pwd)/keys

APPS=$(BUILD_DIR)/echo_server/enclave.signed $(BUILD_DIR)/echo_server/index.html
TARGET=$(BUILD_DIR)/host $(BUILD_DIR)/socket_server.py $(APPS) $(BUILD_DIR)/trusted_module.js
DEFINES=-DOE_API_VERSION=2
CXX_ONLY_DEFINES=-std=c++11


$(shell mkdir -p $(BUILD_DIR))
$(shell mkdir -p $(BUILD_DIR)/enclave-directory)
$(shell mkdir -p $(BUILD_DIR)/host-directory)
$(shell mkdir -p $(BUILD_DIR)/common)


$(shell mkdir -p $(BUILD_DIR)/echo_server)

HOST_CFLAGS=$(shell pkg-config $(OE_SDK_PATH)/share/pkgconfig/oehost-gcc.pc --cflags)
HOST_LIBS=$(shell pkg-config $(OE_SDK_PATH)/share/pkgconfig/oehost-gcc.pc --libs)
ENC_CFLAGS=$(shell pkg-config $(OE_SDK_PATH)/share/pkgconfig/oeenclave-gcc.pc --cflags)
ENC_LIBS=$(shell pkg-config $(OE_SDK_PATH)/share/pkgconfig/oeenclave-gcc.pc --libs)

HOST_CPPFLAGS=$(shell pkg-config $(OE_SDK_PATH)/share/pkgconfig/oehost-g++.pc --cflags)
ENC_CPPFLAGS=$(shell pkg-config $(OE_SDK_PATH)/share/pkgconfig/oeenclave-g++.pc --cflags)

ENC_CPPLIBS=$(shell pkg-config $(OE_SDK_PATH)/share/pkgconfig/oeenclave-g++.pc --libs)

COMMON_HEADERS=$(wildcard $(SRC_DIR)/common/*.h)
COMMON_SOURCES=$(wildcard $(SRC_DIR)/common/*.cpp)
COMMON_OBJECTS=$(subst $(SRC_DIR),$(BUILD_DIR),$(COMMON_SOURCES:.cpp=.o))


$(BUILD_DIR)/%/index.html: $(APPS_DIR)/%/index.html
	cp $< $@

$(BUILD_DIR)/%.o: $(APPS_DIR)/%/enclave.cpp $(BUILD_DIR)/enclave-directory/project_t.h $(COMMON_HEADERS) 
	$(CC) -c $(ENC_CPPFLAGS) $< -o $@ -I$(BUILD_DIR)/enclave-directory/ $(DEFINES) -I$(SRC_DIR)/common/ -I$(SRC_DIR)
	

$(BUILD_DIR)/%/enclave.signed: $(BUILD_DIR)/enclave.o $(BUILD_DIR)/project_t.o $(KEY_DIR)/private.pem $(BUILD_DIR)/common.a $(SRC_DIR)/enc.conf $(BUILD_DIR)/%.o
	$(CC) $(BUILD_DIR)/enclave.o $(BUILD_DIR)/$*.o $(BUILD_DIR)/project_t.o -o $(BUILD_DIR)/$*/enclave $(BUILD_DIR)/common.a $(ENC_CPPLIBS) 
	$(OE_SDK_PATH)/bin/oesign sign --enclave-image $(BUILD_DIR)/$*/enclave --config-file $(SRC_DIR)/enc.conf --key-file $(KEY_DIR)/private.pem



all: $(TARGET)


$(BUILD_DIR)/trusted_module.js: $(JS_DIR)/trusted_module.js
	cp $< $@


$(BUILD_DIR)/host-directory/project_t.h $(BUILD_DIR)/host-directory/project_u.h $(BUILD_DIR)/enclave-directory/project_t.c $(BUILD_DIR)/enclave-directory/project_t.h: $(SRC_DIR)/project.edl
	$(OE_SDK_PATH)/bin/oeedger8r --trusted-dir $(BUILD_DIR)/enclave-directory --untrusted-dir $(BUILD_DIR)/host-directory $(SRC_DIR)/project.edl	


$(BUILD_DIR)/host.o: $(SRC_DIR)/host.c $(BUILD_DIR)/host-directory/project_u.h
	$(CC) -c $(HOST_CFLAGS) $< -o $@ -I$(BUILD_DIR)/host-directory $(DEFINES) -I$(SRC_DIR)/common/
$(BUILD_DIR)/project_u.o: $(BUILD_DIR)/host-directory/project_u.c $(BUILD_DIR)/host-directory/project_u.h
	$(CC) -c $(HOST_CFLAGS) $< -o $@ -I$(BUILD_DIR)/host-directory $(DEFINES)

	

$(BUILD_DIR)/enclave.o: $(SRC_DIR)/enclave.c $(BUILD_DIR)/enclave-directory/project_t.h $(COMMON_HEADERS)
	$(CC) -c $(ENC_CFLAGS) $< -o $@ -I$(BUILD_DIR)/enclave-directory $(DEFINES) -I$(SRC_DIR)/common/
$(BUILD_DIR)/project_t.o: $(BUILD_DIR)/enclave-directory/project_t.c $(BUILD_DIR)/enclave-directory/project_t.h
	$(CC) -c $(ENC_CFLAGS) $< -o $@ -I$(BUILD_DIR)/enclave-directory $(DEFINES)



$(BUILD_DIR)/host: $(BUILD_DIR)/host.o $(BUILD_DIR)/project_u.o $(BUILD_DIR)/common.a
	$(CC) $^ -o $@ $(HOST_LIBS) -lcurl

$(KEY_DIR)/private.pem:
	cd $(KEY_DIR); sh $(KEY_DIR)/gen_key.sh


#$(BUILD_DIR)/enclave.signed: $(BUILD_DIR)/enclave.o $(BUILD_DIR)/project_t.o $(KEY_DIR)/private.pem $(BUILD_DIR)/common.a $(SRC_DIR)/enc.conf
#	echo $(COMMON_SOURCES)
#	$(CC) $(BUILD_DIR)/enclave.o $(BUILD_DIR)/project_t.o -o $(BUILD_DIR)/enclave $(BUILD_DIR)/common.a $(ENC_CPPLIBS)
#	$(OE_SDK_PATH)/bin/oesign sign --enclave-image $(BUILD_DIR)/enclave --config-file $(SRC_DIR)/enc.conf --key-file $(KEY_DIR)/private.pem




$(BUILD_DIR)/common.a: $(COMMON_OBJECTS)
	ar -rsc $@ $^

$(BUILD_DIR)/common/%.o: $(SRC_DIR)/common/%.cpp $(COMMON_HEADERS)
	$(CXX) -c $(ENC_CPPFLAGS) $< -o $@ -I$(BUILD_DIR)/enclave-directory $(DEFINES) $(CXX_ONLY_DEFINES)

$(BUILD_DIR)/create_enclave: $(SRC_DIR)/handlers/create_enclave.c
	$(CC) $< -o $@

$(BUILD_DIR)/socket_server.py: $(SRC_DIR)/handlers/server.py
	cp $< $@
	sed -i 's?BINARY_PATH_PLACEHOLDER?$(BUILD_DIR)/host?g' $@




clean:
	rm -rf build

clean-keys: clean
	rm -f $(KEY_DIR)/private.pem
	rm -f $(KEY_DIR)/public.pem
