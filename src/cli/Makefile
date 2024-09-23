ASYMMETRIC_SRC = $(wildcard $(SRC_DIR)/asymmetric/*.cc)
ASYMMETRIC_OBJ = $(patsubst %.cc, %.o, $(ASYMMETRIC_SRC))
az-rsa: $(ASYMMETRIC_OBJ) $(SRC_DIR)/cli/az_rsa.o $(SRC_DIR)/utils/path_handler.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(patsubst %.o, $(OBJ_DIR)/%.o, $^) -o $(BIN_DIR)/$@ $(CFLAGS) $(DEBUG_FLAGS) $(LDFLAGS)

SYMMETRIC_SRC = $(wildcard $(SRC_DIR)/symmetric/*.cc)
SYMMETRIC_OBJ = $(patsubst %.cc, %.o, $(SYMMETRIC_SRC))

az-aes: $(SYMMETRIC_OBJ) $(SRC_DIR)/cli/az_aes.o $(SRC_DIR)/utils/path_handler.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(patsubst %.o, $(OBJ_DIR)/%.o, $^) -o $(BIN_DIR)/$@ $(CFLAGS) $(DEBUG_FLAGS) $(LDFLAGS)

HASH_SRC = $(wildcard $(SRC_DIR)/hash/*.cc)
HASH_OBJ = $(patsubst %.cc, %.o, $(HASH_SRC))
az-sha: $(HASH_OBJ)  $(SRC_DIR)/cli/az_sha.o $(SRC_DIR)/utils/path_handler.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(patsubst %.o, $(OBJ_DIR)/%.o, $^) -o $(BIN_DIR)/$@ $(CFLAGS) $(DEBUG_FLAGS) $(LDFLAGS)