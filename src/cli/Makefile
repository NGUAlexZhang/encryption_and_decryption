ASYMMETRIC_SRC = $(wildcard $(SRC_DIR)/asymmetric/*cc)
ASYMMETRIC_OBJ = $(patsubst %.cc, %.o, $(ASYMMETRIC_SRC))
az-rsa: $(ASYMMETRIC_OBJ) $(SRC_DIR)/cli/az_rsa.o $(SRC_DIR)/utils/path_handler.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(patsubst %.o, $(OBJ_DIR)/%.o, $^) -o $(BIN_DIR)/$@ $(CFLAGS) $(DEBUG_FLAGS) $(LDFLAGS)