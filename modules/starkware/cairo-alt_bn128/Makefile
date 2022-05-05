all:
	@echo "Compiling.." 
	@cairo-compile alt_bn128_example.cairo --output alt_bn128.json 
	@echo "Running.." 
	@cairo-run --program alt_bn128.json --print_output --layout=small --print_info
run:
	@echo "Running.." 
	@cairo-run --program alt_bn128.json --print_output --layout=small --print_info

