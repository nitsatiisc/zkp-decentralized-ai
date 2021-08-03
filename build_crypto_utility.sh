#/bin/bash
mkdir -p ./build
pushd ./build
cmake .. && make lookup_gadget_benchmark
popd
