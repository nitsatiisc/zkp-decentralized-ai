#/bin/bash
mkdir -p ./build
pushd ./build
cmake .. && make run_proto_benchmarks
popd
