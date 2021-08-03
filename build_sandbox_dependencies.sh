#!/bin/bash
# build libsnark
echo "Building library libsnark"
cp CMakeLists.txt.libsnark depends/libsnark/CMakeLists.txt
cp CMakeLists.txt.libff depends/libsnark/depends/libff/CMakeLists.txt
pushd ./depends
pushd ./libsnark
mkdir -p ./build
pushd ./build
cmake .. && make snark ff
popd
popd
# Back at depends
pushd ./yaml-cpp
mkdir -p ./build
pushd ./build
cmake .. && make
popd
popd
# Back at depends
popd
