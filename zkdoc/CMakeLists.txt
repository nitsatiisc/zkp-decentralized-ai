cmake_minimum_required(VERSION 3.1)
SET(LIBBOOST_IOSTREAM_COMPILE_FLAG "-lboost_iostreams")

set(LIBSNARK_DIRECTORY
	"../depends/libsnark"
)

set(LIBIOP_DIRECTORY
    "../depends/libiop"
)

set(LIBFF_LIBSNARK_DIRECTORY
	${LIBSNARK_DIRECTORY}/depends/libff
)

set(LIBFQFFT_LIBSNARK_DIRECTORY
	${LIBSNARK_DIRECTORY}/depends/libfqfft
)

set(LIBFF_LIBIOP_DIRECTORY
    ${LIBIOP_DIRECTORY}/depends/libff
)

set(YAML_CPP_DIRECTORY
	${CMAKE_SOURCE_DIR}/depends/yaml-cpp/include
)

set(RAPIDCSV_DIRECTORY
	${CMAKE_SOURCE_DIR}/depends/rapidcsv/src
)

add_executable(run_proto_benchmarks src/benchmarks/run_proto_benchmarks.cpp)
target_include_directories(
    run_proto_benchmarks
    PUBLIC

    ${LIBFF_LIBSNARK_DIRECTORY}
    ${LIBFQFFT_LIBSNARK_DIRECTORY}
    ${LIBSNARK_DIRECTORY}
)
target_link_libraries(
    run_proto_benchmarks
    
    ${GMPXX_LIBRARIES}
    ${GMP_LIBRARIES}
    ${LIBSNARK_LIBRARIES}
    ${LIBSNARK_LIBFF_LIBRARIES}
    ${GMPXX_LIBRARIES}
    ${GMP_LIBRARIES}
)

add_executable(test_hash src/test_hash.cpp)
target_include_directories(
    test_hash
    PUBLIC

    ${LIBFF_LIBSNARK_DIRECTORY}
    ${LIBFQFFT_LIBSNARK_DIRECTORY}
    ${LIBSNARK_DIRECTORY}
)
target_link_libraries(
    test_hash
    
    ${GMPXX_LIBRARIES}
    ${GMP_LIBRARIES}
    ${LIBSNARK_LIBRARIES}
    ${LIBSNARK_LIBFF_LIBRARIES}
    ${GMPXX_LIBRARIES}
    ${GMP_LIBRARIES}
    sodium
)

add_executable(run_nizk_benchmarks src/benchmarks/run_nizk_benchmarks.cpp)
target_include_directories(
    run_nizk_benchmarks
    PUBLIC

    ${LIBFF_LIBSNARK_DIRECTORY}
    ${LIBFQFFT_LIBSNARK_DIRECTORY}
    ${LIBSNARK_DIRECTORY}
)
target_link_libraries(
    run_nizk_benchmarks
    
    ${GMPXX_LIBRARIES}
    ${GMP_LIBRARIES}
    ${LIBSNARK_LIBRARIES}
    ${LIBSNARK_LIBFF_LIBRARIES}
    ${GMPXX_LIBRARIES}
    ${GMP_LIBRARIES}
    sodium
)

add_executable(zk_rest_server src/zk_rest_server.cpp)
target_include_directories(
    zk_rest_server
    PUBLIC

    ${LIBFF_LIBSNARK_DIRECTORY}
    ${LIBFQFFT_LIBSNARK_DIRECTORY}
    ${LIBSNARK_DIRECTORY}
    ${YAML_CPP_DIRECTORY}
    ${RAPIDCSV_DIRECTORY}
)
target_link_libraries(
    zk_rest_server
    
    ${GMPXX_LIBRARIES}
    ${GMP_LIBRARIES}
    ${LIBSNARK_LIBRARIES}
    ${LIBSNARK_LIBFF_LIBRARIES}
    ${GMPXX_LIBRARIES}
    ${GMP_LIBRARIES}
    ${YAML_CPP_LIBRARIES}
    sodium
)

add_executable(data_representation_test src/benchmarks/data_representation_test.cpp)
target_include_directories(
    data_representation_test
    PUBLIC

    ${RAPIDCSV_DIRECTORY}
    ${YAML_CPP_DIRECTORY}
)
target_link_libraries(
    data_representation_test

    ${YAML_CPP_LIBRARIES}    
)