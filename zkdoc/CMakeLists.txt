cmake_minimum_required(VERSION 3.1)
SET(LIBBOOST_IOSTREAM_COMPILE_FLAG "-lboost_iostreams")

set(LIBSNARK_DIRECTORY
	"../depends/libsnark"
)

set(LIBFF_LIBSNARK_DIRECTORY
	${LIBSNARK_DIRECTORY}/depends/libff
)

set(LIBFQFFT_LIBSNARK_DIRECTORY
	${LIBSNARK_DIRECTORY}/depends/libfqfft
)

set(YAML_CPP_DIRECTORY
	${CMAKE_SOURCE_DIR}/depends/yaml-cpp/include
)

set(RAPIDCSV_DIRECTORY
	${CMAKE_SOURCE_DIR}/depends/rapidcsv/src
)

add_executable(lookup_gadget_benchmark src/benchmarks/lookup_gadget_benchmark.cpp)
target_include_directories(
    lookup_gadget_benchmark
    PUBLIC

    ${LIBFF_LIBSNARK_DIRECTORY}
    ${LIBFQFFT_LIBSNARK_DIRECTORY}
    ${LIBSNARK_DIRECTORY}
)
target_link_libraries(
    lookup_gadget_benchmark
    
    ${GMPXX_LIBRARIES}
    ${GMP_LIBRARIES}
    ${LIBSNARK_LIBRARIES}
    ${LIBSNARK_LIBFF_LIBRARIES}
    ${GMPXX_LIBRARIES}
    ${GMP_LIBRARIES}
)
