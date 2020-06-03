# CMakefile for the XDP P4-16 back-end.

set (P4C_XDP_SOURCES
  p4c-xdp.cpp
  xdpModel.cpp
  xdpControl.cpp
  xdpProgram.cpp
  target.cpp
  xdpBackend.cpp
  ../../backends/ebpf/ebpfProgram.cpp
  ../../backends/ebpf/ebpfOptions.cpp
  ../../backends/ebpf/ebpfTable.cpp
  ../../backends/ebpf/ebpfControl.cpp
  ../../backends/ebpf/ebpfParser.cpp
  ../../backends/ebpf/target.cpp
  ../../backends/ebpf/ebpfType.cpp
  ../../backends/ebpf/codeGen.cpp
  ../../backends/ebpf/ebpfModel.cpp
  ../../backends/ebpf/midend.cpp
  ../../backends/ebpf/lower.cpp
  )

build_unified(P4C_XDP_SOURCES)
set (P4C_XDP_HEADERS
  xdpModel.h
  xdpProgram.h
  xdpControl.h
  target.h
  xdpBackend.h)

set (XDP_DIST_HEADERS p4include/xdp_model.p4)

add_cpplint_FILES(${CMAKE_CURRENT_SOURCE_DIR} "$(P4C_XDP_SOURCES)")

add_executable(p4c-xdp ${P4C_XDP_SOURCES})
target_link_libraries(p4c-xdp ${P4C_LIBRARIES} ${P4C_LIB_DEPS})

install (TARGETS p4c-xdp
  RUNTIME DESTINATION ${P4C_RUNTIME_OUTPUT_DIRECTORY})
install (DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/p4include
  DESTINATION ${P4C_ARTIFACTS_OUTPUT_DIRECTORY})

add_custom_target(linkp4cxdp
  COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_CURRENT_BINARY_DIR}/p4c-xdp ${P4C_BINARY_DIR}/p4c-xdp
  COMMAND ${CMAKE_COMMAND} -E make_directory ${P4C_BINARY_DIR}/p4include &&
          ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/${XDP_DIST_HEADERS} ${P4C_BINARY_DIR}/p4include
  COMMAND ${CMAKE_COMMAND} -E create_symlink ${P4C_BINARY_DIR}/p4include ${CMAKE_CURRENT_BINARY_DIR}/p4include
  )

# check for the libbpf library, it is required for p4c-xdp to work
find_library(LIBBPF NAMES bpf HINTS "${CMAKE_CURRENT_SOURCE_DIR}/runtime/usr/lib64/")
if (LIBBPF)
  message(STATUS "Found libbpf library")
else()
  message(FATAL_ERROR "Missing the libbpf dependency, disabling kernel tests."
  " You can install libbpf by running './build_libbpf' in the "
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime folder.")
endif()



# Automatically insert the xdp_target in the targets folder
if(CMAKE_HOST_UNIX)
EXECUTE_PROCESS(COMMAND ln -sf ${CMAKE_CURRENT_SOURCE_DIR}/xdp_target.py ${P4C_SOURCE_DIR}/backends/ebpf/targets/xdp_target.py
   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
   )
endif(CMAKE_HOST_UNIX)

set (XFAIL_TESTS_XDP
  # Fails because of stack size
  ${CMAKE_CURRENT_SOURCE_DIR}/tests/xdp7.p4
  ${CMAKE_CURRENT_SOURCE_DIR}/tests/xdp12.p4
  )

add_dependencies(p4c_driver linkp4cxdp)

set(XDP_DRIVER "${P4C_SOURCE_DIR}/backends/ebpf/run-ebpf-test.py -t xdp -c \"${P4C_BINARY_DIR}/p4c-xdp\"")

# This file will not run the full tests, but it will attempt to compile the p4 files down to C
set (XDP_TEST_SUITES "${CMAKE_CURRENT_SOURCE_DIR}/tests/xdp*.p4")
p4c_add_tests("xdp" ${XDP_DRIVER} ${XDP_TEST_SUITES} "${XFAIL_TESTS_XDP}")

