# CMakefile for the XDP P4-16 back-end.

set (P4C_XDP_SOURCES
  p4c-xdp.cpp
  xdpModel.cpp
  xdpControl.cpp
  xdpProgram.cpp
  target.cpp
  xdpBackend.cpp
  ../../backends/ebpf/ebpfProgram.cpp
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

add_dependencies(p4c_driver linkp4cxdp)

set(XDP_DRIVER ${CMAKE_CURRENT_SOURCE_DIR}/run-p4c-xdp.sh)

# This file will not run the full tests, but it will attempt to compile the p4 files down to C
set (XDP_TEST_SUITES
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.p4"
  )
p4c_add_tests("xdp" ${XDP_DRIVER} ${XDP_TEST_SUITES} "")
