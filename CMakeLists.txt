# CMakefile for the XDP P4-16 back-end.
# To be included in the main P4C compiler makefile

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
  )

set (P4C_XDP_HEADERS
  xdpModel.h
  xdpProgram.h
  xdpControl.h
  target.h
  xdpBackend.h)

add_cpplint_FILES(${CMAKE_CURRENT_SOURCE_DIR} "$(P4C_XDP_SOURCES)")

add_executable(p4c-xdp ${P4C_XDP_SOURCES})
target_link_libraries(p4c-xdp ${P4C_LIBRARIES} ${P4C_LIB_DEPS})

install (TARGETS p4c-xdp
  RUNTIME DESTINATION ${P4C_RUNTIME_OUTPUT_DIRECTORY})
install (DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/p4include
  DESTINATION ${P4C_ARTIFACTS_OUTPUT_DIRECTORY})
