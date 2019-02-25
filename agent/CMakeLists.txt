# -*- cmake -*-

cmake_minimum_required(VERSION 3.1)
project(tcfagent C)
include(GNUInstallDirs)

set(CMAKE_COLOR_MAKEFILE OFF)

set(TCF_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(TCF_LIB_NAME tcf-agent)
include(../cmake-tcf-lib.txt)

message(STATUS "operating system: " ${TCF_OPSYS})
message(STATUS "machine: " ${TCF_MACHINE})

add_executable(agent tcf/main/main.c)
target_link_libraries(agent ${TCF_LIB_NAME})

# executable and library cant have the same target name,
# but we can rename the output
set_target_properties(agent
        PROPERTIES OUTPUT_NAME tcf-agent)

# add target to install all outputs
install(TARGETS agent ${TCF_LIB_NAME}
  RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
