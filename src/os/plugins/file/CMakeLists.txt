add_library(pwsafe-file MODULE transport-file.cpp)

# No "lib" prefix: produces pwsafe-file.so, not libpwsafe-file.so
set_target_properties(pwsafe-file PROPERTIES
  PREFIX ""
  SUFFIX ".so"
  CXX_STANDARD 17
)

# Link against nothing extra — libc/libstdc++ only
target_include_directories(pwsafe-file PRIVATE
  ${CMAKE_SOURCE_DIR}/src/os
)
