add_library(pwsafe-file MODULE transport-file.cpp)

# No "lib" prefix: produces pwsafe-file.so (Unix) or pwsafe-file.dll (Windows)
set_target_properties(pwsafe-file PROPERTIES
  PREFIX ""
  SUFFIX $<IF:$<BOOL:${WIN32}>,.dll,.so>
  CXX_STANDARD 17
)

# Link against nothing extra — libc/libstdc++ only
target_include_directories(pwsafe-file PRIVATE
  ${CMAKE_SOURCE_DIR}/src/os
)
