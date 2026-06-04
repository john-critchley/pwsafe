add_library(pwsafe-file MODULE transport-file.cpp)

# No "lib" prefix: produces pwsafe-file.so (Unix) or pwsafe-file.dll (Windows)
set_target_properties(pwsafe-file PROPERTIES
  PREFIX ""
  CXX_STANDARD 17
)
if(WIN32)
  set_target_properties(pwsafe-file PROPERTIES SUFFIX ".dll")
endif()

# Link against nothing extra — libc/libstdc++ only
target_include_directories(pwsafe-file PRIVATE
  ${CMAKE_SOURCE_DIR}/src/os
)
