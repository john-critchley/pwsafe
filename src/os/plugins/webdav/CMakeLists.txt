find_package(CURL REQUIRED)

add_library(pwsafe-https MODULE transport-webdav.cpp)

set_target_properties(pwsafe-https PROPERTIES
  PREFIX ""
  SUFFIX ".so"
  CXX_STANDARD 17
)

target_include_directories(pwsafe-https PRIVATE
  ${CMAKE_SOURCE_DIR}/src/os
  ${CURL_INCLUDE_DIRS}
)

target_link_libraries(pwsafe-https PRIVATE ${CURL_LIBRARIES})

# Create pwsafe-http.so as a symlink so http:// URLs use the same plugin
install(CODE
  "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink
     pwsafe-https.so
     \${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pwsafe-http.so)"
)

# For in-tree dev use: also create the symlink next to the built .so
add_custom_command(TARGET pwsafe-https POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    pwsafe-https.so
    $<TARGET_FILE_DIR:pwsafe-https>/pwsafe-http.so
  COMMENT "Creating pwsafe-http.so symlink"
)
