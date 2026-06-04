find_package(CURL REQUIRED)

add_library(pwsafe-https MODULE transport-webdav.cpp)

# No "lib" prefix: produces pwsafe-https.so (Unix) or pwsafe-https.dll (Windows)
set_target_properties(pwsafe-https PROPERTIES
  PREFIX ""
  SUFFIX $<IF:$<BOOL:${WIN32}>,.dll,.so>
  CXX_STANDARD 17
)

target_include_directories(pwsafe-https PRIVATE
  ${CMAKE_SOURCE_DIR}/src/os
  ${CURL_INCLUDE_DIRS}
)

target_link_libraries(pwsafe-https PRIVATE ${CURL_LIBRARIES})

if(WIN32)
  # Windows has no symlinks in general installer context: copy the DLL
  add_custom_command(TARGET pwsafe-https POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      $<TARGET_FILE:pwsafe-https>
      $<TARGET_FILE_DIR:pwsafe-https>/pwsafe-http.dll
    COMMENT "Creating pwsafe-http.dll copy"
  )
  install(FILES $<TARGET_FILE_DIR:pwsafe-https>/pwsafe-http.dll
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )
else()
  # Unix: symlink so http:// URLs use the same plugin
  add_custom_command(TARGET pwsafe-https POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink
      pwsafe-https.so
      $<TARGET_FILE_DIR:pwsafe-https>/pwsafe-http.so
    COMMENT "Creating pwsafe-http.so symlink"
  )
  install(CODE
    "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink
       pwsafe-https.so
       \${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pwsafe-http.so)"
  )
endif()
