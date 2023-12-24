list(APPEND secureidsrc
    secureid.c
)

add_library(secureid STATIC ${secureidsrc})

install(
    TARGETS
        secureid
    DESTINATION
        lib
    EXPORT
        secureidTargets
)

install(
    FILES
        secureid.h
    DESTINATION
        include
)

set_property(TARGET secureid PROPERTY VERSION ${Upstream_VERSION})
set_property(TARGET secureid PROPERTY SOVERSION ${LIBV})
set_property(TARGET secureid PROPERTY INTERFACE_systempp_MAJOR_VERSION ${LIBV})
set_property(TARGET secureid APPEND PROPERTY COMPATIBLE_INTERFACE_STRING cryptplus_MAJOR_VERSION)

set(ConfigPackageLocation lib/cmake/libsecureid)

export(EXPORT secureidTargets
  FILE "${CMAKE_CURRENT_BINARY_DIR}/libsecureidTargets.cmake"
  NAMESPACE Upstream::
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/libsecureidVersion.cmake"
  VERSION ${Upstream_VERSION}
  COMPATIBILITY AnyNewerVersion
)

install(EXPORT secureidTargets
  FILE
    libsecureidTargets.cmake
  NAMESPACE
    Upstream::
  DESTINATION
    ${ConfigPackageLocation}
)

install(
  FILES
    "libsecureidConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/libsecureidVersion.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/libsecureidConfig.cmake"
  DESTINATION
    ${ConfigPackageLocation}
  COMPONENT
    Devel
)
