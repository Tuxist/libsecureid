list(APPEND secureidsrc
    secureid.c
)

add_library(secureid STATIC ${secureidsrc})

install( TARGETS
    secureid
    DESTINATION
    lib
)

install( FILES
    secureid.h
    DESTINATION
    include
)

