#ifndef _IP6_ALT_MARK_H 
#define _IP6_ALT_MARK_H

#ifndef REAL
  #ifndef REPL
    #error REPL or REAL must be defined!
  #endif
#endif

#ifdef REAL
  #ifdef REPL
    #error REPL and REAL cannot be defined both!
  #endif
#endif


#include <linux/in6.h>

//struct ipv6_hopopt_hdr *hopopt_h;

struct ipv6_hopopt_hdr_and_alt_mark {
  __u8  nexthdr;
  __u8  hdrlen;
  __u8  opt_type;
  __u8  optlen;
  __u32  altmark_payload;
} ;

#endif
