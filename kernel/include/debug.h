#pragma once

#define DBG	KERN_INFO "[MAH]: "

#define TEST_PTR(a, b, c, d) if (a == (b) NULL) { c; return d; }

#define SUCCESS     0
#define ERROR       -1