#include <stdio.h>

#ifdef LOG_ON

#define DBGPRINT(fmt)                       printf(fmt)
#define DBGPRINT1(fmt,arg1)                 printf(fmt,arg1)
#define DBGPRINT2(fmt,arg1,arg2)            printf(fmt,arg1,arg2)
#define DBGPRINT3(fmt,arg1,arg2,arg3)       printf(fmt,arg1,arg2,arg3)
#define DBGPRINT4(fmt,arg1,arg2,arg3,arg4)  printf(fmt,arg1,arg2,arg3,arg4)

#else

#define DBGPRINT(fmt)                       
#define DBGPRINT1(fmt,arg1)                 
#define DBGPRINT2(fmt,arg1,arg2)            
#define DBGPRINT3(fmt,arg1,arg2,arg3)       
#define DBGPRINT4(fmt,arg1,arg2,arg3,arg4)  

#endif
