

#include "nsisapi.h"


HINSTANCE g_hInstance;
HWND g_hwndParent;
int g_stringsize;
stack_t **g_stacktop;
char *g_variables;


BOOL WINAPI _DllMainCRTStartup(HANDLE hInst, ULONG ul_reason_for_call, LPVOID lpReserved)
{
  g_hInstance=(HINSTANCE)hInst;
	return TRUE;
}


// utility functions (not required but often useful)
int popstring(char *str)
{
  stack_t *th;
  if (!g_stacktop || !*g_stacktop) return 1;
  th=(*g_stacktop);
  lstrcpy(str,th->text);
  *g_stacktop = th->next;
  GlobalFree((HGLOBAL)th);
  return 0;
}

void pushstring(char *str)
{
  stack_t *th;
  if (!g_stacktop) return;
  th=(stack_t*)GlobalAlloc(GPTR,sizeof(stack_t)+g_stringsize);
  lstrcpyn(th->text,str,g_stringsize);
  th->next=*g_stacktop;
  *g_stacktop=th;
}

char *getuservariable(int varnum)
{
  if (varnum < 0 || varnum >= __INST_LAST) return NULL;
  return g_variables+varnum*g_stringsize;
}

