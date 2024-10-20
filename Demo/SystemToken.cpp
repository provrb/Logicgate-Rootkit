#include "ProcessManager.h"

BOOL APIENTRY DllMain(HMODULE hModule,
					  DWORD  ul_reason_for_call,
					  LPVOID lpReserved
)
{
	switch ( ul_reason_for_call )
	{
	case DLL_PROCESS_ATTACH:		
		ProcessManager remoteProcessManager;						// Construct our process manager class
		HANDLE systemToken = remoteProcessManager.GetSystemToken(); // Get a token that has SYSTEM privileges
		if ( !systemToken ) {
			MessageBoxA(NULL, "Got System Token?: No. Error.", "Status", MB_OK | MB_ICONEXCLAMATION);
			return FALSE;
		}

		MessageBoxA(NULL, "Got System Token?: Yes", "Status", MB_OK | MB_ICONINFORMATION);

		// Can be used to open processes under the SYSTEM security context.

		break;
	}
	return TRUE;
}

