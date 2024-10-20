#include "ProcessManager.h"

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch ( ul_reason_for_call )
	{
	case DLL_PROCESS_ATTACH:
		ProcessManager remoteProcessManager;								  // Construct our process manager class
		HANDLE systemToken = remoteProcessManager.GetTrustedInstallerToken(); // Get a token that has Trusted Installer privileges
		if ( !systemToken ) {
			MessageBoxA(NULL, "Got Trusted Installer Token?: No. Error.", "Status", MB_OK | MB_ICONEXCLAMATION);
			return FALSE;
		}

		MessageBoxA(NULL, "Got Trusted Installer Token?: Yes", "Status", MB_OK | MB_ICONINFORMATION);

		// Can be used to open processes under the Trusted Installer context.

		break;
	}
	return TRUE;
}

