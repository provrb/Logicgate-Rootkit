#ifndef _SANDBOX_COMP_
#define _SANDBOX_COMP_

#include "framework.h"

#include <vector>
//#include <random>

namespace SandboxCompromise 
{
	std::vector<const char*> suspiciousProcNames = { 
		"vmware.exe", 
		"xenservice.exe",
		"vmsrvc.exe",
		"vboxservice.exe",
		"joeboxserver.exe",
		"prl_cc.exe"
	};

	BOOL SuspicousProcRunning() 
	{
		//for ( const char* app : suspiciousProcNames )
		//	if ( ProcessUtilities::PIDFromName(app) != -1 )
		//		return TRUE;

		return FALSE;
	}

	void DelayOperation() {
		//std::random_device dev;
		//std::mt19937 random(dev());
		//std::uniform_int_distribution<std::mt19937::result_type> dist(35000, 45000);
		////Sleep(dist(random));
	}
}

#endif