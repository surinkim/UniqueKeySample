// UniqueKeySample.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <Windows.h>
#include <iostream>
#include <WbemCli.h>

#include <openssl\md5.h>

#pragma comment(lib, "wbemuuid.lib")

using namespace std;

IWbemLocator* pLocator = NULL;
IWbemServices* pService = NULL;

std::wstring biosId;
std::wstring boardId;
std::wstring processorId;

auto Init = [&]() -> bool
{
	HRESULT hRes = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hRes))
	{
		cout << "Unable to launch COM: 0x" << std::hex << hRes << endl;
		return false;
	}

	if ((FAILED(hRes = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, 0))))
	{
		cout << "Unable to initialize security: 0x" << std::hex << hRes << endl;
		return false;
	}

	if (FAILED(hRes = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_ALL, IID_PPV_ARGS(&pLocator))))
	{
		cout << "Unable to create a WbemLocator: " << std::hex << hRes << endl;
		return false;
	}

	if (FAILED(hRes = pLocator->ConnectServer(L"root\\CIMV2", NULL, NULL, NULL, WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &pService)))
	{
		pLocator->Release();
		cout << "Unable to connect to \"CIMV2\": " << std::hex << hRes << endl;
		return false;
	}

	return true;
};

auto GetUniqueInfo = [&](WCHAR* query, WCHAR* prop, wstring& value) -> bool
{
	HRESULT hRes = S_OK;
	IEnumWbemClassObject* pEnumerator = NULL;
	if (FAILED(hRes = pService->ExecQuery(L"WQL", query, WBEM_FLAG_FORWARD_ONLY, NULL, &pEnumerator)))
	{
		pLocator->Release();
		pService->Release();
		cout << "Unable to retrive '" << query << "': " << std::hex << hRes << endl;
		return false;
	}

	IWbemClassObject* clsObj = NULL;
	int numElems;
	while ((hRes = pEnumerator->Next(WBEM_INFINITE, 1, &clsObj, (ULONG*)&numElems)) != WBEM_S_FALSE)
	{
		if (FAILED(hRes))
			break;

		VARIANT vRet;
		VariantInit(&vRet);
		if (SUCCEEDED(clsObj->Get(prop, 0, &vRet, NULL, NULL)) && vRet.vt == VT_BSTR)
		{
			std::wcout << prop << ": " << vRet.bstrVal << endl;

			value = vRet.bstrVal;
			VariantClear(&vRet);
		}
		else
		{
			std::wcout << "Get " << prop << " failed." << endl;
		}

		clsObj->Release();
	}

	pEnumerator->Release();
	return true;
};

auto MakeMD5Key = [&](wstring key, wchar_t* mdstring, int size) -> bool
{
	unsigned char digest[16];

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, key.c_str(), key.length());
	MD5_Final(digest, &ctx);

	for (int i = 0; i < (size/2); i++)
		swprintf_s(&mdstring[i * 2], size, L"%02x", (unsigned int)digest[i]);

	return true;

};

int main()
{
	if (!Init())
	{
		return -1;
	}
	
	wstring biosId, boardId, processId;
	if (!GetUniqueInfo(L"SELECT * FROM Win32_BIOS", L"SerialNumber", biosId) ||
		!GetUniqueInfo(L"SELECT * FROM Win32_BaseBoard", L"SerialNumber", boardId) ||
		!GetUniqueInfo(L"SELECT * FROM Win32_Processor", L"ProcessorId", processId))
	{
		pService->Release();
		pLocator->Release();
	}

	/*char keyA[MAX_PATH];
	wstring key = biosId + boardId + processId;
	if (!WideCharToMultiByte(CP_UTF8,
		0,
		key.c_str(),
		key.length(),
		keyA,
		MAX_PATH,
		NULL,
		NULL)) {
		return 0;
	}*/

	wstring key = biosId + boardId + processId;
	wchar_t mdValue[33];
	if (!MakeMD5Key(key, mdValue, 33))
	{
		return -1;
	}

	wcout << "md5 key : " << mdValue << endl;

	getchar();

	return 0;
}
