#include "searchCode.h"
/*
	火哥特征码匹配函数工具
*/
//返回模块的基址
ULONG_PTR querySystemModule(PUCHAR moduleName, OUT PULONG size) {
	RTL_PROCESS_MODULES pModule = { 0 };
	ULONG retLen = 0;
	PVOID moduleBase = NULL;
	PRTL_PROCESS_MODULES sysModule = &pModule;
	//DbgBreakPoint();
	//判断我传入的模块名，不能为空，为空则返回0
	if (strlen(moduleName) == 0) { DbgPrint("查询的模块名不能为空\r\n"); return 0; }

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, sysModule, sizeof(RTL_PROCESS_MODULES), &retLen);
	//当查询
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		ULONG len = retLen + sizeof(RTL_PROCESS_MODULES);
		sysModule = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, len);
		if (!sysModule) { DbgPrint("内存申请失败\r\n");return 0; }
		//申请成功的话 初始化这块内存
		memset(sysModule, 0, len);

		//这里就在重新查询一次
		status = ZwQuerySystemInformation(SystemModuleInformation, sysModule, len, &retLen);
		if (!NT_SUCCESS(status)) { ExFreePool(sysModule); DbgPrint("模块查询失败\r\n"); return 0; }
		//转换成小写
		_strlwr(moduleName);
		if (strstr(moduleName, "ntkrnlpa.exe") || strstr(moduleName, "ntoskrnl.exe"))
		{
			PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = &(sysModule->Modules[0]);
			moduleBase = ModuleInfo->ImageBase;
			*size = ModuleInfo->ImageSize;
			return moduleBase;
		}

		for (int i = 0;i < sysModule->NumberOfModules;i++)
		{
			PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = &(sysModule->Modules[i]);
			PUCHAR pathName = _strlwr(ModuleInfo->FullPathName);
			DbgPrintEx(77, 0, "baseName = %s,fullPath = %s\r\n", ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName, ModuleInfo->FullPathName);

			if (strstr(ModuleInfo->FullPathName, moduleName))
			{
				moduleBase = ModuleInfo->ImageBase;
				*size = ModuleInfo->ImageSize;
				ExFreePool(sysModule);
				return moduleBase;

			}
		}
	}
	//查询失败则返回 0
	DbgPrint("Not Found!!!\r\n");
	return 0;
}

//搜索特征码返回函数地址
ULONG_PTR searchCode(IN PUCHAR moduleName, IN PUCHAR code, IN PUCHAR sectionName, IN INT offset) {
	TzmCode tzmCode[1] = { 0 };
	initTzmCode(&tzmCode, code, 0, offset);
	ULONG size = 0;
	ULONG moduleBase = querySystemModule(moduleName, &size);
	//DbgBreakPoint();
	if (!moduleBase) return 0;
	//开始PE解析模块
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;

	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + pDos->e_lfanew);

	//拿到第一个节表的位置
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNts);
	PIMAGE_SECTION_HEADER pResult = NULL;
	
	//循环遍历节表，当和你输入的节的名称相同时返回当前节表
	for (int i = 0; i < pNts->FileHeader.NumberOfSections; i++)
	{
		char bufName[9] = { 0 };
		memcpy(bufName, pSection->Name, 8);
		//DbgBreakPoint();
		if (_stricmp(bufName, sectionName) == 0)
		{
			//DbgBreakPoint();
			pResult = pSection;
			break;
		}
		pSection++;
	}

	if (pResult)
	{
		moduleBase += pResult->VirtualAddress;
		size = pResult->SizeOfRawData;
	}
	//DbgBreakPoint();
	ULONG_PTR funAddr = findAddressByCode(moduleBase, moduleBase + size, tzmCode, 1);
	
	return funAddr;

}

VOID initTzmCode(PTzmCode findCode, PCHAR code, ULONG_PTR offset, ULONG_PTR lastAddrOffset) {
	//initTzmCode(&tzmCode, code, 0, offset);
	memset(findCode, 0, sizeof(TzmCode));
	
	findCode->lastAddressOffset = lastAddrOffset; //
	findCode->offset = offset;

	PCHAR pTemp = code;
	ULONG_PTR i = 0;
	for (i = 0; *pTemp != '\0'; i++)
	{
		if (*pTemp == '*' || *pTemp == '?')
		{
			findCode->code[i] = *pTemp;
			pTemp++;
			continue;
		}

		findCode->code[i] = charToHex(pTemp);
		pTemp += 2;

	}

	findCode->len = i;
}
//特征码对比代码
ULONG_PTR findAddressByCode(ULONG_PTR beginAddr, ULONG_PTR endAddr, PTzmCode findCode, ULONG numbers)
{
	ULONG64 j = 0;
	LARGE_INTEGER rtna = { 0 };

	for (ULONG_PTR i = beginAddr; i <= endAddr; i++)
	{
		if (!MmIsAddressValid((PVOID)i))
		{
			i = i & (~0xfff) + PAGE_SIZE - 1;
			continue;
		}

		for (j = 0; j < numbers; j++)
		{
			TzmCode  fc = findCode[j];
			ULONG_PTR tempAddress = i;

			//这里通过当前所在的地址+函数里偏移的位置得到在实际内存中的一个位置
			UCHAR* code = (UCHAR*)(tempAddress + fc.offset);
			BOOLEAN isFlags = FALSE;

			//这里比较我传入的特征码和实际内存中的值
			for (ULONG_PTR k = 0; k < fc.len; k++)
			{
				if (!MmIsAddressValid((PVOID)(code + k)))
				{
					isFlags = TRUE;
					break;
				}
				//特征码中如果存在*或者？那么就跳过不去比较
				if (fc.code[k] == '*' || fc.code[k] == '?') continue;

				//如果当前实际内存的值和我传入特征码对应位置的值不相等则跳出循环
				if (code[k] != fc.code[k])
				{
					isFlags = TRUE;
					break;
				}
			}

			if (isFlags) break;

		}
		//这里只有当j成功循环到对应的代码段数量的时候，才是成功匹配到
		if (j == numbers)
		{
			rtna.QuadPart = i;
			rtna.LowPart += findCode[0].lastAddressOffset;
			break;
		}

	}

	return rtna.QuadPart;
}
//将传入的hex字符串转换成hex
UCHAR charToHex(UCHAR* ch)
{
	unsigned char temps[2] = { 0 };
	for (int i = 0; i < 2; i++)
	{
		if (ch[i] >= '0' && ch[i] <= '9')
		{
			temps[i] = (ch[i] - '0');
		}
		else if (ch[i] >= 'A' && ch[i] <= 'F')
		{
			temps[i] = (ch[i] - 'A') + 0xA;
		}
		else if (ch[i] >= 'a' && ch[i] <= 'f')
		{
			temps[i] = (ch[i] - 'a') + 0xA;
		}
	}
	return ((temps[0] << 4) & 0xf0) | (temps[1] & 0xf);
}