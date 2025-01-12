#include "searchCode.h"
/*
	���������ƥ�亯������
*/
//����ģ��Ļ�ַ
ULONG_PTR querySystemModule(PUCHAR moduleName, OUT PULONG size) {
	RTL_PROCESS_MODULES pModule = { 0 };
	ULONG retLen = 0;
	PVOID moduleBase = NULL;
	PRTL_PROCESS_MODULES sysModule = &pModule;
	//DbgBreakPoint();
	//�ж��Ҵ����ģ����������Ϊ�գ�Ϊ���򷵻�0
	if (strlen(moduleName) == 0) { DbgPrint("��ѯ��ģ��������Ϊ��\r\n"); return 0; }

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, sysModule, sizeof(RTL_PROCESS_MODULES), &retLen);
	//����ѯ
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		ULONG len = retLen + sizeof(RTL_PROCESS_MODULES);
		sysModule = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, len);
		if (!sysModule) { DbgPrint("�ڴ�����ʧ��\r\n");return 0; }
		//����ɹ��Ļ� ��ʼ������ڴ�
		memset(sysModule, 0, len);

		//����������²�ѯһ��
		status = ZwQuerySystemInformation(SystemModuleInformation, sysModule, len, &retLen);
		if (!NT_SUCCESS(status)) { ExFreePool(sysModule); DbgPrint("ģ���ѯʧ��\r\n"); return 0; }
		//ת����Сд
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
	//��ѯʧ���򷵻� 0
	DbgPrint("Not Found!!!\r\n");
	return 0;
}

//���������뷵�غ�����ַ
ULONG_PTR searchCode(IN PUCHAR moduleName, IN PUCHAR code, IN PUCHAR sectionName, IN INT offset) {
	TzmCode tzmCode[1] = { 0 };
	initTzmCode(&tzmCode, code, 0, offset);
	ULONG size = 0;
	ULONG moduleBase = querySystemModule(moduleName, &size);
	//DbgBreakPoint();
	if (!moduleBase) return 0;
	//��ʼPE����ģ��
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;

	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + pDos->e_lfanew);

	//�õ���һ���ڱ��λ��
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNts);
	PIMAGE_SECTION_HEADER pResult = NULL;
	
	//ѭ�������ڱ�����������Ľڵ�������ͬʱ���ص�ǰ�ڱ�
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
//������Աȴ���
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

			//����ͨ����ǰ���ڵĵ�ַ+������ƫ�Ƶ�λ�õõ���ʵ���ڴ��е�һ��λ��
			UCHAR* code = (UCHAR*)(tempAddress + fc.offset);
			BOOLEAN isFlags = FALSE;

			//����Ƚ��Ҵ�����������ʵ���ڴ��е�ֵ
			for (ULONG_PTR k = 0; k < fc.len; k++)
			{
				if (!MmIsAddressValid((PVOID)(code + k)))
				{
					isFlags = TRUE;
					break;
				}
				//���������������*���ߣ���ô��������ȥ�Ƚ�
				if (fc.code[k] == '*' || fc.code[k] == '?') continue;

				//�����ǰʵ���ڴ��ֵ���Ҵ����������Ӧλ�õ�ֵ�����������ѭ��
				if (code[k] != fc.code[k])
				{
					isFlags = TRUE;
					break;
				}
			}

			if (isFlags) break;

		}
		//����ֻ�е�j�ɹ�ѭ������Ӧ�Ĵ����������ʱ�򣬲��ǳɹ�ƥ�䵽
		if (j == numbers)
		{
			rtna.QuadPart = i;
			rtna.LowPart += findCode[0].lastAddressOffset;
			break;
		}

	}

	return rtna.QuadPart;
}
//�������hex�ַ���ת����hex
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