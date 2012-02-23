/*
*
* Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
* Licensed under a 3 clause BSD license (Please see LICENSE.txt)
* Source code located at https://github.com/stephenfewer/grinder
*
*/
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "ReflectiveLoader.h"
// REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are defined.

extern HINSTANCE hAppInstance;

HANDLE hLog = NULL;

char * cpLogFile = NULL;

DWORD dwThrottle = 0;

__declspec(dllexport) VOID LOGGER_setThrottle( DWORD dwMilliseconds )
{
	dwThrottle = dwMilliseconds;
}

__declspec(dllexport) VOID LOGGER_setLogFile( char * cpFile )
{
	if( cpFile )
	{
		if( cpLogFile )
		{
			free( cpLogFile );
			cpLogFile = NULL;
		}

		cpLogFile = (char *)malloc( strlen(cpFile) + 1 );
		if( cpLogFile )
		{
			strcpy_s( cpLogFile, strlen(cpFile) + 1, cpFile );
		}
	}
}

__declspec(dllexport) VOID LOGGER_finishedTest( wchar_t * cpMessageW )
{
	do
	{
		if( !hLog )
			break;

		CloseHandle( hLog );

		hLog = NULL;

	} while( 0 );
}

__declspec(dllexport) VOID LOGGER_logMessage( wchar_t * cpMessageW )
{
	char cMessageA[8192];
	int lenW;
	int lenA;

	do
	{
		if( !cpMessageW )
			break;

		lenW = wcslen( cpMessageW ) + 1;

		lenA = WideCharToMultiByte( CP_ACP, 0, cpMessageW, lenW, 0, 0, NULL, NULL );

		if( lenA > 8192 )
			break;

		WideCharToMultiByte( CP_ACP, 0, cpMessageW, lenW, (LPSTR)&cMessageA, lenA, NULL, NULL);
		
		cMessageA[lenA] = 0;

		if( !hLog && cpLogFile )
		{
			hLog = CreateFile( cpLogFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
			if( hLog == INVALID_HANDLE_VALUE )
			{
				hLog = NULL;
			}
		}

		if( hLog )
		{
			DWORD dwTotal   = 0;
			DWORD dwWritten = 0;
			DWORD dwLength  = strlen( cMessageA );

			while( dwTotal < dwLength )
			{
				if( !WriteFile( hLog, (LPCVOID)((LPBYTE)((char *)&cMessageA + dwTotal)), (dwLength - dwTotal), &dwWritten, NULL ) )
					break;
				dwTotal += dwWritten;
			}
		}

	} while( 0 );

	if( dwThrottle )
	{
		Sleep( dwThrottle );
	}
}
