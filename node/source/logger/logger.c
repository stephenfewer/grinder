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

HANDLE hLog                         = NULL;

char * cpLogFile                    = NULL;

char * cpLogMessage                 = NULL;

DWORD dwLogMessageSize              = 0;

DWORD dwThrottle                    = 0;

LPCRITICAL_SECTION pCriticalSection = NULL;

BOOL LOGGER_init( VOID )
{
	BOOL bSuccess = FALSE;

	do
	{
		if( !pCriticalSection )
		{
			pCriticalSection = (LPCRITICAL_SECTION)malloc( sizeof(CRITICAL_SECTION) );
			if( !pCriticalSection )
				break;

			InitializeCriticalSection( pCriticalSection );
		}

		if( !cpLogMessage )
		{
			cpLogMessage = (char * )malloc( 8192 );
			if( !cpLogMessage )
				break;

			dwLogMessageSize = 8192;

			memset( cpLogMessage, 0, dwLogMessageSize );
		}

		bSuccess = TRUE;

	} while( 0 );
	
	return bSuccess;
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
	switch( dwReason ) 
    { 
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			bReturnValue = LOGGER_init();
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}

__declspec(dllexport) VOID LOGGER_setThrottle( DWORD dwMilliseconds )
{
	EnterCriticalSection( pCriticalSection );

	dwThrottle = dwMilliseconds;

	LeaveCriticalSection( pCriticalSection );
}

__declspec(dllexport) VOID LOGGER_setLogFile( char * cpFile )
{
	EnterCriticalSection( pCriticalSection );

	do
	{
		if( !cpFile )
			break;

		if( cpLogFile )
		{
			free( cpLogFile );

			cpLogFile = NULL;
		}

		cpLogFile = (char *)malloc( strlen(cpFile) + 1 );
		if( !cpLogFile )
			break;

		strcpy_s( cpLogFile, strlen(cpFile) + 1, cpFile );

	} while( 0 );

	LeaveCriticalSection( pCriticalSection );
}

__declspec(dllexport) VOID LOGGER_finishedTest( wchar_t * cpMessageW )
{
	EnterCriticalSection( pCriticalSection );

	do
	{
		if( !hLog )
			break;

		CloseHandle( hLog );

		hLog = NULL;

	} while( 0 );

	LeaveCriticalSection( pCriticalSection );
}

__declspec(dllexport) VOID LOGGER_logMessage( wchar_t * cpMessageW )
{
	DWORD lenW;
	DWORD lenA;

	EnterCriticalSection( pCriticalSection );

	do
	{
		if( !cpMessageW )
			break;

		lenW = wcslen( cpMessageW ) + 1;

		lenA = WideCharToMultiByte( CP_ACP, 0, cpMessageW, lenW, 0, 0, NULL, NULL );

		if( lenA > dwLogMessageSize )
		{
			if( cpLogMessage )
			{
				memset( cpLogMessage, 0, dwLogMessageSize );

				free( cpLogMessage );
			}

			dwLogMessageSize = lenA + ( 1024 - ( lenA % 1024 ) );

			cpLogMessage = (char * )malloc( dwLogMessageSize );
			if( !cpLogMessage )
			{
				dwLogMessageSize = 0;
				break;
			}

			memset( cpLogMessage, 0, dwLogMessageSize );
		}

		WideCharToMultiByte( CP_ACP, 0, cpMessageW, lenW, cpLogMessage, lenA, NULL, NULL );
		
		cpLogMessage[lenA] = 0;

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
			DWORD dwLength  = strlen( cpLogMessage );

			while( dwTotal < dwLength )
			{
				if( !WriteFile( hLog, (LPCVOID)((LPBYTE)(cpLogMessage + dwTotal)), (dwLength - dwTotal), &dwWritten, NULL ) )
					break;

				dwTotal += dwWritten;
			}
		}

	} while( 0 );

	if( dwThrottle )
	{
		Sleep( dwThrottle );
	}

	LeaveCriticalSection( pCriticalSection );
}
