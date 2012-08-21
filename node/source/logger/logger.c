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
#include "ReflectiveLoader.h"

// REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are defined.

extern HINSTANCE hAppInstance;

typedef BOOL (* HEAPFLUSH)();

HANDLE hLog                         = NULL;

char * cpLogFile                    = NULL;

char * cpLogMessage                 = NULL;

HEAPFLUSH pHeapFlush                = NULL;

DWORD dwLogMessageSize              = 0;

DWORD dwThrottle                    = 0;

LPCRITICAL_SECTION pCriticalSection = NULL;

/*
 * Print debug output.
 */
VOID dprintf( char * cpFormat, ... )
{
	va_list vArgs;
	char cBuffer[1024];
	
	va_start( vArgs, cpFormat );

	vsnprintf_s( cBuffer, sizeof(cBuffer), sizeof(cBuffer) - 3, cpFormat, vArgs );

	va_end( vArgs );

	strcat_s( cBuffer, sizeof(cBuffer), "\r\n" );

	OutputDebugString( cBuffer );

	//printf( "%s", cBuffer );
}

BOOL LOGGER_init( VOID )
{
	BOOL bSuccess = FALSE;

	do
	{
		if( !pCriticalSection )
		{
			pCriticalSection = (LPCRITICAL_SECTION)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CRITICAL_SECTION) );
			if( !pCriticalSection )
				break;

			InitializeCriticalSection( pCriticalSection );
		}

		if( !cpLogMessage )
		{
			cpLogMessage = (char * )HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 8192 );
			if( !cpLogMessage )
				break;

			dwLogMessageSize = 8192;
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

__declspec(dllexport) VOID LOGGER_setHeapFlush( HEAPFLUSH pFunction )
{
	EnterCriticalSection( pCriticalSection );

	pHeapFlush = pFunction;

	LeaveCriticalSection( pCriticalSection );
}

__declspec(dllexport) VOID LOGGER_setThrottle( DWORD dwMilliseconds )
{
	EnterCriticalSection( pCriticalSection );

	dwThrottle = dwMilliseconds;

	LeaveCriticalSection( pCriticalSection );
}

__declspec(dllexport) VOID LOGGER_setLogFile( char * cpFile )
{
	DWORD dwSize;
	
	EnterCriticalSection( pCriticalSection );

	do
	{
		if( !cpFile )
			break;

		if( cpLogFile )
			HeapFree( GetProcessHeap(), 0, cpLogFile );

		dwSize = strlen( cpFile ) + 1;

		cpLogFile = (char *)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize );
		if( !cpLogFile )
			break;

		strcpy_s( cpLogFile, dwSize, cpFile );

	} while( 0 );

	LeaveCriticalSection( pCriticalSection );
}

VOID logMessage( wchar_t * cpMessageW )
{
	DWORD dwLengthW;
	DWORD dwLengthA;
	DWORD dwTotal;
	DWORD dwWritten;

	do
	{
		if( !cpMessageW )
			break;

		dwLengthW = wcslen( cpMessageW ) + 1;

		dwLengthA = WideCharToMultiByte( CP_ACP, 0, cpMessageW, dwLengthW, 0, 0, NULL, NULL );

		if( dwLengthA > dwLogMessageSize )
		{
			if( cpLogMessage )
			{
				RtlZeroMemory( cpLogMessage, dwLogMessageSize );

				HeapFree( GetProcessHeap(), 0, cpLogMessage );
			}

			dwLogMessageSize = dwLengthA + ( 1024 - ( dwLengthA % 1024 ) );

			cpLogMessage = (char * )HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwLogMessageSize );
			if( !cpLogMessage )
			{
				dwLogMessageSize = 0;
				break;
			}
		}

		WideCharToMultiByte( CP_ACP, 0, cpMessageW, dwLengthW, cpLogMessage, dwLengthA, NULL, NULL );
		
		cpLogMessage[dwLengthA] = 0;

		if( !hLog && cpLogFile )
		{
			hLog = CreateFile( cpLogFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
			if( hLog == INVALID_HANDLE_VALUE )
				hLog = NULL;
		}

		if( !hLog )
			break;

		dwTotal    = 0;
		
		dwWritten  = 0;

		dwLengthA -= 1;

		while( dwTotal < dwLengthA )
		{
			if( !WriteFile( hLog, (LPCVOID)((BYTE *)(cpLogMessage + dwTotal)), (dwLengthA - dwTotal), &dwWritten, NULL ) )
				break;

			dwTotal += dwWritten;
		}

	} while( 0 );

	if( dwThrottle )
	{
		Sleep( dwThrottle );
	}
}

__declspec(dllexport) VOID LOGGER_startingTest( wchar_t * cpMessageW )
{
	EnterCriticalSection( pCriticalSection );

	do
	{
		if( pHeapFlush )
			pHeapFlush();

		logMessage( cpMessageW );

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

		logMessage( cpMessageW );

		CloseHandle( hLog );

		hLog = NULL;

	} while( 0 );

	LeaveCriticalSection( pCriticalSection );
}

__declspec(dllexport) VOID LOGGER_logMessage( wchar_t * cpMessageW )
{
	EnterCriticalSection( pCriticalSection );

	logMessage( cpMessageW );

	LeaveCriticalSection( pCriticalSection );
}

__declspec(dllexport) DWORD * LOGGER_FuzzerIdx = (DWORD *)-1;

__declspec(dllexport) VOID LOGGER_logMessage2( wchar_t * cpMessageW, DWORD dwIdx )
{
	EnterCriticalSection( pCriticalSection );
	
	InterlockedExchange( (DWORD *)&LOGGER_FuzzerIdx, dwIdx );

	logMessage( cpMessageW );

	LeaveCriticalSection( pCriticalSection );
}
