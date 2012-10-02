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

BOOL CALLBACK enumproc( HWND hWnd, LPARAM lParam )
{
	int ret = 0;
	char cString[4096];

	do
	{
		ret = GetWindowText( hWnd, (LPSTR)&cString, 4096 );
		if( !ret )
			break;

		//printf( "cString = %s.\n", cString );

		if( strcmp( cString, "&Leave this page" ) == 0 )
		{
			SendMessage( hWnd, BM_CLICK, 0 , 0 );
			return FALSE;
		}
		else if( strcmp( cString, "Close the program" ) == 0 )
		{
			SendMessage( hWnd, BM_CLICK, 0 , 0 );
			return FALSE;
		}
		else if( strcmp( cString, "Quit Firefox" ) == 0 )
		{
			SendMessage( hWnd, BM_CLICK, 0 , 0 );
			return FALSE;
		}

	} while(0);

	return TRUE;
}


void main( void )
{
	while( TRUE )
	{
		// Automatically close the IE8 'Stop running this script?' dialog.
		HWND hWindow = FindWindow( NULL, "Windows Internet Explorer" );
		if( hWindow )
		{
			HWND hButton = FindWindowEx( hWindow, 0, "Button", "&No" );
			if( hButton )
			{
				SendMessage( hButton, BM_CLICK, 0 , 0 );
			}
			else
			{
				EnumChildWindows( hWindow, enumproc, 0 );				
			}
		}

		hWindow = FindWindow( NULL, "Microsoft Windows" );
		if( hWindow )
		{
			EnumChildWindows( hWindow, enumproc, 0 );
		}

		// Automatically cancels the Adobe Reader 'Print' dialog.
		hWindow = FindWindow( NULL, "Print" );
		if( hWindow )
		{
			HWND hButton = FindWindowEx( hWindow, 0, "Button", "Cancel" );
			if( hButton )
				SendMessage( hButton, BM_CLICK, 0 , 0 );
		}

		// Automatically cancels the Adobe Reader 'Print' dialog.
		hWindow = FindWindow( NULL, "Security Block" );
		if( hWindow )
		{
			HWND hButton = FindWindowEx( hWindow, 0, "Button", "OK" );
			if( hButton )
				SendMessage( hButton, BM_CLICK, 0 , 0 );
		}

		// Automatically cancels the Firefox 'Unresponsive script' dialog.
		hWindow = FindWindow( NULL, "Warning: Unresponsive script" );
		if( hWindow )
		{
			// cant find the 'Continue' button
		}

		hWindow = FindWindow( NULL, "WebKit2WebProcess.exe" );
		if( hWindow )
			EnumChildWindows( hWindow, enumproc, 0 );
		
		hWindow = FindWindow( NULL, "Internet Explorer" );
		if( hWindow )
			EnumChildWindows( hWindow, enumproc, 0 );

		hWindow = FindWindow( NULL, "Are you sure?" );
		if( hWindow )
		{
			SendMessage( hWindow, WM_KEYDOWN, VK_RETURN, 0 );
		}

		hWindow = FindWindow( NULL, "Google Chrome" );
		if( hWindow )
		{
			EnumChildWindows( hWindow, enumproc, 0 );
		}

		hWindow = FindWindow( NULL, "Mozilla Crash Reporter" );
		if( hWindow )
		{
			EnumChildWindows( hWindow, enumproc, 0 );
		}

		Sleep( 250 );
	}
}