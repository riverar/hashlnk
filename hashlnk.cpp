/*
 * Copyright (c) 2012 Rafael Rivera
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

// An Anonymous fellow and Peter Bright (yes, that guy) helped me refactor.
// Appreciate it, sirs.

#include "stdafx.h"

// {7B2D8DFB-D190-344E-BF60-6EAC09922BBF}
DEFINE_PROPERTYKEY(PKEY_WINX_HASH, 0xFB8D2D7B, 0x90D1, 0x4E34, 0xBF, 0x60, 0x6E, 0xAC, 0x09, 0x92, 0x2B, 0xBF, 0x02);

#define CHECKHR(HR, MESSAGE) \
    if(FAILED(HR)) \
    { \
        if(MESSAGE) wprintf(L"%s (hr: %X)\r\n", MESSAGE, hr); \
        return HR; \
    }

#define GUID_MAX_LEN 40

using namespace std;

HRESULT GeneralizePath(const wchar_t*, wchar_t*, size_t);

int wmain(int argc, wchar_t* argv[])
{
    wprintf(
        L"\nHashLnk v0.2.0.0\n"
        L"Copyright(c) 2012 Rafael Rivera\n"
        L"Within Windows - http://withinwindows.com\n\n");

    if(argc != 2)
    {
        wprintf(L"usage: hashlnk <.lnk file>\n\n");
        return ERROR_BAD_ARGUMENTS;
    }

    DWORD bufferSize = GetFullPathNameW(argv[1], 0, nullptr, nullptr);
    if(bufferSize == 0)
    {
        wprintf(L"Specified path is invalid.");
        return ERROR_INVALID_PARAMETER;
    }

    unique_ptr<wchar_t[]> resolvedTarget(new wchar_t[bufferSize]);
    GetFullPathNameW(argv[1], bufferSize, resolvedTarget.get(), nullptr);

    if(!PathFileExistsW(resolvedTarget.get()))
    {
        wprintf(L"Specified file does not exist.");
        return ERROR_FILE_NOT_FOUND;
    }

    HRESULT hr = CoInitialize(nullptr);
    CHECKHR(hr, L"Failed to initialize COM.");

    //
    // Let's pull out the shortcut's target path/args
    //
    CComPtr<IShellItem2> lnk;
    hr = SHCreateItemFromParsingName(resolvedTarget.get(), nullptr, IID_PPV_ARGS(&lnk));
    CHECKHR(hr, L"Failed to create shell item.");

    CComHeapPtr<wchar_t> targetPath;
    hr = lnk->GetString(PKEY_Link_TargetParsingPath, &targetPath);
    CHECKHR(hr, L"Failed to retrieve target path.");

    unique_ptr<wchar_t[]> generalizedPath(new wchar_t[MAX_PATH]);
    hr = GeneralizePath(targetPath, generalizedPath.get(), MAX_PATH);
    if(FAILED(hr))
    {
        return hr;
    }

    CComHeapPtr<wchar_t> targetArgs;
    hr = lnk->GetString(PKEY_Link_Arguments, &targetArgs);
    if(FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
    {
        wprintf(L"Failed to retrieve target arguments.");
        return hr;
    }

    //
    // Glue everything together and lowercase it, so we can hash it.
    //
    const wchar_t salt[] = L"do not prehash links.  this should only be done by the user.";

    wstring blob = generalizedPath.get();
    if(targetArgs)
    {
        blob += targetArgs;
    }
    blob += salt;

    int lowerCaseLength = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, blob.data(), blob.size(), nullptr, 0, nullptr, nullptr, 0);
    if(!lowerCaseLength)
    {
        wprintf(L"Failed to lowercase blob string.");
        return GetLastError();
    }

    unique_ptr<wchar_t[]> hashableBlob(new wchar_t[lowerCaseLength]);
    LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, blob.data(), blob.size(), hashableBlob.get(), lowerCaseLength, nullptr, nullptr, 0);

    ULONG hash = 0;
    hr = HashData(reinterpret_cast<BYTE*>(hashableBlob.get()), lowerCaseLength * sizeof(wchar_t), reinterpret_cast<BYTE*>(&hash), sizeof(hash));
    CHECKHR(hr, L"Failed to hash data.");

    //
    // We have a hash, let's stamp it onto the .lnk now.
    //
    CComPtr<IPropertyStore> store;
    hr = lnk->GetPropertyStore(GPS_READWRITE, IID_PPV_ARGS(&store));
    CHECKHR(hr, L"Failed to get property store.");

    PROPVARIANT propValue = {0};
    propValue.ulVal = hash;
    propValue.vt = VT_UI4;

    hr = store->SetValue(PKEY_WINX_HASH, propValue);
    CHECKHR(hr, L"Failed to set property store value.");

    hr = store->Commit();
    CHECKHR(hr, L"Failed to write changes to .lnk.");

    wprintf(L"Hash generated and applied (0x%X)\n", hash);

    CoUninitialize();

    return 0;
}

HRESULT GeneralizePath(const wchar_t* originalPath, wchar_t* generalizedPath, size_t capacity)
{
    HRESULT hr = ERROR_SUCCESS;

    //
    // Do we need to do some trickery to get the Program Files
    // known folder?
    //
    BOOL isRunningUnderEmulation = FALSE;
    IsWow64Process(GetCurrentProcess(), &isRunningUnderEmulation);

    //
    // Because SHGetKnownFolderPath doesn't properly retrieve
    // FOLDERID_ProgramFilesX64 from 32-bit processes, I
    // abandoned its use. We'll use good ol' environment
    // variables instead. >_>. The FOLDERIDs are for
    // generalization purposes only.
    //
    // It sucks but not as much as distributing two
    // flavors of hashlnk.
    //
    
    KNOWNFOLDERID guids[3];
    wchar_t* tokens[3];

    if(isRunningUnderEmulation)
    {
        tokens[0] = L"%ProgramW6432%";
        guids[0] = FOLDERID_ProgramFilesX64;
    }
    else
    {
        tokens[0] = L"%ProgramFiles%";
        guids[0] = FOLDERID_ProgramFilesX86;
    }

    tokens[1] = L"%SystemRoot%\\System32";
    guids[1] = FOLDERID_System;

    tokens[2] = L"%SystemRoot%";
    guids[2] = FOLDERID_Windows;

    for(int i = 0; i < sizeof(guids) / sizeof(KNOWNFOLDERID); ++i)
    {
        unique_ptr<wchar_t[]> folderPath(new wchar_t[MAX_PATH]);
        
        int numCharsInPath = ExpandEnvironmentStringsW(tokens[i], folderPath.get(), MAX_PATH);
        if(numCharsInPath == 0)
        {
            CHECKHR(hr, L"Failed to resolve known folder location.");
        }

        --numCharsInPath; // Remove NULL terminator from count.

        int numCommonChars = PathCommonPrefixW(folderPath.get(), originalPath, NULL);
        if(numCommonChars < numCharsInPath)
        {
            continue;
        }

        unique_ptr<wchar_t[]> guid(new wchar_t[GUID_MAX_LEN]);
        if(!StringFromGUID2(guids[i], guid.get(), GUID_MAX_LEN))
        {
            hr = E_OUTOFMEMORY;
            CHECKHR(hr, L"Failed to derive string from known folder GUID.");
        }

        ZeroMemory(generalizedPath, capacity);

        hr = StringCchCatW(generalizedPath, MAX_PATH, guid.get());
        CHECKHR(hr, L"Failed to build generalized path.");

        hr = StringCchCatW(generalizedPath, MAX_PATH, originalPath + numCommonChars);
        CHECKHR(hr, L"Failed to build generalized path.");

        break;
    }

    return hr;
}
