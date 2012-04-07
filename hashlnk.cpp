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
        wprintf(L"%s (hr: %X)\r\n", MESSAGE, hr); \
        return HR; \
    }

using namespace std;

int wmain(int argc, wchar_t* argv[])
{
    wprintf(
        L"\nHashLnk v0.1.1.0\n"
        L"Copyright(c) 2012 Rafael Rivera\n"
        L"Within Windows - http://withinwindows.com\n\n");

    //
    // Before we go too far, let's see if we have a few things in order.
    //
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

    CComHeapPtr<wchar_t> targetArgs;
    hr = lnk->GetString(PKEY_Link_Arguments, &targetArgs);
    if(FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
    {
        wprintf(L"Failed to retrieve target arguments.");
        return hr;
    }
    wchar_t* targetPathSansRoot = PathSkipRootW(targetPath);

    //
    // Glue everything together and lowercase it, so we can hash it.
    //
    const wchar_t salt[] = L"do not prehash links.  this should only be done by the user.";

    wstring blob = targetPathSansRoot;
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

    wprintf(L"Hash generated and applied (0x%X)", hash);

    CoUninitialize();

    return 0;
}