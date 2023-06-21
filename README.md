# Software Heap Vulnerability Analysis and Security

> Viewer Software를 타겟으로 분석을 진행
<br>

## Vulnerability Analysis
---

![image](https://github.com/Gyeongje/Data-Analysis-Capstone/assets/31283542/925ce784-1ad0-4346-ac03-12761ecdd8ad)
(그림 0. procmon을 통한 process 모니터링 과정)
![image](https://github.com/Gyeongje/Data-Analysis-Capstone/assets/31283542/f05f4856-d671-47f6-8e08-4b688815f93e)
(그림 1. 알씨 동적 링킹 라이브러리 목록)

해당 뷰어에서 여러 확장자를 지원하기에 수 많은 확장자 중 Adobe Photoshop의 기본 파일 포맷인 PSD file 분석을 먼저 진행했다.  
본격적으로 분석하기 전 Sysinternals suite에서 지원하는 Procmon을 통해 모든 파일 시스템 활동을 확인하였다.  
File 뷰어 특성상 file data를 read하기 때문에 operation을 readfile로 조건으로 삽입한 뒤, processing 과정을 (그림 0)과 같이 모니터링하였다.  
또한 (그림 0)에서 offset 0부터 4,2,1,4에 해당하는 size로 parsing 하는 작업을 보고 (그림 1)과 같이 세부적으로 파싱내용을 확인할 수 있었다.   
즉 Viewer.exe → A.dll → B.dll -> C.dll parsing fucntion(info -> load -> save) -> D.dll (library) 순서로 파싱이 진행되는 것을 알 수 있다.
<br><br>


### 1. A.dll (FileInfo)
---
``` c++
int __stdcall FileInfo(LPCWSTR lpFileName, int a2, int a3, int a4, int a5)
{
  int v5; // eax
  void (__cdecl *v6)(int); // esi
  int v7; // edi

  if ( !sub_61401520(lpFileName) )
    return L_FileInfo(lpFileName, a2, a3, a4, a5);
  v5 = sub_614047F0(lpFileName);
  if ( v5 )
  {
    v6 = *(void (__cdecl **)(int))(v5 + 644);
    v7 = *(_DWORD *)(v5 + 628);
    sub_61404AD0();
    v6(v7);
    return L_FileInfo(lpFileName, a2, a3, a4, a5);
  }
  return 0;
}
```
해당 A.dll에서 전반적인 File Info 데이터를 확인한다.  
실제로 sub_61401520 함수에서 CretaeFileW, GetFileSize를 체크하여 최소 헤더크기인 0x20보다 작을 시 CloseHanlde하는 코드를 확인할 수 있다.  
<br><br>

### 2. B.dll (file header 식별 및 알맞은 info,load dll 호출)
---
``` c++
  if ( v3 > 'SPB8' )
  {
    if ( v3 > (unsigned int)'\xFF\xFF\xFF\xFF\x95j\xA6Y' )
    {
      if ( v3 == '\xC6\xD3\xD0\xC5' )
        return 10;
    }
    else
    {
      switch ( v3 )
      {
        case '\x95j\xA6Y':
          return 16;
        case 'WMCL':
          return 57;
        case 'daeL':
          return 1;
      }
    }
  }
  else
  {
    if ( v3 == 'SPB8' )
      return 11;
```
B.dll은 file header를 식별하고 이에 알맞은 File의 info, load dll을 호출하는 라이브러리이다.  
위 코드를 보면 L_RedirectedRead(os_read)를 통해 File의 첫 DATA 부터 24 size만 v20에 read 받은 후 파일 헤더 검사를 진행한다. (“**SPB8**”은 PSD 파일의 헤더)  
<br>

``` c++
int (__stdcall *__usercall sub_1001E340@<eax>(int a1@<eax>))()
{
  L_DllLoader *v1; // esi
  int (__stdcall *result)(); // eax

  v1 = (L_DllLoader *)((char *)&unk_1002B090 + 16 * a1);
  if ( L_DllLoader::IsFunctionOk(v1, "fltInfo") )
    result = L_DllLoader::GetFunction(v1, "fltInfo");
  else
    result = 0;
  return result;
}
```
``` c++
int __usercall sub_1001F940@<eax>(int a1@<eax>, int a2)
{
  int *v3; // edi
  L_DllLoader *v4; // esi
  int (__stdcall *v5)(); // eax

  v3 = &dword_10029BD0[9 * a1];
  if ( !sub_1001E720() )
    return -16;
  v4 = (L_DllLoader *)((char *)&unk_1002B090 + 16 * a1);
  if ( L_DllLoader::IsFunctionOk(v4, "fltLoad") )
  {
    v5 = L_DllLoader::GetFunction(v4, "fltLoad");
    if ( v5 )
      return ((int (__stdcall *)(int))v5)(a2);
  }
  EnterCriticalSection(&CriticalSection);
  if ( L_DllLoader::IsLoaded((L_DllLoader *)((char *)&unk_1002B090 + 16 * *v3)) )
    --v3[4];
  LeaveCriticalSection(&CriticalSection);
  return -16;
}
```
또한 알맞은 DllLoader 하는 부분을 확인하였고, 실질적인 data 수집은 위와 같은 코드처럼 알맞은 확장자의 동적 링킹 라이브러리를 로드하여 이루어진다.  
<br>

### C.dll (parsing fucntion)
---
``` c++
int __stdcall fltInfo(_DWORD *a1)
{
  ...
  v24 = 0;
  char v28[15]; // [esp+74h] [ebp-24h] BYREF
  ...
  
  L_RedirectedSeek(v1, 0, 0);
  if ( L_RedirectedRead(a1[2], v28, 30) != 30 )
    return -7;
  if ( v28[0] != '8' || v28[1] != 'B' || v28[2] != 'P' || v28[3] != 'S' )
    return -9;
  LOBYTE(v3) = 0;
  HIBYTE(v3) = v28[4];
  v4 = (unsigned __int8)v28[5] | v3;
  LOBYTE(v3) = 0;
  HIBYTE(v3) = v28[12];
  LOBYTE(v5) = 0;
  HIBYTE(v5) = v37;
  *(_WORD *)&v28[4] = v4;
  v6 = (unsigned __int8)v28[13] | v3;
  v7 = HIBYTE(v37) | v5;
  LOBYTE(v8) = 0;
  HIBYTE(v8) = v36;
  *(_WORD *)&v28[12] = v6;
  v37 = v7;
  v36 = HIBYTE(v36) | v8;
  v38 = HIBYTE(v38) | ((BYTE2(v38) | ((BYTE1(v38) | ((unsigned __int8)v38 << 8)) << 8)) << 8);

  ...
}
```
위 코드와 같이 fltinfo 함수에서 PSD에 알맞은 FIle Header Structure Data를 parsing한다.
