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
