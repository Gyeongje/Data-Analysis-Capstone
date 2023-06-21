# Software Heap Vulnerability Analysis and Security

> Viewer Software를 타겟으로 분석을 진행
<br>

## Vulnerability Analysis
---

해당 뷰어에서 여러 확장자를 지원하기에 수 많은 확장자 중 Adobe Photoshop의 기본 파일 포맷인 PSD file 분석을 먼저 진행했다.
Sysinternals suite에서 지원하는 Procmon을 통해 모든 파일 시스템 활동을 실시간으로 모니터


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
