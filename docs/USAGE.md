# Windows Incident Response Collection

본 저장소는 KISA 「침해사고 분석 절차 안내서(2010-8호)」와  
「정보통신분야 침해사고 대응 안내서(2024.09)」를 기반으로 작성된  
Windows 사고 대응 자동화 수집 스크립트입니다.

## 기능
- 프로세스/네트워크 연결 수집
- 이벤트 로그(Security/System) 덤프
- 서비스 및 드라이버 목록 수집
- 자동 실행 레지스트리 추출
- 사용자 계정 및 세션 정보 수집

## 실행 방법
```powershell
.\scripts\IR_Collection.ps1
