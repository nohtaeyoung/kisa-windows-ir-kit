<# 
KISA-Windows-IR.ps1
- 기능: Windows 사고 현장 기본 아티팩트 자동 수집
- 수집 항목(요구사항 대응):
  1) 실행 중 프로세스
  2) 네트워크 연결 (TCP/UDP, 리스닝/세션)
  3) 이벤트 로그 (보안, 시스템) - 원본 .evtx + 요약 CSV
  4) 서비스/드라이버 목록
  5) 자동 실행 레지스트리 (HKLM/HKCU Run* 등 주요 지점)
  6) 사용자 계정/세션 정보
- 출력: C:\IR_Collection\<HOST>_<YYYYMMDD_HHMMSS>\ 이하 txt/csv/evtx로 저장
- 권장: 관리자 권한 실행, 오프라인 매체에 수집 후 보관
#>

# region 준비
# 관리자 권한 확인
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
  Write-Host "[!] 관리자 권한으로 PowerShell을 다시 실행하세요." -ForegroundColor Yellow
  exit 1
}

# 타임스탬프/출력 폴더
$ts   = Get-Date -Format "yyyyMMdd_HHmmss"
$host = $env:COMPUTERNAME
$base = "C:\IR_Collection\${host}_$ts"
New-Item -ItemType Directory -Path $base -Force | Out-Null

# 로깅 함수
Function Out-FileUtf8($Path, $Content) {
  $dir = Split-Path -Parent $Path
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $Content | Out-File -FilePath $Path -Encoding UTF8 -Width 4096
}

# 수집 시간 범위(최근 N시간 이벤트 파싱용)
param([int]$Hours = 72)
$StartTime = (Get-Date).AddHours(-1 * $Hours)

# endregion

# region 1) 프로세스
try {
  Get-Process | Sort-Object ProcessName |
    Select-Object Name, Id, Path, StartTime, `
      @{n='Company';e={$_.Company}}, `
      @{n='Product';e={$_.ProductVersion}} |
    Format-Table -Auto | Out-String |
    Out-FileUtf8 "$base\01_processes.txt"

  # 모듈(DLL) 개요: 관리자 필요, 실패 허용
  Get-Process | ForEach-Object {
    try {
      $_.Modules | Select-Object @{n='Process';e={$_.FileName}}, ModuleName, FileName
    } catch {}
  } | Export-Csv -NoTypeInformation -Encoding UTF8 "$base\01_process_modules.csv"
} catch { Write-Warning "Process collection error: $_" }
# endregion

# region 2) 네트워크
try {
  # TCP/UDP 연결
  Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$base\02_net_tcp.csv"
  Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$base\02_net_udp.csv"

  # 프로세스 매핑(간단 조인)
  $procs = Get-Process | Select-Object Id, ProcessName, Path
  Import-Csv "$base\02_net_tcp.csv" | ForEach-Object {
    $p = $procs | Where-Object Id -eq $_.OwningProcess
    $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue $p.ProcessName -Force
    $_ | Add-Member -NotePropertyName ProcessPath -NotePropertyValue $p.Path -Force
    $_
  } | Export-Csv -NoTypeInformation -Encoding UTF8 "$base\02_net_tcp_with_proc.csv"

  # 보조 정보
  ipconfig /all > "$base\02_ipconfig.txt"
  arp -a          > "$base\02_arp.txt"
  route print     > "$base\02_route.txt"
  netstat -naob   > "$base\02_netstat_naob.txt"  # 포트/프로세스/모듈
} catch { Write-Warning "Network collection error: $_" }
# endregion

# region 3) 이벤트 로그(보안/시스템)
try {
  $evtxDir = "$base\03_events\evtx"
  New-Item -ItemType Directory -Path $evtxDir -Force | Out-Null

  # 원본 내보내기(전체 로그 보존)
  wevtutil epl Security "$evtxDir\Security.evtx"
  wevtutil epl System   "$evtxDir/System.evtx"

  # 최근 $Hours 시간 요약 CSV(필요시 빠른 triage)
  $sec = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$StartTime} -ErrorAction SilentlyContinue |
         Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message
  $sys = Get-WinEvent -FilterHashtable @{LogName='System';   StartTime=$StartTime} -ErrorAction SilentlyContinue |
         Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message
  $sec | Export-Csv -NoTypeInformation -Encoding UTF8 "$base\03_events\Security_${Hours}h.csv"
  $sys | Export-Csv -NoTypeInformation -Encoding UTF8 "$base\03_events\System_${Hours}h.csv"
} catch { Write-Warning "Event collection error: $_" }
# endregion

# region 4) 서비스/드라이버
try {
  Get-Service | Sort-Object Status,DisplayName |
    Select-Object Status, Name, DisplayName, StartType |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$base\04_services.csv"

  Get-CimInstance Win32_SystemDriver |
    Select-Object State, Name, DisplayName, PathName, StartMode |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$base\04_drivers.csv"
} catch { Write-Warning "Service/Driver collection error: $_" }
# endregion

# region 5) 자동 실행 레지스트리(주요 Run/Winlogon/Policies 등)
$autorunPaths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Windows\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Winlogon',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)
# (2010 안내서에 제시된 Run/Winlogon 등 주요 지점 참조) :contentReference[oaicite:70]{index=70}
try {
  $out = foreach($p in $autorunPaths){
    if (Test-Path $p) {
      Get-ItemProperty -Path $p | Select-Object PSPath, PSParentPath, PSChildName, * -ExcludeProperty PS*, PSDrive, PSProvider
    } else {
      [PSCustomObject]@{ Path=$p; Note='Path not found' }
    }
  }
  $out | Export-Csv -NoTypeInformation -Encoding UTF8 "$base\05_autoruns.csv"
} catch { Write-Warning "Autorun registry collection error: $_" }
# endregion

# region 6) 사용자/세션/계정
try {
  query user    > "$base\06_sessions_query_user.txt" 2>&1
  qwinsta       > "$base\06_sessions_qwinsta.txt"    2>&1
  net user      > "$base\06_accounts_net_user.txt"
  net localgroup administrators > "$base\06_local_admins.txt"
  Get-LocalUser | Select-Object Name, Enabled, LastLogon | Export-Csv -NoTypeInformation -Encoding UTF8 "$base\06_local_users.csv"
} catch { Write-Warning "User/session collection error: $_" }
# endregion

# region 메타데이터/해시
try {
  Get-ChildItem -Recurse -File $base | ForEach-Object {
    $h = Get-FileHash -Algorithm SHA256 -Path $_.FullName
    [PSCustomObject]@{ File=$_.FullName; Algorithm=$h.Algorithm; Hash=$h.Hash }
  } | Export-Csv -NoTypeInformation -Encoding UTF8 "$base\zz_hashes_sha256.csv"
  "[OK] IR collection completed: $base" | Out-FileUtf8 "$base\_DONE.txt"
} catch { Write-Warning "Hashing error: $_" }
# endregion
