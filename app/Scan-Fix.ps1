<#
.SYNOPSIS
    SystemFix Security — сканер уязвимостей Windows с возможностью исправления.
.DESCRIPTION
    Проверяет типовые слабые места конфигурации Windows и предлагает исправления.
    По умолчанию выполняется ТОЛЬКО сканирование (ничего не меняется).
    Режим исправления включается ключом -Fix или через меню и требует подтверждения.
    Для исправлений нужны права администратора.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Scan-Fix.ps1              # только скан
    powershell -ExecutionPolicy Bypass -File .\Scan-Fix.ps1 -Fix         # скан + интерактивные исправления
    powershell -ExecutionPolicy Bypass -File .\Scan-Fix.ps1 -ReportPath .\report.html
#>
[CmdletBinding()]
param(
    [switch]$Fix,
    [string]$ReportPath = ''
)

$ErrorActionPreference = 'SilentlyContinue'
$script:Findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [string]$Id,
        [string]$Title,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,
        [string]$Details,
        [string]$Recommendation,
        [scriptblock]$Repair
    )
    $script:Findings.Add([pscustomobject]@{
        Id             = $Id
        Title          = $Title
        Severity       = $Severity
        Status         = 'Open'
        Details        = $Details
        Recommendation = $Recommendation
        Repair         = $Repair
    })
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegistryValueSafe {
    param([string]$Path, [string]$Name)
    $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $value) { return $null }
    $value.$Name
}

# ---------------- Проверки ----------------

function Invoke-Checks {
    Write-Host ''
    Write-Host '=== СКАНИРОВАНИЕ КОНФИГУРАЦИИ БЕЗОПАСНОСТИ ===' -ForegroundColor Cyan

    # 1. Защитник Windows: режим реального времени
    $rtp = Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring -ErrorAction SilentlyContinue
    if ($rtp -eq $true) {
        Add-Finding -Id 'DEF-RTP' -Title 'Защитник Windows: отключена защита в реальном времени' -Severity 'Critical' `
            -Details 'DisableRealtimeMonitoring = 1. Система не блокирует вредоносные файлы на лету.' `
            -Recommendation 'Включить защиту в реальном времени.' `
            -Repair { Set-MpPreference -DisableRealtimeMonitoring $false }
    } else {
        Write-Host '  [OK] Защитник Windows: защита в реальном времени включена' -ForegroundColor Green
    }

    # 2. Свежесть сигнатур Defender
    $sig = Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated, AntispywareSignatureLastUpdated -ErrorAction SilentlyContinue
    if ($sig -and $sig.AntivirusSignatureLastUpdated) {
        $age = (New-TimeSpan -Start $sig.AntivirusSignatureLastUpdated -End (Get-Date)).Days
        if ($age -ge 7) {
            Add-Finding -Id 'DEF-SIG' -Title "Сигнатуры Защитника устарели ($age дн.)" -Severity 'High' `
                -Details "Последнее обновление баз: $($sig.AntivirusSignatureLastUpdated)." `
                -Recommendation 'Обновить сигнатуры (Update-MpSignature).' `
                -Repair { Update-MpSignature }
        } else {
            Write-Host "  [OK] Сигнатуры Защитника обновлены ($age дн. назад)" -ForegroundColor Green
        }
    }

    # 3. Брандмауэр: все профили
    foreach ($profile in Get-NetFirewallProfile) {
        if ($profile.Enabled -eq $false) {
            Add-Finding -Id "FW-$($profile.Name)" -Title "Брандмауэр: профиль '$($profile.Name)' отключён" -Severity 'Critical' `
                -Details 'Без брандмауэра входящие подключения не фильтруются.' `
                -Recommendation "Включить профиль $($profile.Name)." `
                -Repair { Set-NetFirewallProfile -Name $profile.Name -Enabled True }.GetNewClosure()
        } else {
            Write-Host "  [OK] Брандмауэр: профиль '$($profile.Name)' включён" -ForegroundColor Green
        }
    }

    # 4. SMBv1 (EternalBlue и др.)
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smb1 -and $smb1.State -eq 'Enabled') {
        Add-Finding -Id 'SMB-V1' -Title 'Включён протокол SMBv1' -Severity 'Critical' `
            -Details 'SMBv1 уязвим к EternalBlue (MS17-010) и не нужен современным системам.' `
            -Recommendation 'Отключить компонент SMB1Protocol (потребуется перезагрузка).' `
            -Repair { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart }
    } else {
        Write-Host '  [OK] SMBv1 отключён' -ForegroundColor Green
    }

    # 5. UAC
    $uac = Get-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
    if ($uac -eq 0) {
        Add-Finding -Id 'UAC-OFF' -Title 'Контроль учётных записей (UAC) отключён' -Severity 'Critical' `
            -Details 'Программы могут повышать привилегии без ведома пользователя.' `
            -Recommendation 'Включить UAC (EnableLUA = 1, требуется перезагрузка).' `
            -Repair { Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 }
    } else {
        Write-Host '  [OK] UAC включён' -ForegroundColor Green
    }

    # 6. RDP без NLA
    $rdp = Get-RegistryValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    $nla = Get-RegistryValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    if ($rdp -eq 1) {
        Write-Host '  [OK] RDP отключён' -ForegroundColor Green
    } elseif ($nla -eq 0) {
        Add-Finding -Id 'RDP-NLA' -Title 'RDP включён без сетевой аутентификации (NLA)' -Severity 'High' `
            -Details 'RDP доступен без предварительной аутентификации — цель для брутфорса.' `
            -Recommendation 'Включить NLA для RDP.' `
            -Repair { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 }
    } else {
        Write-Host '  [OK] RDP включён с NLA' -ForegroundColor Green
    }

    # 7. Уровень совместимости LAN Manager (NTLMv1)
    $lm = Get-RegistryValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    if ($null -eq $lm -or $lm -lt 3) {
        Add-Finding -Id 'NTLM-V1' -Title 'Разрешены слабые NTLMv1/LM-аутентификация' -Severity 'High' `
            -Details "LmCompatibilityLevel = $lm (по умолчанию). LM/NTLMv1 поддаются перехвату и подбору." `
            -Recommendation 'Установить LmCompatibilityLevel = 5 (только NTLMv2).' `
            -Repair { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 }
    } else {
        Write-Host '  [OK] Аутентификация ограничена NTLMv2' -ForegroundColor Green
    }

    # 8. TLS 1.0/1.1 включены
    foreach ($tls in '1.0', '1.1') {
        $enabled = Get-RegistryValueSafe "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS $tls\Server" 'Enabled'
        if ($enabled -eq 1) {
            Add-Finding -Id "TLS-$tls" -Title "Устаревший TLS $tls включён на уровне сервера" -Severity 'Medium' `
                -Details 'TLS 1.0/1.1 считаются небезопасными; современные системы используют TLS 1.2+.' `
                -Recommendation "Отключить TLS $tls (SCHANNEL, требуется перезагрузка)." `
                -Repair { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS $tls\Server" -Name Enabled -Value 0 }.GetNewClosure()
        }
    }

    # 9. Парольная политика
    $netAccounts = net accounts 2>$null | Out-String
    $minLen = [regex]::Match($netAccounts, 'минимальная длина пароля[^\d]*(\d+)', 'IgnoreCase').Groups[1].Value
    if (-not $minLen) { $minLen = [regex]::Match($netAccounts, 'Minimum password length\s*(\d+)', 'IgnoreCase').Groups[1].Value }
    if ($minLen -and [int]$minLen -lt 8) {
        Add-Finding -Id 'PWD-LEN' -Title "Минимальная длина пароля: $minLen символов" -Severity 'Medium' `
            -Details 'Короткие пароли подбираются перебором.' `
            -Recommendation 'Установить минимум 12 символов (net accounts /minpwlen:12).' `
            -Repair { net accounts /minpwlen:12 | Out-Null }
    } else {
        Write-Host "  [OK] Минимальная длина пароля: $minLen символов" -ForegroundColor Green
    }

    # 10. Гостевая учётная запись
    $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
    if ($guest -and -not $guest.Enabled) {
        Write-Host '  [OK] Гостевая учётная запись отключена' -ForegroundColor Green
    } elseif ($guest) {
        Add-Finding -Id 'USR-GUEST' -Title 'Гостевая учётная запись включена' -Severity 'High' `
            -Details 'Вход без пароля под Guest — типовой путь входа злоумышленника.' `
            -Recommendation 'Отключить учётную запись Guest.' `
            -Repair { Disable-LocalUser -Name 'Guest' }
    }

    # 11. Автозапуск со сменных носителей
    $autorun = Get-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
    if ($autorun -ne 255) {
        Add-Finding -Id 'AUTO-RUN' -Title 'Автозапуск со сменных носителей не запрещён полностью' -Severity 'Medium' `
            -Details "NoDriveTypeAutoRun = $autorun (255 = автозапуск полностью запрещён)." `
            -Recommendation 'Запретить автозапуск (NoDriveTypeAutoRun = 255).' `
            -Repair { Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255 }
    } else {
        Write-Host '  [OK] Автозапуск со сменных носителей запрещён' -ForegroundColor Green
    }

    # 12. Безопасная загрузка (info)
    $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($sb -eq $false) {
        Add-Finding -Id 'UEFI-SB' -Title 'Безопасная загрузка (Secure Boot) выключена' -Severity 'Low' `
            -Details 'Secure Boot блокирует загрузку неподписанных руткитов на уровне UEFI.' `
            -Recommendation 'Включить Secure Boot в UEFI/BIOS (внутри Windows недоступно).'
    } elseif ($sb -eq $true) {
        Write-Host '  [OK] Secure Boot включён' -ForegroundColor Green
    } else {
        Write-Host '  [--] Secure Boot: статус определить не удалось (Legacy BIOS?)' -ForegroundColor DarkGray
    }

    # 13. Отчёт Windows Update: давно ли устанавливались обновления
    $wu = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID, InstalledOn
    if ($wu -and $wu.InstalledOn) {
        $days = (New-TimeSpan -Start $wu.InstalledOn -End (Get-Date)).Days
        if ($days -gt 60) {
            Add-Finding -Id 'WU-OLD' -Title "Последнее обновление Windows установлено $days дн. назад" -Severity 'High' `
                -Details "Обновление $($wu.HotFixID) от $($wu.InstalledOn)." `
                -Recommendation 'Установить обновления (параметры → Центр обновления Windows).'
        } else {
            Write-Host "  [OK] Обновления Windows: последнее $days дн. назад ($($wu.HotFixID))" -ForegroundColor Green
        }
    }

    # 14. Открытые общие папки с доступом Everyone
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin 'IPC$', 'ADMIN$', 'NETLOGON', 'SYSVOL' }
    foreach ($share in $shares) {
        $everyone = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue | Where-Object { $_.AccountName -match 'Everyone|Все' -and $_.AccessRight -eq 'Full' }
        if ($everyone) {
            Add-Finding -Id "SHR-$($share.Name)" -Title "Общая папка '$($share.Name)' открыта для Everyone (Full)" -Severity 'High' `
                -Details 'Полный сетевой доступ для всех пользователей сети.' `
                -Recommendation "Ограничить права доступа к папке $($share.Name)." `
                -Repair { Revoke-SmbShareAccess -Name $share.Name -AccountName 'Everyone' -Force }.GetNewClosure()
        }
    }
}

# ---------------- Отчёт ----------------

function Show-Report {
    param([string]$Path)
    $rows = $script:Findings | ForEach-Object {
        $color = @{ Critical = '#ff5c5c'; High = '#ffab5c'; Medium = '#ffd85c'; Low = '#9ad1ff'; Info = '#bdbdbd' }[$_.Severity]
        "<tr><td><b>$($_.Id)</b></td><td style='color:$color'><b>$($_.Severity)</b></td><td>$($_.Title)</td><td>$([System.Net.WebUtility]::HtmlEncode($_.Details))</td><td>$([System.Net.WebUtility]::HtmlEncode($_.Recommendation))</td><td>$($_.Status)</td></tr>"
    }
    $html = @"
<!doctype html><html lang="ru"><meta charset="utf-8"><title>SystemFix Security — отчёт $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
<style>body{background:#101208;color:#f8f6ed;font:14px/1.6 'Segoe UI',Arial,sans-serif;padding:32px}h1{color:#f1d990}table{border-collapse:collapse;width:100%}td,th{border:1px solid #3a3d24;padding:9px 12px;text-align:left;vertical-align:top}th{background:#1d2010;color:#f1d990}tr:nth-child(even){background:#161908}</style>
<h1>SystemFix Security — отчёт о сканировании</h1>
<p>Узел: $env:COMPUTERNAME · Дата: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') · Найдено проблем: $($script:Findings.Count)</p>
<table><tr><th>ID</th><th>Критичность</th><th>Проблема</th><th>Детали</th><th>Рекомендация</th><th>Статус</th></tr>$($rows -join "`n")</table>
"@
    if ($Path) {
        $html | Out-File -FilePath $Path -Encoding UTF8
        Write-Host "Отчёт сохранён: $Path" -ForegroundColor Green
    } else {
        $html
    }
}

# ---------------- Исправления ----------------

function Invoke-Repairs {
    $open = @($script:Findings | Where-Object { $_.Status -eq 'Open' -and $_.Repair })
    if (-not $open.Count) {
        Write-Host 'Нет исправлений, требуемых действий: всё чисто или исправления недоступны.' -ForegroundColor Green
        return
    }
    if (-not (Test-Admin)) {
        Write-Host 'Для исправлений нужны права администратора. Перезапусти приложение через Launch-Fix.cmd.' -ForegroundColor Red
        return
    }
    Write-Host ''
    Write-Host '=== ИСПРАВЛЕНИЕ ===' -ForegroundColor Cyan
    Write-Host 'Точка восстановления перед изменениями не создаётся автоматически.' -ForegroundColor Yellow
    foreach ($finding in $open) {
        $answer = Read-Host "Исправить [$($finding.Id)] $($finding.Title)? (y/N)"
        if ($answer -match '^[YyДд]') {
            try {
                & $finding.Repair
                $finding.Status = 'Fixed'
                Write-Host "  Исправлено: $($finding.Id)" -ForegroundColor Green
            } catch {
                $finding.Status = "Ошибка: $($_.Exception.Message)"
                Write-Host "  Не удалось: $($finding.Id) — $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            $finding.Status = 'Пропущено'
        }
    }
    Write-Host ''
    Write-Host 'Некоторые исправления (SMBv1, UAC, TLS) вступают в силу после перезагрузки.' -ForegroundColor Yellow
}

# ---------------- Запуск ----------------

Write-Host '==============================' -ForegroundColor Yellow
Write-Host '  SystemFix Security  v1.0' -ForegroundColor Yellow
Write-Host '  сканер уязвимостей Windows' -ForegroundColor Yellow
Write-Host '==============================' -ForegroundColor Yellow

if (-not (Test-Admin)) {
    Write-Host 'Запущено без прав администратора: часть проверок может быть недоступна.' -ForegroundColor DarkYellow
}

Invoke-Checks

Write-Host ''
if ($script:Findings.Count -eq 0) {
    Write-Host 'РЕЗУЛЬТАТ: критичных проблем конфигурации не найдено.' -ForegroundColor Green
} else {
    Write-Host "РЕЗУЛЬТАТ: найдено проблем — $($script:Findings.Count)" -ForegroundColor Yellow
    foreach ($f in $script:Findings) {
        $color = @{ Critical = 'Red'; High = 'DarkRed'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }[$f.Severity]
        Write-Host "  [$($f.Severity)] $($f.Id): $($f.Title)" -ForegroundColor $color
        Write-Host "      $($f.Details)"
        Write-Host "      → $($f.Recommendation)"
    }
}

if ($Fix) { Invoke-Repairs }

Show-Report -Path $ReportPath

if (-not $Fix -and $script:Findings.Count -gt 0) {
    Write-Host ''
    Write-Host 'Подсказка: запусти с ключом -Fix (или через Launch-Fix.cmd), чтобы исправить найденное по одному с подтверждением.' -ForegroundColor Cyan
}
