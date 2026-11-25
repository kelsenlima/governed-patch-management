# =============================================================================
# Estado do servidor Windows (SOMENTE LEITURA) — usado antes e depois do patch.
# Parâmetros vêm do Ansible (win_powershell "parameters").
# Devolve em $Ansible.Result: SO, build, disco, reboot pendente, serviços críticos,
# serviços automáticos rodando, URLs/sites IIS que falharam e KBs instaladas.
# =============================================================================
[CmdletBinding()]
param(
    [string[]]$Servicos = @(),
    [string[]]$Urls = @(),
    [object[]]$Iis = @(),
    [int[]]$CodigosOk = @(200, 204, 301, 302, 401, 403)
)

$Ansible.Changed = $false
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls

# Requisição HTTP com cabeçalho Host opcional (IIS exige o nome do binding); devolve o código ou 0
function Testar-Url([string]$url, [string]$hostHeader, [int]$ms = 15000) {
    try {
        $req = [Net.HttpWebRequest]::Create($url)
        $req.Method = 'GET'; $req.Timeout = $ms; $req.ReadWriteTimeout = $ms; $req.AllowAutoRedirect = $false
        if ($hostHeader) { $req.Host = $hostHeader }
        $resp = $req.GetResponse(); $cod = [int]$resp.StatusCode; $resp.Close(); return $cod
    } catch [Net.WebException] {
        if ($_.Exception.Response) { $cod = [int]$_.Exception.Response.StatusCode; $_.Exception.Response.Close(); return $cod }
        return 0
    } catch { return 0 }
}

# --- sistema operacional e build (ex.: 20348.2849)
$os = Get-CimInstance Win32_OperatingSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$build = '{0}.{1}' -f $os.BuildNumber, $cv.UBR
$disco = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive)

# --- reboot pendente (só sinais confiáveis; PendingFileRenameOperations gera falso positivo)
$pend = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pend += 'CBS' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pend += 'WindowsUpdate' }

# --- serviços críticos (host_vars)
$parados = @(); $inexistentes = @()
foreach ($n in $Servicos) {
    $s = Get-Service -Name $n -ErrorAction SilentlyContinue
    if (-not $s) { $inexistentes += $n }
    elseif ($s.Status -ne 'Running') { $parados += ('{0} ({1})' -f $n, $s.Status) }
}

# --- foto dos serviços automáticos rodando (comparação antes × depois)
$auto = @(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State='Running'" | ForEach-Object { $_.Name } | Sort-Object)

# --- URLs de saúde e sites do IIS (host_vars)
$falhas = @()
foreach ($u in $Urls) {
    $c = Testar-Url $u ''
    if ($CodigosOk -notcontains $c) { $falhas += ('{0} -> HTTP {1}' -f $u, $c) }
}
foreach ($s in $Iis) {
    $c = Testar-Url ([string]$s.url) ([string]$s.host)
    if ($CodigosOk -notcontains $c) { $falhas += ('IIS {0} {1} host={2} -> HTTP {3}' -f $s.site, $s.url, $s.host, $c) }
}

# --- política do Windows Update (GPO/registro): de onde o servidor pode baixar atualizações
$wuPol = @{}
$polBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
foreach ($par in @(@($polBase, 'WUServer'), @($polBase, 'DoNotConnectToWindowsUpdateInternetLocations'),
                   @($polBase, 'DisableWindowsUpdateAccess'), @("$polBase\AU", 'UseWUServer'), @("$polBase\AU", 'NoAutoUpdate'))) {
    $v = (Get-ItemProperty -Path $par[0] -Name $par[1] -ErrorAction SilentlyContinue).($par[1])
    if ($null -ne $v) { $wuPol[$par[1]] = [string]$v }
}

# --- KBs instaladas (para conferir as KBs do plano)
$kbs = @()
try { $kbs = @(Get-HotFix | ForEach-Object { $_.HotFixID } | Sort-Object -Unique) } catch { $kbs = @() }

$Ansible.Result = @{
    so                    = $os.Caption
    build                 = $build
    disco_livre_gb        = [math]::Round($disco.FreeSpace / 1GB, 1)
    reboot_pendente       = $pend
    ultimo_boot           = $os.LastBootUpTime.ToUniversalTime().ToString('o')
    servicos_parados      = $parados
    servicos_inexistentes = $inexistentes
    auto_rodando          = $auto
    urls_falha            = $falhas
    kbs_instaladas        = $kbs
    politica_wu           = $wuPol
}
