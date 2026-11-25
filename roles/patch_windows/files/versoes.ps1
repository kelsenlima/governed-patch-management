# =============================================================================
# Versão instalada de produtos (SOMENTE LEITURA) — W2b.
# Lê as chaves Uninstall (64 e 32 bits) e devolve, por produto do catálogo,
# se está instalado e a versão (a maior, se houver mais de uma entrada), e as
# instalações por usuário encontradas nos perfis (C:\Users\<usuario>\...).
# tipo office_c2r: Office ClickToRun — instalado = cliente ClickToRun presente;
# versão = VersionToReport; canal/origem de atualização vão em "detalhe".
# =============================================================================
[CmdletBinding()]
param(
    [object[]]$Produtos = @()
)

$Ansible.Changed = $false
$ErrorActionPreference = 'Stop'

$chaves = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = @(Get-ItemProperty -Path $chaves -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName } |
          Select-Object DisplayName, DisplayVersion)

$saida = @{}
foreach ($p in $Produtos) {
    # ---------------------------------------------------------- Office ClickToRun
    if ([string]$p.tipo -eq 'office_c2r') {
        $cli = Join-Path $env:CommonProgramFiles 'microsoft shared\ClickToRun\OfficeC2RClient.exe'
        $cfg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue
        $presente = (Test-Path -LiteralPath $cli) -and $cfg -and $cfg.VersionToReport
        $detalhe = ''
        if ($presente) {
            $origem = @($cfg.UpdateUrl, $cfg.UpdatePath, $cfg.CDNBaseUrl) | Where-Object { $_ } | Select-Object -First 1
            $detalhe = ('produtos={0}; atualizações habilitadas={1}; origem={2}' -f $cfg.ProductReleaseIds, $cfg.UpdatesEnabled, $origem)
        }
        $saida[[string]$p.nome] = @{
            instalado = [bool]$presente
            versao    = [string]($(if ($presente) { $cfg.VersionToReport } else { '' }))
            perfis    = @()
            detalhe   = $detalhe
        }
        continue
    }

    # ---------------------------------------------------------- produto comum (MSI/EXE)
    $achados = @($apps | Where-Object { $_.DisplayName -match [string]$p.regex_registro })
    $versao = ''
    if ($achados.Count -gt 0) {
        $versao = ($achados | ForEach-Object { $_.DisplayVersion } |
                   Sort-Object { try { [version]$_ } catch { [version]'0.0' } } -Descending |
                   Select-Object -First 1)
    }
    # instalações POR USUÁRIO (dentro do perfil): o Qualys detecta, mas o MSI de máquina não atualiza
    $perfis = @()
    if ($p.caminho_perfil) {
        foreach ($u in (Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
            $exe = Join-Path $u.FullName ([string]$p.caminho_perfil)
            if (Test-Path -LiteralPath $exe) {
                $v = (Get-Item -LiteralPath $exe -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
                $perfis += ('{0}={1}' -f $u.Name, $v)
            }
        }
    }
    $saida[[string]$p.nome] = @{ instalado = ($achados.Count -gt 0); versao = [string]$versao; perfis = $perfis; detalhe = '' }
}
$Ansible.Result = $saida
