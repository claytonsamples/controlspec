# Starts a fresh, isolated local experiment. Existing Docker workloads are untouched.
# Requires PowerShell 7, Docker Desktop Linux containers, and outbound downloads.
[CmdletBinding()]
param([string]$Repository = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Docker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed (exit $LASTEXITCODE): $($args[0])" }
}

$Repository = (Resolve-Path -LiteralPath $Repository).Path
if (-not (Test-Path -LiteralPath (Join-Path $Repository 'backend/uv.lock'))) {
    throw 'Repository must be the ControlSpec checkout containing backend/uv.lock.'
}
$DockerOs = (Invoke-Docker info --format '{{.OSType}}').Trim()
$DockerArchitecture = (Invoke-Docker info --format '{{.Architecture}}').Trim()
if ($DockerOs -ne 'linux' -or $DockerArchitecture -notin @('amd64', 'x86_64')) {
    throw 'This pinned experiment requires Linux amd64 Docker containers.'
}
$RunName = 'csrt-' + (Get-Date -Format 'yyyyMMdd') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 4)
$Controller = "$RunName-controller"
$StateVolume = "$RunName-state"
$Network = "$RunName-net"
$WorkloadImage = "${RunName}-workload:local"
$SupervisorImage = "${RunName}-supervisor:local"
$SupervisorBase = 'ghcr.io/nvidia/openshell/supervisor@sha256:d7b5264bb6bc56f4796e6fa3617b8e4a8d785be0b7293542efd8cc250b0fb67a'
$ControllerImage = 'ghcr.io/astral-sh/uv@sha256:531f855bda2c73cd6ef67d56b733b357cea384185b3022bd09f05e002cd144ca'
$WorkDirectory = Join-Path ([IO.Path]::GetTempPath()) $RunName
New-Item -ItemType Directory -Path $WorkDirectory | Out-Null

$Manifest = [ordered]@{
    run_name = $RunName; controller = $Controller; state_volume = $StateVolume
    network = $Network; workload_image = $WorkloadImage; supervisor_image = $SupervisorImage
    work_directory = $WorkDirectory; repository = $Repository
    controller_base = $ControllerImage; supervisor_base = $SupervisorBase
    synthetic_only = $true
}
$Manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $WorkDirectory 'launch.json') -Encoding utf8
Write-Host "Experiment manifest: $WorkDirectory/launch.json"

Invoke-Docker network create $Network | Out-Null
Invoke-Docker volume create $StateVolume | Out-Null
Invoke-Docker run -d --init --name $Controller --network $Network `
    --mount 'type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock' `
    --mount "type=volume,source=$StateVolume,target=/state" `
    --mount "type=bind,source=$Repository,target=/repo,readonly" `
    -e HOME=/state -e XDG_DATA_HOME=/state/data -e XDG_STATE_HOME=/state/state `
    -e XDG_CONFIG_HOME=/state/config -e UV_PROJECT_ENVIRONMENT=/state/venv `
    -e PYTHONPATH=/repo/backend/src:/repo/backend:/repo `
    $ControllerImage sleep infinity | Out-Null

# git is needed by optional evidence generation. Packages stay inside this controller.
Invoke-Docker exec $Controller sh -c 'apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*'
Invoke-Docker exec $Controller uv sync --project /repo/backend --locked --all-extras
$Python = '/state/venv/bin/python'
$Bootstrap = '/repo/integrations/openshell/runtime/bootstrap.py'
Invoke-Docker exec $Controller $Python $Bootstrap install-binaries
$ControllerIp = (Invoke-Docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $Controller).Trim()
Invoke-Docker exec $Controller $Python $Bootstrap prepare --controller-ip $ControllerIp `
    --workload-image $WorkloadImage --supervisor-image $SupervisorImage --namespace $RunName
Invoke-Docker exec $Controller $Python $Bootstrap prepare-target-tls

# Export only PUBLIC certificates. Private keys remain exclusively in the state volume.
Invoke-Docker cp "${Controller}:/state/tls/target-ca.pem" (Join-Path $WorkDirectory 'target-ca.pem')
$Extractor = "$RunName-ca-extract"
Invoke-Docker create --name $Extractor $SupervisorBase | Out-Null
Invoke-Docker cp "${Extractor}:/etc/ssl/certs/ca-certificates.crt" (Join-Path $WorkDirectory 'system-ca.pem')
# Remove only the stopped scratch container created immediately above.
Invoke-Docker rm $Extractor | Out-Null
$SystemCa = [IO.File]::ReadAllBytes((Join-Path $WorkDirectory 'system-ca.pem'))
$TargetCa = [IO.File]::ReadAllBytes((Join-Path $WorkDirectory 'target-ca.pem'))
[IO.File]::WriteAllBytes((Join-Path $WorkDirectory 'combined-ca.pem'), [byte[]]($SystemCa + [byte[]]@(10) + $TargetCa))
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Dockerfile.supervisor') -Destination $WorkDirectory
Invoke-Docker build -t $SupervisorImage -f (Join-Path $WorkDirectory 'Dockerfile.supervisor') $WorkDirectory
Invoke-Docker build -t $WorkloadImage -f (Join-Path $PSScriptRoot 'Dockerfile.workload') $PSScriptRoot
Invoke-Docker exec $Controller $Python $Bootstrap up

$Manifest['controller_ip'] = $ControllerIp
$Manifest['workload_image_id'] = (Invoke-Docker image inspect --format '{{.Id}}' $WorkloadImage).Trim()
$Manifest['supervisor_image_id'] = (Invoke-Docker image inspect --format '{{.Id}}' $SupervisorImage).Trim()
$Manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $WorkDirectory 'launch.json') -Encoding utf8
Write-Host "Ready. Controller: $Controller"
Write-Host "Sandbox name to use: $RunName"
Write-Host "Inspect logs with: docker exec $Controller cat /state/logs/gateway.log"
Write-Host 'No host ports were published. Services remain running for the operator.'
