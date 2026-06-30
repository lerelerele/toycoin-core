$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
New-Item -ItemType Directory -Force -Path dist\windows-amd64 | Out-Null
$env:GOOS="windows"
$env:GOARCH="amd64"
go build -o dist\windows-amd64\toycoind.exe .\cmd\toycoind
go build -o dist\windows-amd64\toycoin-cli.exe .\cmd\toycoin-cli
Write-Host "Built dist\windows-amd64\"
