# Installs lazyios with uv. No admin rights needed.
# Wrapped in a script block so `irm | iex` doesn't leave settings in the caller's session.
& {
    $ErrorActionPreference = "Stop"

    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
        Write-Host "installing uv..."
        irm https://astral.sh/uv/install.ps1 | iex
        $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
    }

    # 3.12: some pymobiledevice3 deps have no wheels for newer Pythons and would need a C compiler
    uv tool install --upgrade --python 3.12 https://github.com/Manuel-1312/lazyios/archive/refs/heads/main.zip
    if ($LASTEXITCODE -ne 0) { throw "uv tool install failed" }

    $apple = (Get-AppxPackage AppleInc.AppleDevices -ErrorAction SilentlyContinue) -or
             (Get-Service "Apple Mobile Device Service" -ErrorAction SilentlyContinue)
    if (-not $apple) {
        Write-Host ""
        Write-Host "lazyios needs usbmuxd, which comes with Apple Devices or iTunes. Install it with:"
        Write-Host "  winget install 9NP83LWLPZ9K -s msstore"
    }

    Write-Host ""
    Write-Host "done. open a new terminal and run: lazyios"
}
