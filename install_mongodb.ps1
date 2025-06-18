# Create MongoDB data directory
$dataDir = "C:\data\db"
if (-not (Test-Path $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir -Force
    Write-Host "Created MongoDB data directory at $dataDir"
}

# Download MongoDB Community Server
$downloadUrl = "https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-6.0.13-signed.msi"
$installerPath = "$env:TEMP\mongodb-installer.msi"

Write-Host "Downloading MongoDB installer..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath

# Install MongoDB
Write-Host "Installing MongoDB..."
Start-Process msiexec.exe -ArgumentList "/i $installerPath /quiet /norestart" -Wait

# Add MongoDB to PATH
$mongodbPath = "C:\Program Files\MongoDB\Server\6.0\bin"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if (-not $currentPath.Contains($mongodbPath)) {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$mongodbPath", "Machine")
    Write-Host "Added MongoDB to system PATH"
}

# Clean up installer
Remove-Item $installerPath

Write-Host "MongoDB installation completed!"
Write-Host "Please restart your PowerShell window and run: mongod --dbpath 'C:\data\db'" 