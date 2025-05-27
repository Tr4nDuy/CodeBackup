# Script cài đặt Elasticsearch
Write-Host "Đang cài đặt Elasticsearch..." -ForegroundColor Green

# Tạo thư mục ELK
$elkDir = "C:\ELK"
New-Item -ItemType Directory -Force -Path $elkDir

# Download Elasticsearch
$esVersion = "8.11.0"
$esUrl = "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$esVersion-windows-x86_64.zip"
$esZip = "$elkDir\elasticsearch-$esVersion.zip"

Write-Host "Downloading Elasticsearch $esVersion..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $esUrl -OutFile $esZip

# Giải nén
Write-Host "Extracting Elasticsearch..." -ForegroundColor Yellow
Expand-Archive -Path $esZip -DestinationPath $elkDir -Force

# Đổi tên thư mục
$esDir = "$elkDir\elasticsearch-$esVersion"
if (Test-Path $esDir) {
    Rename-Item -Path $esDir -NewName "elasticsearch"
}

Write-Host "Elasticsearch đã được cài đặt tại: $elkDir\elasticsearch" -ForegroundColor Green
Write-Host "Để chạy Elasticsearch, mở PowerShell với quyền Admin và chạy:" -ForegroundColor Cyan
Write-Host "cd C:\ELK\elasticsearch\bin" -ForegroundColor White
Write-Host ".\elasticsearch.bat" -ForegroundColor White
