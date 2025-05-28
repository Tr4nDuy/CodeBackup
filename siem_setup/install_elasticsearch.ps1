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
Expand-Archive -Path $esZip -DestinationPath "$elkDir\elasticsearch" -Force

# Cấu hình Elasticsearch
$esConfigFile = "$elkDir\elasticsearch\elasticsearch-$esVersion\config\elasticsearch.yml"
if (Test-Path $esConfigFile) {
    # Sao lưu file cấu hình
    Copy-Item -Path $esConfigFile -Destination "$esConfigFile.bak"
    
    # Thêm cấu hình cho bộ nhớ thấp (4GB)
    Add-Content -Path $esConfigFile -Value "`n# Memory settings for small VM"
    Add-Content -Path $esConfigFile -Value "cluster.name: nids-siem"
    Add-Content -Path $esConfigFile -Value "node.name: nids-node-1"
    Add-Content -Path $esConfigFile -Value "http.port: 9200"
    Add-Content -Path $esConfigFile -Value "transport.port: 9300"
    Add-Content -Path $esConfigFile -Value "network.host: localhost"
    Add-Content -Path $esConfigFile -Value "discovery.type: single-node"
    Add-Content -Path $esConfigFile -Value "xpack.security.enabled: false"
    Add-Content -Path $esConfigFile -Value "xpack.security.enrollment.enabled: false"
}

# Cấu hình JVM cho bộ nhớ thấp
$jvmOptionsFile = "$elkDir\elasticsearch\elasticsearch-$esVersion\config\jvm.options.d\memory.options"
New-Item -ItemType Directory -Force -Path (Split-Path -Path $jvmOptionsFile -Parent)
Set-Content -Path $jvmOptionsFile -Value "-Xms512m`n-Xmx512m"

Write-Host "Elasticsearch đã được cài đặt tại: $elkDir\elasticsearch" -ForegroundColor Green
Write-Host "Để chạy Elasticsearch, mở PowerShell với quyền Admin và chạy:" -ForegroundColor Cyan
Write-Host "cd C:\ELK\elasticsearch\elasticsearch-$esVersion\bin" -ForegroundColor White
Write-Host ".\elasticsearch.bat" -ForegroundColor White
