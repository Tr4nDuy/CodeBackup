# Script cài đặt Kibana
Write-Host "Đang cài đặt Kibana..." -ForegroundColor Green

# Tạo thư mục ELK
$elkDir = "C:\ELK"
New-Item -ItemType Directory -Force -Path "$elkDir\kibana"

# Download Kibana
$kbVersion = "8.11.0"
$kbUrl = "https://artifacts.elastic.co/downloads/kibana/kibana-$kbVersion-windows-x86_64.zip"
$kbZip = "$elkDir\kibana-$kbVersion.zip"

Write-Host "Downloading Kibana $kbVersion..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $kbUrl -OutFile $kbZip

# Giải nén
Write-Host "Extracting Kibana..." -ForegroundColor Yellow
Expand-Archive -Path $kbZip -DestinationPath "$elkDir\kibana" -Force

# Cấu hình Kibana
$kbConfigFile = "$elkDir\kibana\kibana-$kbVersion\config\kibana.yml"
if (Test-Path $kbConfigFile) {
    # Sao lưu file cấu hình
    Copy-Item -Path $kbConfigFile -Destination "$kbConfigFile.bak"
    
    # Thêm cấu hình cho hệ thống NIDS
    Add-Content -Path $kbConfigFile -Value "`n# NIDS Configuration"
    Add-Content -Path $kbConfigFile -Value "server.host: localhost"
    Add-Content -Path $kbConfigFile -Value "server.port: 5601"
    Add-Content -Path $kbConfigFile -Value "elasticsearch.hosts: [""http://localhost:9200""]"
    Add-Content -Path $kbConfigFile -Value "elasticsearch.serviceAccountToken: """
    Add-Content -Path $kbConfigFile -Value "elasticsearch.ssl.verificationMode: none"
    Add-Content -Path $kbConfigFile -Value "telemetry.enabled: false"
    Add-Content -Path $kbConfigFile -Value "telemetry.allowChangingOptInStatus: false"
}

Write-Host "Kibana đã được cài đặt tại: $elkDir\kibana\kibana-$kbVersion" -ForegroundColor Green
Write-Host "Để chạy Kibana, mở PowerShell với quyền Admin và chạy:" -ForegroundColor Cyan
Write-Host "cd $elkDir\kibana\kibana-$kbVersion\bin" -ForegroundColor White
Write-Host ".\kibana.bat" -ForegroundColor White
