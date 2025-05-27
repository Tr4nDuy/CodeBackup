# Script cài đặt Logstash cho SIEM
# Chạy với quyền Administrator

Write-Host "=== Cài đặt Logstash ===" -ForegroundColor Green

# Tạo thư mục làm việc
$workDir = "C:\ELK\logstash"
if (!(Test-Path $workDir)) {
    New-Item -ItemType Directory -Path $workDir -Force
}
Set-Location $workDir

# Download Logstash
$logstashVersion = "8.12.0"
$logstashUrl = "https://artifacts.elastic.co/downloads/logstash/logstash-$logstashVersion-windows-x86_64.zip"
$logstashZip = "logstash-$logstashVersion-windows-x86_64.zip"

Write-Host "Downloading Logstash..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $logstashUrl -OutFile $logstashZip -UseBasicParsing
    Write-Host "Download completed!" -ForegroundColor Green
} catch {
    Write-Host "Download failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Giải nén
Write-Host "Extracting Logstash..." -ForegroundColor Yellow
try {
    Expand-Archive -Path $logstashZip -DestinationPath . -Force
    $extractedDir = "logstash-$logstashVersion"
    if (Test-Path $extractedDir) {
        Rename-Item $extractedDir "logstash"
    }
    Remove-Item $logstashZip
    Write-Host "Extraction completed!" -ForegroundColor Green
} catch {
    Write-Host "Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Cấu hình Logstash
$configDir = "$workDir\logstash\config"
$pipelineDir = "$workDir\logstash\pipeline"

# Tạo thư mục pipeline
if (!(Test-Path $pipelineDir)) {
    New-Item -ItemType Directory -Path $pipelineDir -Force
}

# Cấu hình JVM (giảm RAM usage)
$jvmOptions = @"
-Xms512m
-Xmx1g
-XX:+UseG1GC
-XX:MaxGCPauseMillis=250
-XX:G1HeapRegionSize=16m
-XX:+ExplicitGCInvokesConcurrent
-XX:+UseLargePages
-XX:+UseTLAB
-XX:+ResizeTLAB
-XX:+UseCompressedOops
-XX:+UseCompressedClassPointers
"@

$jvmOptions | Out-File -FilePath "$configDir\jvm.options" -Encoding UTF8

Write-Host "Logstash installation completed!" -ForegroundColor Green
Write-Host "Location: $workDir\logstash" -ForegroundColor Cyan
Write-Host "Next: Configure pipeline for NIDS integration" -ForegroundColor Yellow
