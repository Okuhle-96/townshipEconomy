$ErrorActionPreference = "Stop"

$projectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$envPath = Join-Path $projectDirectory ".env"
if (Test-Path $envPath) {
    throw ".env already exists. Keep it private; rename it only if you intend to replace its settings."
}

$psqlPath = "C:\Program Files\PostgreSQL\18\bin\psql.exe"
if (-not (Test-Path $psqlPath)) {
    $psqlCommand = Get-Command psql -ErrorAction SilentlyContinue
    if ($psqlCommand) {
        $psqlPath = $psqlCommand.Source
    } else {
        throw "PostgreSQL command-line tools were not found. Install PostgreSQL or add psql.exe to PATH."
    }
}

try {
    $secureAdminPassword = Read-Host "Enter the local PostgreSQL postgres password (input is hidden)" -AsSecureString
} catch {
    throw "Run this helper from an interactive PowerShell terminal so you can enter the local PostgreSQL password securely. The password is not needed in chat."
}
$adminPasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAdminPassword)
$setupSqlPath = Join-Path ([System.IO.Path]::GetTempPath()) ("township-economy-setup-" + [guid]::NewGuid().ToString("N") + ".sql")

try {
    $adminPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($adminPasswordPointer)
    $env:PGPASSWORD = $adminPassword

    & $psqlPath -w -h localhost -p 5432 -U postgres -d postgres -v ON_ERROR_STOP=1 -c "SELECT 1" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not connect to local PostgreSQL as postgres. Check that the service is running and the password is correct."
    }

    $appPasswordBytes = New-Object byte[] 32
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($appPasswordBytes)
    } finally {
        $random.Dispose()
    }
    $appPassword = ([BitConverter]::ToString($appPasswordBytes)).Replace("-", "").ToLowerInvariant()
    $sessionSecretBytes = New-Object byte[] 48
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($sessionSecretBytes)
    } finally {
        $random.Dispose()
    }
    $sessionSecret = ([BitConverter]::ToString($sessionSecretBytes)).Replace("-", "").ToLowerInvariant()

    $setupSql = @"
DO `$setup`$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'township_economy_app') THEN
        CREATE ROLE township_economy_app LOGIN PASSWORD '$appPassword';
    ELSE
        ALTER ROLE township_economy_app WITH LOGIN PASSWORD '$appPassword';
    END IF;
END
`$setup`$;
SELECT format('CREATE DATABASE township_economy OWNER township_economy_app')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'township_economy')
\gexec
ALTER DATABASE township_economy OWNER TO township_economy_app;
"@
    Set-Content -Path $setupSqlPath -Value $setupSql -Encoding ASCII
    & $psqlPath -w -h localhost -p 5432 -U postgres -d postgres -v ON_ERROR_STOP=1 -f $setupSqlPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not prepare the Township Economy database. Check the PostgreSQL logs and try again."
    }

    $envContent = @"
NODE_ENV=development
PORT=3000
DATABASE_URL=postgresql://township_economy_app:$appPassword@localhost:5432/township_economy
APP_ORIGIN=http://localhost:3000
PGSSL=false
COOKIE_SECURE=false
SESSION_SECRET=$sessionSecret
RESEND_API_KEY=
RESEND_FROM_EMAIL=
"@
    Set-Content -Path $envPath -Value $envContent -Encoding ASCII
    Write-Output "Local database and private .env configuration are ready."
    Write-Output "Next, run: npm start"
    Write-Output "Then open: http://localhost:3000"
} finally {
    Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
    if (Test-Path $setupSqlPath) {
        Remove-Item -LiteralPath $setupSqlPath -Force
    }
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($adminPasswordPointer)
}
