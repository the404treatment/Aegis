# Screenshot capture helper. Not part of the app — used to regenerate the
# images in assets/ for the README. Requires the server running locally.
param([string]$Chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe")

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $root 'assets'
New-Item -ItemType Directory -Path $out -Force | Out-Null

# view key -> output file. Each is captured from a fresh profile so the
# seeded localStorage is deterministic.
$shots = @(
  @{ v = 'matrix';  f = 'matrix.png' },
  @{ v = 'logsrc';  f = 'huntmap.png' },
  @{ v = 'studio';  f = 'studio.png' }
)

foreach ($s in $shots) {
  $prof = Join-Path $env:TEMP ("aegis-shot-" + $s.v)
  Remove-Item -Recurse -Force $prof -ErrorAction SilentlyContinue
  $target = Join-Path $out $s.f
  Remove-Item -Force $target -ErrorAction SilentlyContinue

  # Invoke directly rather than via Start-Process: Start-Process -PassThru
  # plus WaitForExit does not reliably wait for headless Chrome here, and the
  # capture gets killed before it writes.
  & $Chrome --headless=new --disable-gpu --hide-scrollbars `
    --window-size=1600,1000 "--user-data-dir=$prof" `
    "--screenshot=$target" --virtual-time-budget=6000 `
    "http://127.0.0.1:8787/_shot.html?v=$($s.v)" 2>&1 | Out-Null
  Start-Sleep -Milliseconds 300

  if (Test-Path $target) {
    "{0,-14} {1,8:N0} bytes" -f $s.f, (Get-Item $target).Length
  } else {
    "{0,-14} FAILED" -f $s.f
  }
}
