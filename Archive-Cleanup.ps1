# Safe housekeeping. Preview by default. Use -Execute to MOVE, never delete.
param([switch]$Execute)
$root = (Get-Location).Path
$archive = Join-Path $root '_submission_archive'
$names = @('audit_after_intent','audit_baseline','audit_snapshots','inspection_report.json','evidence_coverage_report.json','ghosttrace_review.json','ghosttrace_predictions.json','ghosttrace_sample_evaluation.json','ghosttrace_full_report.json','ghosttrace_full_predictions.json','ghosttrace_coverage_report.json','GhostTrace_Current_Source.zip','GhostTrace_Source_And_Dataset.zip','GhostTrace_Submission_Rescue.zip','code/engine.backup.py')
foreach($name in $names) {
  $p = Join-Path $root $name
  if(!(Test-Path -LiteralPath $p)) { continue }
  if(!$Execute) { Write-Host "PREVIEW move: $name"; continue }
  New-Item -ItemType Directory -Force -Path $archive | Out-Null
  $safeName = $name.Replace('/','__').Replace('\\','__')
  $target = Join-Path $archive $safeName
  if(Test-Path $target) { Write-Warning "SKIP existing target: $target"; continue }
  Move-Item -LiteralPath $p -Destination $target
  Write-Host "Archived $name"
}
Write-Host 'Preserved: code/, dataset/, evaluation/, output.csv, README.md, AGENTS.md, problem_statement.md, .git, any real log.txt, unlisted user files.'
