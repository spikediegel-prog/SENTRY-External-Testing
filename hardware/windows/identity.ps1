<# Optional explicit TPM key enrollment/signing helper. No execution by CI or Rust default startup.
   Signatures prove possession only; they do not prove hardware provenance or current platform integrity. #>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('Probe','Provision','Sign')][string]$Operation,
  [ValidatePattern('^[A-Za-z0-9._-]{1,128}$')][string]$KeyName='SENTRY-External-Testing-Identity',
  [string]$ChallengePath
)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows provider required; no software fallback' }
$provider=[Security.Cryptography.CngProvider]::new('Microsoft Platform Crypto Provider')
if ($Operation -eq 'Probe') {
  $tpm=Get-Tpm -ErrorAction Stop
  [pscustomobject]@{ classification='Recorded'; present=$tpm.TpmPresent; ready=$tpm.TpmReady; provider=$provider.Provider; attestationVerified=$false } | ConvertTo-Json
  return
}
if ($Operation -eq 'Provision') {
  if ([Security.Cryptography.CngKey]::Exists($KeyName,$provider)) { throw 'Key already exists; overwrite/rotation is not automatic' }
  $parameters=[Security.Cryptography.CngKeyCreationParameters]::new()
  $parameters.Provider=$provider
  $parameters.ExportPolicy=[Security.Cryptography.CngExportPolicies]::None
  $parameters.KeyUsage=[Security.Cryptography.CngKeyUsages]::Signing
  $parameters.Parameters.Add([Security.Cryptography.CngProperty]::new('Length',[BitConverter]::GetBytes(2048),[Security.Cryptography.CngPropertyOptions]::None))
  $key=[Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa,$KeyName,$parameters)
} else {
  if (-not $ChallengePath) { throw 'ChallengePath required' }
  $challengeFile=Get-Item -LiteralPath $ChallengePath
  if ($challengeFile.Length -gt 4096) { throw 'Challenge size exceeded' }
  $stream=[IO.File]::OpenRead($challengeFile.FullName)
  try {
    $buffer=New-Object byte[] 4097
    $total=0
    while ($total -lt $buffer.Length) { $read=$stream.Read($buffer,$total,$buffer.Length-$total); if ($read -eq 0) { break }; $total+=$read }
    if ($total -gt 4096) { throw 'Challenge size exceeded' }
    $message=New-Object byte[] $total
    [Array]::Copy($buffer,$message,$total)
  } finally { $stream.Dispose() }
  $text=[Text.Encoding]::UTF8.GetString($message)
  if ($text -notmatch '\ASENTRY-HARDWARE-IDENTITY-V2\nsession=[0-9a-f]{64}\nsequence=[1-9][0-9]{0,19}\nnonce=[0-9a-f]{64}\ninstance=[A-Za-z0-9._-]{1,128}\ngeneration=[1-9][0-9]{0,19}\npolicy=[A-Za-z0-9._-]{1,128}\n\z') { throw 'Invalid domain-bound challenge' }
  $key=[Security.Cryptography.CngKey]::Open($KeyName,$provider)
}
try {
  if ($key.Provider.Provider -ne 'Microsoft Platform Crypto Provider' -or $key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None) { throw 'Provider/export policy mismatch; no downgrade' }
  $public=$key.Export([Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob)
  $sha=[Security.Cryptography.SHA256]::Create()
  try { $fingerprint=([BitConverter]::ToString($sha.ComputeHash($public))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
  $output=[ordered]@{ classification='Recorded'; kind='identity-signature-only'; provider=$key.Provider.Provider; keyName=$KeyName; publicBlobFormat='BCRYPT_RSAPUBLIC_BLOB'; publicBlob=[Convert]::ToBase64String($public); publicBlobSha256=$fingerprint; hardwareEnrollmentVerified=$false; platformStateVerified=$false }
  if ($Operation -eq 'Sign') {
    $rsa=[Security.Cryptography.RSACng]::new($key)
    try { $signature=$rsa.SignData($message,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1);$output.signature=[Convert]::ToBase64String($signature);$output.scheme='RSASSA-PKCS1-v1_5-SHA256' } finally { $rsa.Dispose() }
  }
  [pscustomobject]$output | ConvertTo-Json
} finally { $key.Dispose() }
