# Net8-Desktop-InsecureApp

**Application WPF .NET 8 volontairement vuln�rable � OWASP Desktop App Security Top 10**

Chaque bouton de l�application d�clenche une vuln�rabilit�, pour la d�tection SAST/SCA et la formation � la s�curit�.

## Liste des vuln�rabilit�s

- **DA1 � Injection** : Requ�te SQL construite dynamiquement sans param�trage (vuln�rable � l�injection SQL).
- **DA2 � Broken Authentication/Session** : Stockage du mot de passe en clair et gestion de session par variable globale statique.
- **DA3 � Sensitive Data Exposure** : Ecriture d�un mot de passe en clair sur disque.
- **DA4 � Improper Cryptography Usage** : Utilisation de DES (algorithme faible) avec une cl� cod�e en dur.
- **DA5 � Improper Authorization** : Manipulation de fichiers sensibles sans contr�le de droits.
- **DA6 � Security Misconfiguration** : Mode debug actif avec informations sensibles dans les logs.
- **DA7 � Insecure Communication** : Transmission de secrets via HTTP non s�curis�.
- **DA8 � Poor Code Quality** : D�passement de tampon (buffer overflow).
- **DA9 � Known Vulnerable Component** : Usage d�une version vuln�rable de Newtonsoft.Json.

Chaque vuln�rabilit� est document�e dans son fichier respectif, et le code est volontairement non s�curis� pour les besoins de test et formation.

##  Ne jamais utiliser ce code en production !

# DA01 � Injections (WPF, .NET Framework 4.7.2)

**Purpose.** Showcase 15 classic injection sinks in a desktop context. The UI calls centralized sinks in `InjectionVuln.cs` so SAST can flag CWE issues reliably.

## How to run
- Build & run the app, open **DA01 � Injections**.
- Use default payloads or your own; observe popups/inline feedback. Some cases will error on purpose (still valuable for SAST).

## Injections covered (15)
| # | UI Card | Method | What it shows | Likely CWE | SAST Hints |
|---|---------|--------|---------------|------------|------------|
| 1 | SQL Injection | `RunSqlInjection(input)` | String concat in SQL command | CWE-89 | `SqlCommand.CommandText` + concat |
| 2 | OS Command Injection | `RunCommandInjection(payload)` | `cmd.exe /C` with user input | CWE-78 | `Process.Start("cmd.exe", "/C "+�)` |
| 3 | LDAP Injection | `RunLdapInjection(filter)` | Unsafe `DirectorySearcher.Filter` | CWE-90 | `DirectorySearcher.Filter` + concat |
| 4 | XPath Injection | `RunXpathInjection(xpath)` | User XPath passed to `SelectNodes` | CWE-643 | `XmlDocument.SelectNodes(user)` |
| 5 | XXE / XML Injection | `RunXxeInjection(xml)` | DTD + resolver enabled | CWE-611 | `DtdProcessing.Parse`, `XmlResolver` |
| 6 | XSLT Injection | `RunXsltInjection(xsl)` | User stylesheet loaded/applied | CWE-94/917 | `XslCompiledTransform.Load` (user) |
| 7 | OS Path Injection | `RunOsPathInjection(path)` | Write to user path (traversal) | CWE-22 | `File.WriteAllText(userPath)` |
| 8 | Expression Injection | `RunExpressionInjection(expr)` | `DataTable.Compute(expr)` | CWE-94 | Expression evaluation |
| 9 | Regex Injection / ReDoS | `RunRegexInjection(pattern,sample)` | User regex compiled & executed | CWE-1333 | `new Regex(userPattern)` |
|10 | Process Args Injection | `RunProcessArgsInjection(exe,args)` | Launch external tool with args | CWE-88/78 | `ProcessStartInfo` user args |
|11 | CSV Formula Injection | `RunCsvFormulaInjection(cell)` | Dangerous formula cell in CSV | CWE-1236 | `=,+,-,@` leading cells |
|12 | PowerShell Injection | `RunPowershellInjection(ps)` | powershell.exe `-Command` user data | CWE-78 | `Process.Start("powershell.exe", �)` |
|13 | XAML Injection | `RunXamlInjection(xaml)` | `XamlReader.Parse` on user XAML | CWE-915/94 | `XamlReader.Parse` |
|14 | Reflection Type Injection | `RunReflectionInjection(type)` | `Type.GetType` + instantiate | CWE-470 | `Activator.CreateInstance(user)` |
|15 | Assembly Load Injection | `RunAssemblyLoadInjection(path)` | Load assembly from user path | CWE-114 | `Assembly.LoadFrom(user)` |

## Safer alternatives (short)
- Use **parameterized queries** and allowlists.
- Never pass user input to **shell/PowerShell**; prefer safe APIs.
- Disable DTD/XmlResolver; avoid `XamlReader.Parse` on untrusted text.
- Sanitize/normalize filesystem paths; use sandboxed locations.
- Avoid dynamic code/expr/reflection on untrusted input.


---

# DA01 � Injections (FR)

**Objectif.** Pr�senter 15 sinks d�injection en contexte desktop. L�UI appelle `InjectionVuln.cs` pour une d�tection **SAST** fiable.

## Ex�cution
- Build & run, ouvre **DA01 � Injections**.
- Utilise les payloads par d�faut ou les tiens ; certains cas g�n�rent volontairement des erreurs (toujours utiles c�t� SAST).

## Cas couverts (15)
| # | Carte UI | M�thode | Contenu d�montr� | CWE (indicatif) | Indices SAST |
|---|----------|--------|------------------|------------------|--------------|
| 1 | Injection SQL | `RunSqlInjection(input)` | Concat�nation dans une requ�te | CWE-89 | `SqlCommand.CommandText` + concat |
| 2 | Injection de commande OS | `RunCommandInjection(payload)` | `cmd.exe /C` avec entr�e utilisateur | CWE-78 | `Process.Start("cmd.exe", �)` |
| 3 | Injection LDAP | `RunLdapInjection(filter)` | `DirectorySearcher.Filter` non s�curis� | CWE-90 | Concat�nation du filtre |
| 4 | Injection XPath | `RunXpathInjection(xpath)` | XPath utilisateur dans `SelectNodes` | CWE-643 | `SelectNodes(user)` |
| 5 | XXE / Injection XML | `RunXxeInjection(xml)` | DTD + r�solveur activ�s | CWE-611 | `DtdProcessing.Parse`, `XmlResolver` |
| 6 | Injection XSLT | `RunXsltInjection(xsl)` | Feuille XSL contr�l�e par l�utilisateur | CWE-94/917 | `XslCompiledTransform.Load` |
| 7 | Injection de chemin OS | `RunOsPathInjection(path)` | �criture sur chemin utilisateur | CWE-22 | `File.WriteAllText` |
| 8 | Injection d�expression | `RunExpressionInjection(expr)` | `DataTable.Compute(expr)` | CWE-94 | �val d�expression |
| 9 | Injection Regex / ReDoS | `RunRegexInjection(pattern,sample)` | Regex utilisateur compil�e/ex�cut�e | CWE-1333 | `new Regex(user)` |
|10 | Injection d�arguments de process | `RunProcessArgsInjection(exe,args)` | Lancement d�outil externe | CWE-88/78 | `ProcessStartInfo` |
|11 | Injection de formule CSV | `RunCsvFormulaInjection(cell)` | Cellule dangereuse (=,+,-,@) | CWE-1236 | CSV en clair |
|12 | Injection PowerShell | `RunPowershellInjection(ps)` | `powershell.exe -Command` | CWE-78 | `Process.Start("powershell.exe")` |
|13 | Injection XAML | `RunXamlInjection(xaml)` | `XamlReader.Parse` sur XAML | CWE-915/94 | `XamlReader.Parse` |
|14 | Injection de type (Reflection) | `RunReflectionInjection(type)` | `Type.GetType` + instance | CWE-470 | `Activator.CreateInstance` |
|15 | Injection via chargement d�assembly | `RunAssemblyLoadInjection(path)` | `Assembly.LoadFrom` | CWE-114 | Chargement dynamique |

## Bonnes pratiques (r�sum�)
- **Param�trer** les requ�tes ; listes d�autorisation strictes.
- Pas d�entr�e utilisateur transmise au **shell/PowerShell**.
- D�sactiver DTD/XmlResolver ; ne pas parser XAML non fiable.
- Normaliser/s�curiser les chemins ; r�pertoires d�di�s.
- �viter le code/expr/r�flexion dynamiques sur entr�es non fiables.


---

> **?? Ce code est intentionnellement vuln�rable, � n'utiliser qu'� des fins de test et formation !  
> ?? This code is intentionally vulnerable, for testing and educational use only!**


## DA02 � Broken Authentication & Session Management (WPF, .NET Framework 4.7.2)

**Purpose.** This window demonstrates intentionally vulnerable authentication/session patterns. The UI calls centralized sinks in `AuthSessionVuln.cs` so SAST can flag CWE issues clearly.

### How to run
- Build and start the app, open **DA02 � Broken Authentication**.
- Each card has inputs, an action button, and inline feedback (some also show a popup).

### Exposed vulnerabilities
| # | UI Card | Method | What it shows | Likely CWE | SAST Hints |
|---|---------|--------|---------------|------------|------------|
| 1 | Password in Cleartext | `HardcodedPassword()` | Hardcoded password/secret | CWE-798 | Hardcoded credential/secret string |
| 2 | Weak Token Generation | `PredictableToken()` | Predictable token (clock + `Random`) | CWE-330/338 | `System.Random` used for tokens |
| 3 | No Brute Force Protection | `NoBruteForceProtection()` | Unlimited login attempts | CWE-307 | No throttling/lockout |
| 4 | Session Fixation | `SessionFixation(id)` | Accepts attacker-provided session ID | CWE-384 | No session regeneration |
| 5 | Missing MFA + MD5 | `LoginWithoutMfa(u,p)` | No MFA, weak hash (MD5) | CWE-327/306/287 | `MD5.Create()` |
| 6 | Global Session | `GlobalSession()` | Single in-memory global session | CWE-613 (approx) | Global static state |
| 7 | No Session Expiration | `NoSessionExpiration()` | No TTL/expiry | CWE-613 | No timeout/invalidation |
| 8 | Reuse Session Across Users | `ReuseSession()` | Same ID reused cross users | CWE-384/613 | Shared SID |
| 9 | Weak Session ID | `WeakSessionIdGeneration()` | Short, low-entropy SID | CWE-330/331 | 8-char base36 + `Random` |
|10 | Predictable Reset Token | `InsecureResetToken(u)` | Base64(username:ticks) | CWE-640/330 | Derivable from public data |
|11 | Remember-Me plaintext | `RememberMePersist(u)` | Long-lived token in public folder | CWE-922/312 | Plaintext token on disk |
|12 | Insecure TLS Login | `InsecureTlsLogin(url,u,p)` | Trust-all TLS + POST creds | CWE-295 | `ServerCertificateValidationCallback => true` |
|13 | Insecure Deserialization | `InsecureDeserializeSession(b64)` | `BinaryFormatter` deserialization | CWE-502 | `BinaryFormatter` usage |
|14 | AES-ECB for Session | `EncryptSessionWithEcb(json)` | AES in ECB + hardcoded key | CWE-327 | `AesManaged` + `Mode=ECB` |
|15 | Log Sensitive Token | `LogSensitiveToken(tok)` | Token logged to temp file | CWE-532 | Logging of secrets |

### Safer version (for contrast)
- Regenerate session ID after login; enforce expiry/idle timeouts.
- MFA; password hashing with PBKDF2/bcrypt/scrypt/Argon2 + unique salt.
- Cryptographic randomness for tokens/IDs (`RandomNumberGenerator`).
- Never trust-all TLS; use proper certificate validation.
- Avoid `BinaryFormatter`; prefer safe serializers with strict validation.
- Don�t log secrets/tokens; redact sensitive fields.

---

## FRAN�AIS

**Objectif.** D�montrer des patterns d�authentification/session volontairement vuln�rables.  
L�UI appelle des sinks centralis�s dans `AuthSessionVuln.cs` afin que les outils **SAST** identifient nettement les CWE.

### Ex�cution
- Build la solution (.NET Framework 4.7.2) et ouvre **DA02 � Broken Authentication**.
- Chaque carte propose des champs, un bouton d�action et un feedback (certaines affichent un `MessageBox`).

### Vuln�rabilit�s expos�es
| # | Carte UI | M�thode | Contenu d�montr� | CWE (indicatif) | Indices SAST courants |
|---|----------|---------|------------------|------------------|-----------------------|
| 1 | Password in Cleartext | `HardcodedPassword()` | Secret/mot de passe **en dur** | CWE-798 | Cha�nes �password/secret� cod�es en dur |
| 2 | Weak Token Generation | `PredictableToken()` | Jeton **pr�visible** (horloge + `Random`) | CWE-330/338 | `System.Random` pour secret/token |
| 3 | No Brute Force Protection | `NoBruteForceProtection()` | Aucune limite d�essais | CWE-307 | Absence de lockout/throttling |
| 4 | Session Fixation | `SessionFixation(id)` | ID de session impos� par l�attaquant | CWE-384 | Pas de r�g�n�ration apr�s login |
| 5 | Missing MFA + MD5 | `LoginWithoutMfa(u,p)` | Pas de MFA + hash **MD5** | CWE-327/306/287 | `MD5.Create()` |
| 6 | Global Session | `GlobalSession()` | Session globale en m�moire | CWE-613 (approx) | �tat statique partag� |
| 7 | No Session Expiration | `NoSessionExpiration()` | Aucune expiration/TTL | CWE-613 | Pas de timeout/invalidation |
| 8 | Reuse Session Across Users | `ReuseSession()` | M�me ID r�utilis� entre users | CWE-384/613 | Partage d�ID |
| 9 | Weak Session ID | `WeakSessionIdGeneration()` | SID court/faible entropie | CWE-330/331 | 8 chars base36 + `Random` |
|10| Predictable Reset Token | `InsecureResetToken(u)` | Base64(username:ticks) | CWE-640/330 | Jeton d�rivable |
|11| Remember-Me plaintext | `RememberMePersist(u)` | Token longue dur�e en clair | CWE-922/312 | �criture de secrets en clair |
|12| Insecure TLS Login | `InsecureTlsLogin(url,u,p)` | TLS **trust-all** + POST creds | CWE-295 | Callback `ServerCertificateValidationCallback => true` |
|13| Insecure Deserialization | `InsecureDeserializeSession(b64)` | `BinaryFormatter` | CWE-502 | Utilisation BinaryFormatter |
|14| AES-ECB for Session | `EncryptSessionWithEcb(json)` | AES en **ECB**, cl� en dur | CWE-327 | `AesManaged` + `Mode=ECB` |
|15| Log Sensitive Token | `LogSensitiveToken(tok)` | Jeton logg� (clair) | CWE-532 | Secrets en logs |

### Bonnes pratiques (version � safe �)
- R�g�n�rer l�ID de session apr�s login, ajouter **expiration** et **idle timeout**.
- **MFA**, et hachage mots de passe avec PBKDF2/bcrypt/scrypt/Argon2 (+sel unique).
- G�n�rer les tokens/SID avec `RandomNumberGenerator`.
- Ne jamais d�sactiver la v�rification TLS.
- �viter `BinaryFormatter`; utiliser des s�rialiseurs s�rs avec validation stricte.
- Ne pas journaliser de secrets (masking/redaction).

> **But p�dagogique**: centraliser les sinks dans `AuthSessionVuln.cs` pour que les outils SAST ressortent les CWE imm�diatement, tout en gardant l�UI simple et localisable (EN/FR).

> ?? Code volontairement vuln�rable, usage p�dagogique et test SAST/SCA uniquement?!

# DA03 � Sensitive Data Exposure (WPF, .NET Framework 4.7.2)

**Purpose.** Demonstrate common sensitive-data exposure mistakes on desktop. The UI calls centralized sinks in `DataExposureVuln.cs` so SAST can reliably flag CWE issues.

## How to run
- Build and start the app, open **DA03 � Sensitive Data Exposure**.
- Try each card with default values; observe popups and inline feedback. Use an intercepting proxy (Burp/ZAP) to see HTTP leaks.

## Exposed vulnerabilities
| # | UI Card | Method(s) | What it shows | Likely CWE | SAST Hints |
|---|---------|-----------|---------------|------------|------------|
| 1 | Sensitive Data in Memory | `StoreInMemory(data)` | Secret kept in RAM, never cleared | CWE-522 | Field retains sensitive value |
| 2 | Export Data in Plain CSV | `ExportCsvCleartext(secret,path)` | Unencrypted CSV on disk | CWE-311/312 | `File.WriteAllText` ? `.csv` |
| 3 | Logging Sensitive Data | `LogSensitive(data)` | Plaintext logging of secrets | CWE-532 | Secrets/PII in logs |
| 4 | Public File Share | `WritePublicShare(data,path)` | Write secret to public/shared path | CWE-200/538 | Public/common path usage |
| 5 | Clipboard Data Exposure | `ClipboardCopySensitive(data)` | Copy secret to clipboard | CWE-200 | `Clipboard.SetText` |
| 6 | Weak Crypto (Base64) | `WeakEncryptionBase64(data)` | Base64 as �encryption� | CWE-327 | `Convert.ToBase64String` |
| 7 | Hardcoded Secret/Key | `HardcodedKey()`, `ExposedSecret()` | Constants embedded in code | CWE-798/312 | Identifiers like key/secret |
| 8 | Sensitive Temp File | `WriteTempSensitiveFile(data)` | Secret in temp file | CWE-312 | `Path.GetTempFileName` + write |
| 9 | Sensitive in Window Title | `LeakInWindowTitle(window,secret)` | Secret in UI/title bar | CWE-200 | `window.Title = secret` |
|10 | Verbose Exception With Secret | `VerboseError(data)` | Error/stacktrace leaks data | CWE-209 | `ex.ToString()` surfaced |
|11 | Insecure HTTP Transport (POST) | `InsecureTransport(url,data)` | POST over HTTP / trust-all TLS | CWE-319/295 | `WebClient.UploadString` to `http://`, cert callback |
|12 | Store Cleartext on Disk | `StoreCleartext(data)` | Plaintext file persisted | CWE-312 | `File.WriteAllText` |
|13 | Weak Encryption (ROT13) | `WeakEncryptionRot13(data)` | Obfuscation, not encryption | CWE-327 | ROT13 routine |
|14 | Insecure HTTP Transport (GET with query) | `InsecureTransportGet(url,query)` | Secrets in URL query string | CWE-319/200 | `HttpWebRequest` + `http://` query |
|15 | Plaintext Connection String (.config) | `WriteConnectionStringConfig()` | Credentials stored in clear config | CWE-312 | `.config` write with creds |
|16 | Windows Registry (plaintext) | `WriteSecretToRegistry(name,val)` | Secret written to HKCU in clear | CWE-312/200 | `Registry.*.SetValue` |
|17 | Weak Encryption (DES-ECB) | `WeakEncryptionDes(data)` | DES-ECB + hardcoded key | CWE-327 | `DESCryptoServiceProvider` + `ECB` |

## Safer version (for contrast)
- Enforce TLS and proper certificate validation; never send secrets over HTTP.
- Encrypt at rest (AES-GCM/ChaCha20-Poly1305) with secure key management (no hardcoding).
- Don�t log secrets; redact and minimize logs.
- Avoid storing secrets in temp files, clipboard, or UI.
- Clear sensitive memory (explicit zeroing / `SecureString` patterns).

---

# DA03 � Exposition de Donn�es Sensibles (WPF, .NET Framework 4.7.2)

**Objectif.** Illustrer des fuites de donn�es sensibles c�t� desktop. L�UI appelle des sinks centralis�s dans `DataExposureVuln.cs` pour faciliter la d�tection **SAST** des CWE.

## Ex�cution
- Build la solution et ouvre **DA03 � Sensitive Data Exposure**.
- Lance chaque carte avec les valeurs par d�faut. Utilise un proxy (Burp/ZAP) pour observer l�HTTP.

## Vuln�rabilit�s expos�es
| # | Carte UI | M�thode(s) | Contenu d�montr� | CWE (indicatif) | Indices SAST |
|---|----------|------------|------------------|------------------|--------------|
| 1 | Donn�es sensibles en m�moire | `StoreInMemory(data)` | Secret conserv� en RAM (non nettoy�) | CWE-522 | Champ stockant le secret |
| 2 | Export CSV en clair | `ExportCsvCleartext(secret,path)` | CSV non chiffr� sur disque | CWE-311/312 | `File.WriteAllText` ? `.csv` |
| 3 | Journalisation de donn�es sensibles | `LogSensitive(data)` | Logs en clair | CWE-532 | Secrets/PII dans logs |
| 4 | Partage de fichier public | `WritePublicShare(data,path)` | �criture de secret dans un dossier partag� | CWE-200/538 | Chemin public/commun |
| 5 | Fuite via le presse-papiers | `ClipboardCopySensitive(data)` | Copie du secret dans le presse-papiers | CWE-200 | `Clipboard.SetText` |
| 6 | Crypto faible (Base64) | `WeakEncryptionBase64(data)` | Base64 pr�sent� comme �chiffrement� | CWE-327 | `Convert.ToBase64String` |
| 7 | Secret/cl� cod�(e) en dur | `HardcodedKey()`, `ExposedSecret()` | Constantes sensibles dans le code | CWE-798/312 | Identifiants suspects : key/secret |
| 8 | Fichier temporaire sensible | `WriteTempSensitiveFile(data)` | Secret dans un fichier temp | CWE-312 | `Path.GetTempFileName` + write |
| 9 | Secret dans le titre de la fen�tre | `LeakInWindowTitle(window,secret)` | Secret affich� dans l�UI | CWE-200 | `window.Title = secret` |
|10 | Exception verbeuse avec secret | `VerboseError(data)` | Message/stack trace divulgue des donn�es | CWE-209 | `ex.ToString()` en UI |
|11 | Transport HTTP non s�curis� (POST) | `InsecureTransport(url,data)` | POST en HTTP / TLS trust-all | CWE-319/295 | `WebClient.UploadString` vers `http://`, callback cert |
|12 | �criture en clair sur disque | `StoreCleartext(data)` | Fichier en clair | CWE-312 | `File.WriteAllText` |
|13 | Chiffrement faible (ROT13) | `WeakEncryptionRot13(data)` | Obfuscation, pas chiffrement | CWE-327 | Routine ROT13 |
|14 | Transport HTTP non s�curis� (GET avec query) | `InsecureTransportGet(url,query)` | Secrets dans l�URL | CWE-319/200 | `HttpWebRequest` + `http://` query |
|15 | Cha�ne de connexion en clair (.config) | `WriteConnectionStringConfig()` | Identifiants stock�s en clair | CWE-312 | �criture `.config` avec creds |
|16 | Registre Windows (en clair) | `WriteSecretToRegistry(name,val)` | Secret sous HKCU en clair | CWE-312/200 | `Registry.*.SetValue` |
|17 | Chiffrement faible (DES-ECB) | `WeakEncryptionDes(data)` | DES-ECB + cl� en dur | CWE-327 | `DESCryptoServiceProvider` + `ECB` |

## Bonnes pratiques (version � safe �)
- Forcer **TLS** avec v�rification stricte ; ne jamais envoyer de secrets en HTTP.
- Chiffrer au repos (AES-GCM/ChaCha20-Poly1305) ; gestion de cl�s s�curis�e (pas de cl�s en dur).
- Ne pas logguer de secrets ; **redacter** et minimiser les logs.
- �viter presse-papiers, fichiers temporaires et UI pour des secrets.
- Nettoyer explicitement la m�moire sensible (`SecureString`/effacement contr�l�).



# DA04 � Insecure Communication & Unsafe Interprocess/External Interactions (WPF, .NET Framework 4.7.2)

**Purpose.** Demonstrate real-world insecure communication, IPC, and unsafe external interactions from a desktop app.  
The UI calls centralized sinks in `CommVuln.cs`, which helps SAST flag issues consistently.

## How to run
- Build and start the app, open **DA04 � Insecure Communication & Unsafe Interactions**.
- Try each card with defaults; observe popups/inline feedback. Use a proxy (Burp/ZAP) or a local socket/FTP/SOAP endpoint to see traffic.

## Exposed vulnerabilities (15)
| # | UI Card | Method | What it shows | Likely CWE | SAST Hints |
|---|---------|--------|---------------|------------|------------|
| 1 | Plain HTTP Request | `HttpPostInsecure(url)` | POST over HTTP, trust-all TLS, legacy protocols | CWE-319/295 | `WebClient.UploadString("http://")`, `ServerCertificateValidationCallback`, `SecurityProtocol = Ssl3|Tls|Tls11` |
| 2 | Plain TCP Socket | `TcpSendPlain(host,port,data)` | Unencrypted TCP payload + creds | CWE-319 | `TcpClient` + `GetStream().Write` |
| 3 | UDP Packet | `UdpSendPlain(host,port,data)` | Unencrypted UDP datagrams | CWE-319 | `UdpClient.Send` |
| 4 | WebSocket (no encryption) | `WebSocketSendInsecure(wsUrl,data)` | `ws://` endpoint (simulated) | CWE-319 | Literal `ws://` usage |
| 5 | Named Pipe (no ACL) | `NamedPipeWriteInsecure(name,data)` | IPC without access control | CWE-284/306 | `NamedPipeClientStream` without security |
| 6 | Insecure File Drop | `WriteSharedFile(folder,file,content)` | Secrets dropped to shared/public folder | CWE-200/538 | `File.WriteAllText` to public path |
| 7 | Unsafe Command Execution | `ExecuteCommandUnsafe(payload)` | Shell/command injection via `/C` | CWE-78 | `Process.Start("cmd.exe", "/C "+payload)` |
| 8 | Unsafe DllImport/COM | `NativeBeep()` | Native call without validation | CWE-676/829 | `DllImport("user32.dll")` |
| 9 | Clipboard Broadcast | `ClipboardCopy(data)` | Secret copied to global clipboard | CWE-200 | `Clipboard.SetText` |
| 10 | SMTP Mail (no TLS) | `SmtpSendNoTls(host,port,...)` | Cleartext email submission | CWE-319 | `SmtpClient.EnableSsl=false` |
| 11 | Registry Write (no ACL) | `RegistryWriteInsecure(line)` | Secret written to HKCU in clear | CWE-276/312 | `Registry.CurrentUser.CreateSubKey().SetValue` |
| 12 | Temp File for IPC | `TempIpcWrite(data)` | Plaintext secret in %TEMP% | CWE-312 | `Path.GetTempPath` + `File.WriteAllText` |
| 13 | FTP Upload (no TLS) | `FtpUploadInsecure(ftpUrl,user,pw,content)` | FTP transfer in clear | CWE-319 | `FtpWebRequest`, `EnableSsl=false`, `Credentials` |
| 14 | SOAP/XML over HTTP (clear) | `SoapOverHttpInsecure(url,action,xml)` | SOAP over HTTP + `SOAPAction` | CWE-319 | `Content-Type: text/xml`, `UploadString("http://")` |
| 15 | Insecure Binary Deserialization | `InsecureDeserializeBinary(base64)` | BinaryFormatter on untrusted data | CWE-502 | `BinaryFormatter.Deserialize` |

## Safer version (for contrast)
- Always use **TLS** with strict certificate validation; avoid trust-all callbacks and legacy protocol flags.
- Secure IPC (Named Pipes with ACLs; authenticated channels).
- Sanitize any input that reaches process execution; avoid `cmd.exe /C`.
- Don�t write secrets to public shares/registry/temp/clipboard; apply least privilege and encrypt at rest.
- Avoid `BinaryFormatter`; use safe serializers with strict type binding and validation.

---

# DA04 � Communications & Interactions non s�curis�es (WPF, .NET Framework 4.7.2)

**Objectif.** Illustrer des communications/IPC non s�curis�es et des interactions externes risqu�es c�t� desktop.  
L�UI appelle des sinks centralis�s dans `CommVuln.cs` pour faciliter la d�tection **SAST**.

## Ex�cution
- Build et lance l�app, ouvre **DA04 � Communications & Interactions non s�curis�es**.
- Teste chaque carte ; observe les popups/retours inline. Utilise un proxy (Burp/ZAP) ou des endpoints locaux (socket/FTP/SOAP) pour voir le trafic.

## Vuln�rabilit�s expos�es (15)
| # | Carte UI | M�thode | Contenu d�montr� | CWE (indicatif) | Indices SAST |
|---|----------|--------|------------------|------------------|--------------|
| 1 | Requ�te HTTP non s�curis�e | `HttpPostInsecure(url)` | POST en HTTP, TLS trust-all, protocoles legacy | CWE-319/295 | `WebClient.UploadString("http://")`, `ServerCertificateValidationCallback`, `SecurityProtocol = Ssl3|Tls|Tls11` |
| 2 | Socket TCP sans TLS | `TcpSendPlain(host,port,data)` | Donn�es TCP en clair + creds | CWE-319 | `TcpClient` + `Write` |
| 3 | Paquet UDP | `UdpSendPlain(host,port,data)` | Donn�es UDP en clair | CWE-319 | `UdpClient.Send` |
| 4 | WebSocket non chiffr� | `WebSocketSendInsecure(wsUrl,data)` | Usage `ws://` (simulation) | CWE-319 | Litt�ral `ws://` |
| 5 | NamedPipe sans ACL | `NamedPipeWriteInsecure(name,data)` | IPC sans contr�le d�acc�s | CWE-284/306 | `NamedPipeClientStream` sans s�curit� |
| 6 | D�p�t fichier non s�curis� | `WriteSharedFile(folder,file,content)` | Secret dans un dossier partag�/public | CWE-200/538 | �criture fichier public |
| 7 | Ex�cution de commande non filtr�e | `ExecuteCommandUnsafe(payload)` | Injection via `/C` | CWE-78 | `Process.Start("cmd.exe", "/C "+payload)` |
| 8 | DllImport/COM risqu� | `NativeBeep()` | Appel natif sans validation | CWE-676/829 | `DllImport("user32.dll")` |
| 9 | Diffusion presse-papiers | `ClipboardCopy(data)` | Secret copi� dans le presse-papiers global | CWE-200 | `Clipboard.SetText` |
| 10 | SMTP sans TLS | `SmtpSendNoTls(host,port,...)` | Envoi email en clair | CWE-319 | `EnableSsl=false` |
| 11 | �criture registre | `RegistryWriteInsecure(line)` | Secret sous HKCU en clair | CWE-276/312 | `CreateSubKey().SetValue` |
| 12 | Fichier temporaire IPC | `TempIpcWrite(data)` | Secret en clair dans %TEMP% | CWE-312 | `Path.GetTempPath` + `WriteAllText` |
| 13 | Upload FTP (sans TLS) | `FtpUploadInsecure(ftpUrl,user,pw,content)` | Transfert FTP en clair | CWE-319 | `FtpWebRequest`, `EnableSsl=false`, `Credentials` |
| 14 | SOAP/XML sur HTTP (clair) | `SoapOverHttpInsecure(url,action,xml)` | SOAP en HTTP + `SOAPAction` | CWE-319 | `Content-Type: text/xml`, `UploadString("http://")` |
| 15 | D�s�rialisation binaire non s�curis�e | `InsecureDeserializeBinary(base64)` | BinaryFormatter sur donn�es non fiables | CWE-502 | `BinaryFormatter.Deserialize` |

## Bonnes pratiques (version � safe �)
- Toujours utiliser **TLS** avec validation stricte ; proscrire les callbacks trust-all et les protocoles obsol�tes.
- S�curiser l�IPC (ACL sur NamedPipe ; canaux authentifi�s).
- Filtrer les entr�es avant ex�cution de processus ; �viter `cmd.exe /C`.
- Ne pas stocker de secrets en clair (partages/registre/temp/presse-papiers) ; chiffrer et appliquer le moindre privil�ge.
- Bannir `BinaryFormatter` ; privil�gier des s�rialiseurs s�rs avec validation stricte.



# DA05 � Insufficient Authorization / Access Control (.NET Patterns)

## ENGLISH

**Demonstrates 10 common access control failures in .NET desktop apps, with explicit .NET security patterns (attributes, principals, dangerous API). All code is intentionally vulnerable.**

- BOLA: File access with no user check.
- IDOR: Access user data by ID, no verification.
- Vertical Privilege Escalation: Run admin command, no [PrincipalPermission].
- Horizontal Privilege Escalation: Read another user's data (same role, no check).
- Forced Browsing: Hidden feature callable by guessing function name (no attribute).
- Missing Function Level Access: Dangerous function callable by anyone, no role check.
- Role Tampering: User sets roles directly via Thread.CurrentPrincipal.
- Unprotected Event Handler: Delegate called with no authorization.
- Security Through Obscurity: Admin action available by guessing magic path.
- Role Confusion: Combination of roles grants excessive privileges.

## FRAN�AIS

**D�montre 10 failles classiques de contr�le d�acc�s dans une appli desktop .NET, en utilisant des patterns de s�curit� natifs (attributs, principals, API critique). Tout est volontairement vuln�rable.**

- BOLA�: Lecture fichier sans check utilisateur.
- IDOR�: Donn�es d�utilisateur accessibles par ID sans v�rification.
- Escalade verticale�: Ex�cution admin sans [PrincipalPermission].
- Escalade horizontale�: Lecture donn�es d�un autre user (m�me r�le, pas de check).
- Forced Browsing�: Fonction cach�e accessible par devinette (pas d�attribut).
- Absence de contr�le fonctionnel�: Fonction sensible accessible � tous.
- Role Tampering�: Modification directe de Thread.CurrentPrincipal.
- Event handler non prot�g�: Delegate critique accessible � tous.
- Obscurit�: Action admin accessible par devinette du chemin.
- Role confusion�: Combinaison de r�les donne trop de droits.



# DA06 � Insecure Resources & Dependency Management

## ENGLISH

This module demonstrates multiple insecure patterns in dependency management and resource loading for .NET desktop apps.

**Included scenarios:**
- **Call Vulnerable DLL**: Loads and executes code from an outdated/vulnerable DLL.
- **Dynamic Assembly Load**: Loads assemblies from user-supplied paths with no validation.
- **Load All Plugins**: Loads all DLLs in a directory without whitelist or integrity check.
- **Download & Execute DLL**: Downloads a DLL from a remote URL and loads it, trusting the network.
- **Load From Manifest**: Loads dependencies as listed in a user-editable manifest.json file.
- **User Import DLL**: Loads a DLL explicitly chosen by the user (BYOVD).
- **DLL Hijacking**: Launches an .exe, which will load any DLL (e.g., evil.dll) in the same directory.
- **Call Vulnerable NuGet Package**: Invokes a method from a fake vulnerable NuGet package.
- **Download External Resource via HTTP**: Downloads and uses a config/script file over insecure HTTP.
- **Dynamic PowerShell Script Execution**: Runs PowerShell code from user input.
- **Load DLL via Relative Path**: Loads a DLL using a relative path, prone to hijacking or planting.

Each scenario has a test field and button in the interface, all code is intentionally vulnerable for security testing.

---

## FRAN�AIS

Ce module d�montre divers sc�narios de gestion non s�curis�e des ressources et d�pendances dans les applis .NET desktop.

**Sc�narios inclus?:**
- **Appel DLL vuln�rable**?: charge et ex�cute du code depuis une DLL obsol�te/vuln�rable.
- **Chargement d�assembly dynamique**?: charge une assembly depuis un chemin non valid�.
- **Chargement de tous les plugins**?: charge toutes les DLL d�un dossier sans whitelist ou contr�le d�int�grit�.
- **T�l�chargement/chargement de DLL distante**?: r�cup�re une DLL via HTTP(s) puis la charge directement.
- **Chargement via manifest**?: charge des d�pendances depuis un manifest.json modifiable.
- **Import DLL utilisateur**?: charge une DLL explicitement choisie (BYOVD).
- **DLL hijacking**?: lance un .exe, qui charge n�importe quelle DLL (ex?: evil.dll) pr�sente.
- **Appel package NuGet vuln�rable**?: appelle une m�thode d�une librairie NuGet fictive vuln�rable.
- **T�l�charger une ressource externe HTTP**?: t�l�charge et charge un fichier config/script via HTTP non s�curis�.
- **Ex�cution dynamique de script PowerShell**?: ex�cute un code PowerShell fourni.
- **Charger DLL par chemin relatif**?: charge une DLL par chemin relatif (risque de planting/hijack).

Chaque sc�nario inclut un champ et un bouton de test, d�clenchable dans l�interface.
**Le code est volontairement vuln�rable, usage formation et tests s�curit�.**

# DA08 � Security Misconfiguration

## ENGLISH

This module demonstrates typical security misconfigurations in desktop .NET apps.

**Included scenarios:**
- **Plaintext secrets in App.config:** Sensitive keys/passwords stored unencrypted in config.
- **Hardcoded absolute paths:** Files or folders referenced with fixed drive/root paths.
- **Verbose logging in production:** Debug logs left enabled and leaking data in prod builds.
- **Global/shared temp directory:** Use of world-writable temp folders for critical files.
- **Private key/certificate in project:** Sensitive credentials shipped with the app.
- **Wide permissions (Everyone):** Critical files/folders with world access rights.
- **Writable hosts/system files:** App or user can edit system config like hosts.
- **Debug mode enabled in prod:** Compilation or runtime flags enable debug in release.
- **Weak cryptography:** Allowed use of outdated/insecure algorithms (ex: MD5, DES).
- **Insecure IPC:** Inter-process communication endpoints with no auth or encryption.
- **Runs as admin:** App runs with administrator privileges by default.

All scenarios are accessible from the interface for security testing and education.

---

## FRAN�AIS

Ce module illustre les mauvaises configurations de s�curit� typiques des applications desktop .NET.

**Sc�narios inclus?:**
- **Secrets en clair dans App.config?:** cl�s/mots de passe sensibles stock�s non chiffr�s.
- **Chemins absolus cod�s en dur?:** fichiers/r�pertoires r�f�renc�s avec des chemins fixes.
- **Logs verbeux en production?:** traces debug actives en prod, fuite de donn�es.
- **R�pertoire temporaire partag�?:** usage de dossiers temp accessibles � tous pour fichiers critiques.
- **Cl� priv�e/certificat dans le projet?:** credentials sensibles inclus dans le binaire.
- **Permissions �Everyone�?:** acc�s universel sur des fichiers/r�pertoires sensibles.
- **Fichiers syst�me �ditables?:** modification possible des fichiers hosts/system par l�app.
- **Mode debug actif en prod?:** flags de compilation ou ex�cution debug en production.
- **Crypto faible?:** utilisation permise d�algos obsol�tes (ex?: MD5, DES).
- **IPC non s�curis�?:** communication inter-processus sans auth ni chiffrement.
- **Ex�cution admin par d�faut?:** application lanc�e avec les droits admin sans raison.

Chaque sc�nario est testable via l�interface pour la formation ou l�analyse s�curit�.

# DA09 � Improper Error & Exception Handling

## ENGLISH

This module demonstrates insecure error and exception handling patterns in .NET desktop apps.

**Included scenarios:**
- **Stacktrace in UI:** Shows the .NET stacktrace to the user on error.
- **Uncaught exception (crash):** No handler, app closes with native dialog.
- **Generic catch (swallow):** Exceptions silently swallowed, logic continues.
- **Technical error in prod:** UI displays technical or debug info instead of user message.
- **Overly verbose error logs:** Writes full errors to logs in production.
- **Leaking system info:** Errors leak OS, path, user or version info.
- **Exposing inner exceptions:** Shows nested exception details (db/network/other).
- **Throw in prod:** Throws error up the stack without catch or handler.
- **No global handler:** No `AppDomain.CurrentDomain.UnhandledException` or `DispatcherUnhandledException` set.
- **Poor IO/network error handling:** Minimal/no try/catch for file/network ops.
- **Sensitive info in error log:** Logs passwords/tokens in error traces.
- **Crash dump file world-readable:** Crash logs/dumps written with wide permissions.

All cases can be triggered from the interface.  
**The code is intentionally vulnerable for education and security testing.**

---

## FRAN�AIS

Ce module illustre les mauvaises pratiques de gestion des erreurs/exceptions dans les applis .NET desktop.

**Sc�narios inclus?:**
- **Stacktrace dans l�UI?:** Affiche la stacktrace .NET compl�te � l�utilisateur.
- **Exception non catch�e (crash)?:** Pas de gestion, l�appli ferme sur crash natif.
- **Catch g�n�rique silencieux?:** L�exception est �swallow� sans log ni signal.
- **Erreur technique en prod?:** Message technique/debug montr� � l�utilisateur.
- **Logs d�erreur verbeux?:** Traces d�taill�es m�me en prod.
- **Fuite d�infos syst�me?:** Erreur r�v�le OS, chemin, utilisateur, version�
- **Exposer inner exceptions?:** D�tail d�exception imbriqu�e affich�/bruit�.
- **Throw sans catch global?:** Propagation sans handler, crash ou comportement impr�vu.
- **Pas de handler global?:** Pas de handler UnhandledException/Dispatcher.
- **Mauvaise gestion des erreurs IO/r�seau?:** Peu ou pas de try/catch pour les acc�s fichiers ou r�seau.
- **Infos sensibles dans logs?:** Mot de passe/token/secret logu� dans le d�tail erreur.
- **Crash dump accessible � tous?:** Dump �crit avec droits �Everyone�.

Chaque cas est testable via l�interface.  
**Code volontairement vuln�rable, usage formation/tests s�curit�.**

# DA10 � Insufficient Logging & Monitoring (Desktop/WPF, Extended)

## Table of Contents

1. No log on sensitive file access
2. No admin access log
3. No config change log
4. No log on login failure
5. No alert on forbidden action
6. No deletion log
7. No log on critical error/crash
8. Log only if DEBUG
9. No log rotation/backup
10. World-writable log file
11. Log folder open to all
12. Secrets/creds in cleartext logs

---

### 1. No log on sensitive file access
A file is read, but no trace/audit is kept.  
:warning: **Exploitation:** Attackers read confidential files without detection.

### 2. No admin access log
Admin area used, but access not tracked.  
:warning: **Exploitation:** Unnoticed privilege escalation, no accountability.

### 3. No config change log
User changes config; action not logged.  
:warning: **Exploitation:** Tampering remains invisible; audit trail missing.

### 4. No log on login failure
Bruteforce or password guessing undetected.  
:warning: **Exploitation:** Multiple failed logins; no evidence in logs.

### 5. No alert on forbidden action
Forbidden/blocked actions not logged or alerted.  
:warning: **Exploitation:** Bypass attempts remain stealthy.

### 6. No deletion log
Sensitive files/data are deleted, no record.  
:warning: **Exploitation:** Destruction, sabotage, or cleanup with no trace.

### 7. No log on critical error/crash
Application crash or fatal error leaves no trace for forensics.  
:warning: **Exploitation:** Root cause is hidden, attackers hide their tracks.

### 8. Log only if DEBUG
Security events only logged in DEBUG builds; release/prod is blind.  
:warning: **Exploitation:** Attacks in production go undetected.

### 9. No log rotation/backup
All events in one log file, never rotated; data may be lost or overwritten.  
:warning: **Exploitation:** Logs erased, filled up, or deleted to hide tracks.

### 10. World-writable log file
Logs with �Everyone� rights?: any user or malware can overwrite or destroy logs.  
:warning: **Exploitation:** Log tampering, erasure, or sabotage.

### 11. Log folder open to all
Logs stored in a directory with global access.  
:warning: **Exploitation:** Same as above, but all files at risk.

### 12. Secrets/creds in cleartext logs
Credentials, passwords, tokens, or PII written directly in log files.  
:warning: **Exploitation:** Credential theft by anyone with log access.

---

**Tip SAST/SCA:**  
- Recherchez `File.AppendAllText`, absence de �log�, patterns �WorldSid�, log cleartext passwords, etc.
- Testez avec vos outils SAST �log review� et �sensitive info in logs�.

---

**Besoin d�un exploit step-by-step ou d�une payload pour chaque cas?? Dis-le?!**

