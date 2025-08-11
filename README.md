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

# DA01 � Injections

## Fran�ais
Ce module d�montre de multiples variantes d'injections dans une application desktop .NET?:
- **Injection SQL**?: requ�te construite dynamiquement, vuln�rable � l�injection de code SQL (`admin'--`)
- **Injection de commande OS**?: ex�cution d�une commande dont l�argument est contr�l� par l�utilisateur (`127.0.0.1 & calc.exe`)
- **Injection LDAP**?: filtre de recherche utilisateur non �chapp� (`*)(uid=*)`)
- **Injection XML (XXE)**?: XML parser vuln�rable � l�inclusion d�entit� externe (`<!DOCTYPE foo ...>`)
- **NoSQL Injection**?: param�tre non contr�l� dans une requ�te JSON MongoDB/CosmosDB (`{$ne:null}`)
- **Path Traversal**?: chemin fichier non valid� (`..\..\Windows\win.ini`)
- **OS Path Injection**?: ex�cution d�un binaire dont le chemin est fourni (`c:\windows\system32\notepad.exe`)
- **XSS Desktop**?: contenu HTML non �chapp� dans un WebView (`<script>alert('xss')</script>`)
- **Expression Language Injection**?: expression dynamique ex�cutable (`x == 1 || true`)

Chaque champ propose un **payload pr�t � l�emploi** et chaque attaque est d�clenchable par un bouton.

---

## English
This module demonstrates multiple injection variants in a .NET desktop application:
- **SQL Injection**: dynamic query construction, vulnerable to SQL code injection (`admin'--`)
- **Command Injection**: execution of an OS command with user-controlled argument (`127.0.0.1 & calc.exe`)
- **LDAP Injection**: user search filter not escaped (`*)(uid=*)`)
- **XML Injection (XXE)**: XML parser vulnerable to external entity injection (`<!DOCTYPE foo ...>`)
- **NoSQL Injection**: uncontrolled parameter in a JSON MongoDB/CosmosDB query (`{$ne:null}`)
- **Path Traversal**: unchecked file path (`..\..\Windows\win.ini`)
- **OS Path Injection**: execution of binary from user-supplied path (`c:\windows\system32\notepad.exe`)
- **Desktop XSS**: unescaped HTML content in a WebView (`<script>alert('xss')</script>`)
- **Expression Language Injection**: dynamic executable expression (`x == 1 || true`)

Each field comes with a **ready-to-use payload**, and each attack can be triggered with a button.

---

> **?? Ce code est intentionnellement vuln�rable, � n'utiliser qu'� des fins de test et formation !  
> ?? This code is intentionally vulnerable, for testing and educational use only!**


# DA02 � Broken Authentication & Session Management

## ENGLISH

This module demonstrates authentication/session vulnerabilities:
- **Hardcoded password**: password in code
- **Global session variable**: session state shared and static
- **No session expiration**: sessions never expire
- **Predictable session token**: tokens generated using timestamps
- **Session reuse**: session/token not invalidated after logout
- **Authentication bypass**: logic error allows access without auth
- **Poor multi-user management**: session shared between users
- **No brute force protection**: unlimited login attempts

---

## FRAN�AIS

Ce module d�montre des vuln�rabilit�s d�authentification/session :
- **Mot de passe cod� en dur**?: secret pr�sent dans le code source
- **Session globale**?: variable partag�e et statique
- **Absence d�expiration de session**?: session jamais invalid�e
- **Jeton pr�visible**?: tokens g�n�r�s via timestamp
- **R�utilisation de session**?: token non invalid� apr�s d�connexion
- **Bypass Auth**?: erreur logique, acc�s sans authentification
- **Mauvaise gestion multi-utilisateur**?: session partag�e entre comptes
- **Pas de protection brute force**?: nombre illimit� de tentatives

---

> ?? Code volontairement vuln�rable, usage p�dagogique et test SAST/SCA uniquement?!

# DA03 � Sensitive Data Exposure / Data Protection

## ENGLISH

This module demonstrates practical ways sensitive data can be exposed or poorly protected in a .NET desktop application.

**Included scenarios:**
1. **Sensitive data in memory:** secrets are stored in RAM and never cleared.
2. **Unencrypted CSV export:** sensitive data saved in local CSV file with no encryption.
3. **Sensitive data in logs:** secrets, credentials or PII written in cleartext to application logs.
4. **Public file sharing:** secret data written to a public folder.
5. **Clipboard exposure:** sensitive information copied to the system clipboard and may be read by other apps or users.
6. **Weak �encryption�:** data is �protected� using reversible algorithms like base64.
7. **Hardcoded secret:** a sensitive value is present in code and revealed by the interface.
8. **Sensitive data in temp file:** secret is written to a temporary file.
9. **Sensitive data in window title:** secret is displayed in the window title.
10. **Verbose error with secret:** exception or error includes sensitive value in its message.

Each scenario provides an example payload and can be triggered from the UI.  
**The code is intentionally vulnerable for training, awareness, and security tool testing.**

---

## FRAN�AIS

Ce module pr�sente des exemples concrets d�exposition ou de mauvaise protection de donn�es sensibles dans une application desktop .NET.

**Sc�narios inclus?:**
1. **Donn�es sensibles en m�moire?:** des secrets restent stock�s en RAM et ne sont jamais effac�s.
2. **Export CSV non chiffr�?:** des donn�es sensibles sont sauvegard�es dans un fichier CSV local sans chiffrement.
3. **Donn�es sensibles dans les logs?:** secrets, identifiants ou PII sont �crits en clair dans les journaux applicatifs.
4. **Partage de fichiers publics?:** une donn�e confidentielle est �crite dans un dossier accessible � tous.
5. **Fuite via le presse-papiers?:** des informations sensibles sont copi�es dans le presse-papiers syst�me, et peuvent �tre lues par d�autres applications ou utilisateurs.
6. **Chiffrement faible ou inexistant?:** la donn�e est �prot�g�e� avec des algorithmes r�versibles (base64).
7. **Secret cod� en dur?:** une valeur sensible est pr�sente dans le code et r�v�l�e par l�interface.
8. **Donn�e sensible dans un fichier temporaire?:** un secret est �crit dans un fichier temp.
9. **Secret dans le titre de la fen�tre?:** une information sensible est affich�e dans le titre de la fen�tre.
10. **Exception verbeuse avec secret?:** une erreur ou exception inclut la valeur sensible dans son message.

Chaque sc�nario inclut un exemple de payload et peut �tre test� depuis l�interface.  
**Le code est volontairement vuln�rable pour la formation, la sensibilisation et le test d�outils de s�curit�.**


# DA04 � Insecure Communication & Unsafe Interprocess/External Interactions

## ENGLISH

This module demonstrates insecure communications and unsafe external or interprocess interactions in a desktop application.

**Included scenarios:**
- **No TLS/SSL on network communication**: sending data to a server in cleartext (HTTP).
- **Accepts invalid SSL certificates**: disables certificate validation, allowing MiTM.
- **Unsafe inter-process communication (IPC)**: named pipes, files, or other IPC channels without authentication.
- **Command/Process injection via IPC**: user-controlled data executed as a command or process.
- **Unprotected named pipe/socket**: creates or connects to IPC channels with no ACLs.
- **Dangerous service/port exposed**: opens local ports or services without authentication.
- **Unauthenticated communication**: sends requests or data without credentials or session.
- **Secrets sent in clear over network**: API keys, passwords, etc. transmitted on HTTP or insecure protocols.

Each scenario provides a typical payload and can be triggered from the interface.  
**This code is intentionally vulnerable for training and detection with SAST/DAST tools.**

---

## FRAN�AIS

Ce module illustre des communications non s�curis�es et des interactions inter-processus ou externes risqu�es dans une application desktop.

**Sc�narios inclus :**
- **Pas de TLS/SSL sur la communication r�seau**?: envoi de donn�es en clair (HTTP).
- **Accepte les certificats SSL invalides**?: d�sactivation de la v�rification des certificats, vuln�rable au MiTM.
- **IPC non s�curis�**?: pipes nomm�s, fichiers ou autres canaux IPC sans authentification.
- **Injection de commande/processus via IPC**?: donn�es utilisateur ex�cut�es comme commande ou process.
- **Canal/socket non prot�g�**?: cr�ation ou connexion � un pipe/socket sans ACL.
- **Service/port dangereux expos�**?: ouverture de ports/services locaux sans authentification.
- **Communication non authentifi�e**?: envoi de requ�tes ou donn�es sans credentials/session.
- **Secrets envoy�s en clair**?: mots de passe, API keys, etc. sur HTTP ou protocoles non chiffr�s.

Chaque sc�nario pr�sente un payload-type et peut �tre d�clench� depuis l�interface.  
**Le code est intentionnellement vuln�rable, usage formation et outils SAST/DAST.**


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

