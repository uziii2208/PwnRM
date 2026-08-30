# 01 — Architecture, Core Subsystems & Wire Protocols

## 1. MS-PSRP Wire Protocol & Binary Framing Specification

PowerShell Remoting does not transmit raw plaintext command strings across the network. It operates as a layered protocol stack defined by the **Microsoft PowerShell Remoting Protocol ([MS-PSRP])**, encapsulated within **WS-Management ([MS-WSMV])** SOAP envelopes transported over HTTP (port 5985) or HTTPS (port 5986).

```
+-------------------------------------------------------------------------------+
| HTTP / HTTPS Request Layer (POST /wsman)                                      |
+-------------------------------------------------------------------------------+
| WS-Management SOAP Envelope (<s:Envelope xmlns:s=".../soap-envelope">)        |
+-------------------------------------------------------------------------------+
| PSRP Stream Message (<rsp:Stream Name="stdin" CommandId="...">)               |
+-------------------------------------------------------------------------------+
| PSRP Binary Fragment Header (ObjectId, FragmentId, Flags, BlobLength)         |
+-------------------------------------------------------------------------------+
| PSRP Message Data (Destination, MessageType, RPID, PID, Payload Data)         |
+-------------------------------------------------------------------------------+
| CLIXML Serialized Payload (<Obj RefId="0"><MS><S N="...">...</S></MS></Obj>)  |
+-------------------------------------------------------------------------------+
```

---

### 1.1 WS-Management SOAP Envelope Anatomy ([MS-WSMV])

Every interaction with the WinRM service (`wsmprovhost.exe`) begins with a WS-Management SOAP request. A standard command creation envelope contains strict WS-Addressing and WS-Transfer XML headers:

```xml
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/powershell">
  <s:Header>
    <a:To>http://10.0.0.5:5985/wsman</a:To>
    <a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>
    <a:MessageID>uuid:8C892160-5028-4BC3-9C1C-036B9F2A669B</a:MessageID>
    <w:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.PowerShell</w:ResourceURI>
    <w:MaxEnvelopeSize mustUnderstand="true">512000</w:MaxEnvelopeSize>
    <w:SelectorSet>
      <w:Selector Name="ShellId">uuid:3838E7E4-5CD8-4F11-9A74-12C85A80DB14</w:Selector>
    </w:SelectorSet>
    <w:OptionSet>
      <w:Option Name="protocolversion" MustComply="true">2.3</w:Option>
    </w:OptionSet>
  </s:Header>
  <s:Body>
    <rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
      <rsp:Command>powershell</rsp:Command>
      <rsp:Arguments>-NoProfile -NonInteractive -ExecutionPolicy Bypass</rsp:Arguments>
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>
```

---

### 1.2 Binary Fragment Header Layout ([MS-PSRP] §2.2.4)

When higher-layer PSRP messages exceed the maximum fragment payload capacity (typically 32,768 bytes), the PSRP engine slices the message into binary fragments. Each fragment begins with a mandatory 21-byte binary header:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          ObjectId (8 bytes)                   |
|                      (Big-Endian uint64)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         FragmentId (8 bytes)                  |
|                      (Big-Endian uint64)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Flags     |              Blob Length (4 bytes)            |
|    (1 byte)   |               (Big-Endian uint32)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Fragment Data ...                     |
|                      (Blob Length bytes)                      |
+---------------------------------------------------------------+
```

#### Field Definitions:
- **`ObjectId` (8 bytes, `uint64_be`)**: Unique integer identifier assigned to a single logical PSRP message. All fragments belonging to the same logical message share identical `ObjectId` values.
- **`FragmentId` (8 bytes, `uint64_be`)**: Monotonically increasing zero-based fragment sequence number (`0, 1, 2, ...`).
- **`Flags` (1 byte, bitmask)**:
  - `0x01` (`StartFragment`): Marks the initial fragment of a fragmented message.
  - `0x02` (`EndFragment`): Marks the terminal fragment of a fragmented message.
  - `0x03` (`StartFragment | EndFragment`): Unfragmented message (entire message fits in one fragment).
- **`Blob Length` (4 bytes, `uint32_be`)**: Exact byte count of the fragment payload following the header.

---

### 1.3 PSRP Message Types & Internal Payload Framing ([MS-PSRP] §2.2.1)

Once all fragments for an `ObjectId` are assembled, the inner PSRP message is unpacked according to the following byte layout:

```text
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Destination (4 bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      MessageType (4 bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      RunspacePoolId (16 bytes)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      PipelineId (16 bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Data (CLIXML payload)                    |
+---------------------------------------------------------------+
```

---

## 2. Advanced Transports & Cryptographic Mechanisms

### 2.1 SPNEGO / NTLM & Extended Protection for Authentication (EPA)

PwnRM supports SPNEGO NTLM authentication with full Channel Binding Token (CBT) derivation over TLS:
1. Derives MD5 hash across server TLS certificate SHA-256 fingerprint:
   $$\text{CBT} = \text{MD5}(\text{"tls-server-end-point:"} \,\|\, \text{SHA256}(\text{ServerCert}))$$
2. Injects CBT into the `NTLMSSP_AUTH` message structure to defeat NTLM relay attacks against enforced WinRM listeners.

---

### 2.2 Kerberos GSS-API Transport & RFC 4121 Wrap Token

For Kerberos authentication (`KerberosTransport`):
1. Acquires Service Ticket (`HTTP/target:5985`) from local `.ccache` or KDC.
2. Formats SPNEGO NegTokenInit encapsulating the Kerberos AP-REQ.
3. Upon session establishment, exchanges **RFC 4121 GSS-API Wrap Tokens** (`0x0504` header):
   - Flags `0x01` (`SentByAcceptor` = false), `0x02` (`Sealed` = true).
   - Sequence Number verification and replay protection.
   - Encrypts payload with session subkey using **AES256-CTS-HMAC-SHA1-96**.
4. Wraps HTTP traffic in multipart encrypted boundaries:
   ```http
   POST /wsman HTTP/1.1
   Content-Type: multipart/x-multi-encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"

   --Encrypted Boundary
   Content-Type: application/HTTP-Kerberos-session-encrypted
   OriginalContent: type=application/soap+xml;charset=UTF-8;Length=1024
   --Encrypted Boundary
   Content-Type: application/octet-stream
   [4-byte Signature Length][GSS-API Wrap Token Header + Signature][Encrypted SOAP Body]
   --Encrypted Boundary--
   ```

---

### 2.3 CredSSP (TSSSP) Multi-Hop Credential Delegation

When accessing secondary network resources from a remote WinRM session (solving the "Double-Hop" Kerberos problem), PwnRM initializes a **Credential Security Support Provider (CredSSP)** transport (`CredSSPTransport`):

```asn1
TSRequest ::= SEQUENCE {
    version     [0] INTEGER,
    negoTokens  [1] NegoData OPTIONAL,
    authInfo    [2] OCTET STRING OPTIONAL,
    pubKeyAuth  [3] OCTET STRING OPTIONAL
}

TSCredentials ::= SEQUENCE {
    credType    [0] INTEGER,
    credentials [1] OCTET STRING
}

TSPasswordCreds ::= SEQUENCE {
    domainName  [0] OCTET STRING,
    userName    [1] OCTET STRING,
    password    [2] OCTET STRING
}
```

#### Handshake Sequence:
1. **TLS Handshake**: Initiates an inner TLS tunnel within the SPNEGO/Kerberos authentication exchange.
2. **TSSSP ASN.1 Negotiation**: Exchanges `TSRequest` tokens containing `NegoTokens` and `pubKeyAuth` to cryptographically bind the inner TLS session with the outer authentication layer.
3. **Encrypted Credential Delegation**: Encrypts and transmits the user's plaintext credentials or Kerberos ticket credentials encapsulated within a `TSCredentials` ASN.1 structure to the target's LSASS process.

---

### 2.4 Mutual TLS Client Certificate Transport (PKCS#12)

For environments configured with certificate-based WinRM authentication (e.g. smart cards or ADCS user certificates):
1. `ClientCertTransport` extracts private key and client certificate from `.pfx` or `.pem` files.
2. Injects client certificate material directly into the HTTPS mutual TLS handshake on port 5986.
3. Maps certificate subject SID to user account via Active Directory explicit certificate mapping (`altSecurityIdentities`).

---

## 3. In-Band SOCKS5 Multiplexer & Port Forwarding Mechanics

PwnRM replaces external binary pivoting agents with a zero-binary, in-band **SOCKS5 proxy multiplexer** (`pwnrm.core.tunnel.Socks5Server`) hardened with **thread-safe mutex locks and socket timeout protection**:

```mermaid
sequenceDiagram
    autonumber
    participant App as Proxychains / Web Browser
    participant S5 as PwnRM Socks5Server (127.0.0.1:1080)
    participant PS as Target PowerShell Runspace (wsmprovhost.exe)
    participant Target as Internal Target Host (10.0.0.10:445)

    App->>S5: \x05\x01\x00 (SOCKS5 Greeting: No Auth)
    S5-->>App: \x05\x00 (Accept No Auth)
    App->>S5: \x05\x01\x00\x01\x0a\x00\x00\x0a\x01\xbd (CONNECT 10.0.0.10:445)
    S5->>PS: In-Memory System.Net.Sockets.TcpClient Routine
    PS->>Target: TCP SYN Handshake
    Target-->>PS: TCP SYN-ACK (Connected)
    PS-->>S5: Socket Connection ACK
    S5-->>App: \x05\x00\x00\x01\x00\x00\x00\x00\x00\x00 (Success)
    loop Bidirectional Streaming Loop
        App->>S5: Inbound SMB Client Data Bytes
        S5->>PS: Transmit chunk over PSRP stream
        PS->>Target: Forward raw bytes into internal socket
        Target-->>PS: Outbound SMB Server Response
        PS-->>S5: Base64 chunk over PSRP
        S5-->>App: Inbound TCP Socket Stream
    end
```

### 3.1 RFC 1928 State Machine Breakdown:
1. **Method Selection**:
   - Client sends: `\x05` (Version), `NMETHODS`, `[METHODS...]`.
   - Server returns: `\x05\x00` (`NO_AUTHENTICATION_REQUIRED`).
2. **Connection Request Evaluation**:
   - Client sends: `\x05` (VER), `\x01` (`CONNECT`), `\x00` (RSV), `ATYP` (`0x01` IPv4, `0x03` Domain, `0x04` IPv6), `[DST.ADDR]`, `[DST.PORT]` (2 bytes Big-Endian).
   - If unsupported command (`BIND` `0x02` or `UDP ASSOCIATE` `0x03`): returns `\x05\x07` (`COMMAND_NOT_SUPPORTED`) and terminates socket.
3. **Data Streaming & Thread Safety**:
   - Implements non-blocking `select.select()` polling with **32,768 byte (32 KB)** chunk buffers.
   - All connection tracking and socket descriptors are guarded by `threading.Lock()` to prevent race conditions during concurrent multi-session switching.
   - Includes timeout guards preventing orphaned socket retention on abrupt client disconnects.

---

## 4. Multi-Session Graph Orchestration (`pwnrm.core.session_mgr`)

The `SessionManager` tracks and coordinates multiple concurrent PSRP sessions across enterprise domains:

```python
class SessionNode:
    session_id: int          # Unique integer identifier (0, 1, 2...)
    name: str                # Human-readable alias (e.g. "dc01-primary")
    runspace: Runspace       # Stateful MS-PSRP Runspace instance
    transport: Transport     # Underlying SPNEGO/Kerberos/Cert transport
    target_info: dict        # {"host": "...", "user": "...", "domain": "..."}
    created_at: datetime     # Timestamp of session initialization
    last_active: datetime    # Timestamp of most recent command execution
    is_alive: bool           # Real-time health status flag
```

### 4.1 Topology & Graph Operations:
- **`!session list`**: Renders formatted ASCII session table with active pointer (`[*]`), target IP, transport mode, and latency.
- **`!session switch <ID>`**: Updates active console context and recalculates remote working directory (`cwd`).
- **`!session exec-all <CMD>`**: Fan-out command execution across all active nodes using a worker thread pool, tagging and isolating stdout/stderr per host (`[S:X | Host]`).
- **`!session save`**: Atomically serializes active topology to `~/.pwnrm/sessions/sessions.json` encrypted with in-memory ephemeral Fernet keys.

---

## 5. Structured & Hardened Loot Pipeline (`pwnrm.core.loot`)

All harvested credentials, tickets, certificates, and dumps are automatically cataloged per target host:

```text
~/.pwnrm/loot/dc01.corp.local/
├── MANIFEST.json          # Index of all collected artifacts with SHA-256 hashes
├── credentials.json       # Array of {"type", "account", "secret", "source", "timestamp"}
├── tickets/               # Kerberos ccache / kirbi ticket blobs
├── certs/                 # ADCS user/machine .pfx and .pem certificates
├── dpapi/                 # DPAPI master keys and encrypted blobs
├── bloodhound/            # In-memory BloodHound CE JSON datasets
└── dumps/                 # LSASS snapshots & memory dumps
```

### 5.1 Permission Hardening & NTFS ACL Stripping:
- **POSIX (Linux/macOS)**: Enforces `0o700` (`S_IRWXU`) on all directories and `0o600` on files.
- **Windows (NTFS)**: Standard `os.mkdir()` inherits permissions from parent folders, allowing other non-admin users on shared jump boxes to read harvested credentials. PwnRM invokes `icacls` with `creationflags=0x08000000` (`CREATE_NO_WINDOW`):
  ```powershell
  icacls "<loot_dir>" /inheritance:r /grant "%USERNAME%:(OI)(CI)F"
  ```

---

## 6. OPSEC Profile & Polymorphic Traffic Shaper (`pwnrm.core.opsec`)

Controls timing jitter, User-Agent header rotation, AST cmdlet obfuscation, and command chunking:

| Profile Mode | Minimum Sleep | Maximum Sleep | Command Obfuscation | Chunk Size |
|---|---|---|---|---|
| **`stealth`** | 1.5 s | 5.0 s | Active (AST Cmdlet Backticks) | 16 KB |
| **`balanced`** | 0.1 s | 0.5 s | Inactive | 64 KB |
| **`aggressive`** | 0.0 s | 0.0 s | Inactive | 128 KB |
| **`hybrid-cloud`** | 0.5 s | 2.0 s | Active (Browser Header Masquerade + AST) | 32 KB |

- **`jitter_sleep()`**: Samples a cryptographic random float using `secrets.randbelow()` between PSRP execution turns to defeat statistical network anomaly detection.
- **`obfuscate_cmd()`**: Dynamically splits PowerShell cmdlet names with backticks (`` ` ``) and normalizes whitespace while preserving variable names and parameters.
