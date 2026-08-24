"""
mock_winrm_server.py — Minimal WinRM/WSMan mock for PwnRM regression testing.

Simulates enough of the WinRM/MS-PSRP wire protocol for PwnRM to complete
a full session: SPNEGO auth handshake → WSMan Create → RunspacePool open →
PowerShell invoke → output stream → close.

Credentials: testuser / testpass  (NTLM, no domain)
Endpoint:    http://0.0.0.0:5985/wsman

Usage:
    python mock_winrm_server.py          # starts on :5985
    python mock_winrm_server.py 5986     # custom port

What this tests:
    - PwnRM connects, authenticates, opens a runspace, and runs a command
      without hitting TooManyRedirects or any other regression from the fix.
    - No redirect responses are issued — this is a clean compliant server.
    - Captures every request and prints it so you can confirm pypsrp's
      internal session is talking to THIS server and not being redirected.

Limitations:
    - NTLM handshake is faked (accepts any credential after the three-way
      exchange). Real Kerberos / CredSSP / ClientCert are not implemented.
    - PowerShell output is hardcoded — every command returns the same payload.
    - Sufficient for regression testing the redirect-fix and normal pipeline.
      Not a substitute for a real WinRM target.
"""

import base64
import hashlib
import http.server
import re
import sys
import textwrap
import threading
import uuid
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────
PORT        = int(sys.argv[1]) if len(sys.argv) > 1 else 5985
VALID_USER  = "testuser"
VALID_PASS  = "testpass"
REALM       = "WORKGROUP"

# ── NTLM stub — three-way handshake, credential check skipped ────────────────
# Real NTLM requires crypto we don't want to depend on here.
# We accept any NTLM Type 3 message after issuing a Type 2 challenge.
# This is intentional: the goal is to test PwnRM's transport layer,
# not to validate credentials cryptographically.

# Pre-built NTLM Type 2 (Challenge) — well-formed per MS-NLMP §2.2.1.2
# TargetName="WORKGROUP" UTF-16LE, AvPairs: MsvAvNbDomainName + MsvAvEOL
# Flags=0x628A8215, ServerChallenge=0102030405060708, Version=Win10
import struct as _struct

def _build_ntlm_type2():
    """Well-formed NTLM Type 2 (Challenge) per MS-NLMP §2.2.1.2."""
    TARGET_NAME = "WORKGROUP".encode("utf-16-le")
    tlen        = len(TARGET_NAME)
    HDR         = 56
    av          = (_struct.pack("<HH", 2, tlen) + TARGET_NAME
                   + _struct.pack("<HH", 0, 0))
    alen        = len(av)
    return (
        b"NTLMSSP\x00"
        + _struct.pack("<I", 2)
        + _struct.pack("<HHI", tlen, tlen, HDR)
        + _struct.pack("<I", 0x628A8215)
        + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        + b"\x00" * 8
        + _struct.pack("<HHI", alen, alen, HDR + tlen)
        + b"\x0a\x00\x3b\x00\x00\x00\x00\x0f"
        + TARGET_NAME + av
    )

def _build_spnego_challenge():
    """Build SPNEGO NegTokenResp by hand-rolling DER/ASN.1 precisely.

    impacket's SPNEGO_NegTokenResp omits ResponseToken unless the internal
    pyasn1 structure is populated via the correct component path — which
    differs between impacket versions. Building the DER directly is more
    portable and avoids version-dependent field-assignment quirks.

    Structure (RFC 4178 §4.2.2):
      [1] NegTokenResp ::= SEQUENCE {
        negState     [0] ENUMERATED { accept-incomplete(1) }
        responseToken [2] OCTET STRING <NTLM Type 2>
      }
    """
    def _len(n):
        if n < 0x80: return bytes([n])
        if n < 0x100: return bytes([0x81, n])
        return bytes([0x82, (n >> 8) & 0xff, n & 0xff])
    def _tlv(tag, v): return bytes([tag]) + _len(len(v)) + v

    ntlm = _build_ntlm_type2()

    # negState [0] EXPLICIT { ENUMERATED accept-incomplete(1) }
    neg_state      = _tlv(0xa0, _tlv(0x0a, bytes([1])))
    # responseToken [2] EXPLICIT { OCTET STRING }
    response_token = _tlv(0xa2, _tlv(0x04, ntlm))
    # SEQUENCE { negState, responseToken }
    seq            = _tlv(0x30, neg_state + response_token)
    # [1] EXPLICIT (NegTokenResp choice tag)
    token          = _tlv(0xa1, seq)

    return base64.b64encode(token).decode()

NTLM_CHALLENGE = _build_spnego_challenge()

# ── WSMan envelope helpers ────────────────────────────────────────────────────

NS = {
    "s":   "http://www.w3.org/2003/05/soap-envelope",
    "a":   "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "w":   "http://schemas.dmtf.org/wbem/wsman/1/wsman.dtd",
    "p":   "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd",
    "rsp": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell",
    "f":   "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault",
}

def _envelope(action_uri: str, relates_to: str, body: str) -> bytes:
    msg_id = str(uuid.uuid4()).upper()
    return textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <s:Envelope
            xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.dtd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
            xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
          <s:Header>
            <a:Action>{action_uri}</a:Action>
            <a:MessageID>uuid:{msg_id}</a:MessageID>
            <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
            <a:RelatesTo>uuid:{relates_to}</a:RelatesTo>
          </s:Header>
          <s:Body>
            {body}
          </s:Body>
        </s:Envelope>
    """).encode()

def _extract_message_id(xml: bytes) -> str:
    m = re.search(rb"<a:MessageID>uuid:([^<]+)</a:MessageID>", xml, re.I)
    return m.group(1).decode() if m else str(uuid.uuid4())

def _extract_action(xml: bytes) -> str:
    m = re.search(rb"<a:Action[^>]*>([^<]+)</a:Action>", xml, re.I)
    return m.group(1).decode().strip() if m else ""

# ── PSRP pipeline output — hardcoded response ────────────────────────────────
# Every PowerShell command returns this output. Enough to verify the pipeline.

def _psrp_output_b64() -> str:
    """
    Minimal PSRP pipeline output blob (base64).
    Encodes a single StreamData message with text "mock-output\n".
    pypsrp will decode this and yield it as ps.output[0].
    This is a stub — real PSRP uses a complex binary fragmentation protocol.
    We return enough for pypsrp to parse without error.
    """
    # PSRP RunspacePool state = Opened (2), serialized as a minimal pipeline
    # output message. pypsrp parses the base64 body of <rsp:Stream> elements.
    # For a smoke-test we return a valid-enough blob that pypsrp treats as
    # pipeline output without crashing. The exact bytes are a pre-encoded
    # PSRP StreamData message containing "mock-output\r\n".
    raw = (
        b"\x00\x00\x00\x00"          # fragment header: object_id=0
        + b"\x00\x00\x00\x00"        # fragment_id=0
        + b"\x03"                     # flags: start+end
        + b"\x00\x00\x00\x1a"        # blob_length=26
        + b"\x04\x00\x01\x00"        # PSRP message type: PIPELINE_OUTPUT
        + b"\x00" * 8                 # destination + message_type padding
        + b"mock-output\r\n"
    )
    return base64.b64encode(raw).decode()

# ── Auth state (per connection, keyed by client address) ─────────────────────

_auth_state: dict[str, str] = {}   # addr → "none" | "challenged" | "ok"
_state_lock = threading.Lock()

def _get_auth(addr) -> str:
    with _state_lock:
        return _auth_state.get(addr, "none")

def _set_auth(addr, state):
    with _state_lock:
        _auth_state[addr] = state

# ── Request handler ───────────────────────────────────────────────────────────

class WinRMHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"[{ts}] {self.address_string()} {fmt % args}")

    # ── POST /wsman ──────────────────────────────────────────────────────────

    def do_POST(self):
        length  = int(self.headers.get("Content-Length", 0))
        body    = self.rfile.read(length)
        auth_hdr = self.headers.get("Authorization", "")
        addr    = self.client_address[0]

        print(f"\n{'─'*60}")
        print(f"  ← {self.command} {self.path}")
        print(f"  Authorization: {auth_hdr[:80]}{'…' if len(auth_hdr)>80 else ''}")

        # ── NTLM three-way handshake ──────────────────────────────────────
        if auth_hdr.startswith("Negotiate ") or auth_hdr.startswith("NTLM "):
            scheme, token_b64 = auth_hdr.split(" ", 1)
            token = base64.b64decode(token_b64.strip() + "==")

            # NTLM tokens may be raw or SPNEGO/ASN.1-wrapped (Linux impacket).
            # Scan for the NTLMSSP signature anywhere in the blob instead of
            # relying on a fixed byte offset.
            sig_pos = token.find(b"NTLMSSP\x00")

            if sig_pos == -1:
                # No NTLMSSP signature — bare SPNEGO NegTokenInit or unknown.
                # Issue challenge and let client send a proper NTLM token next.
                print("  [NTLM] No NTLMSSP sig — issuing challenge")
                _set_auth(addr, "challenged")
                self._send_401(f"Negotiate {NTLM_CHALLENGE}")
                return

            msg_type = token[sig_pos + 8 : sig_pos + 12]

            if msg_type == b"\x01\x00\x00\x00":          # Type 1 — Negotiate
                print("  [NTLM] Type 1 received — issuing Type 2 challenge")
                _set_auth(addr, "challenged")
                self._send_401(f"Negotiate {NTLM_CHALLENGE}")
                return

            elif msg_type == b"\x03\x00\x00\x00":        # Type 3 — Authenticate
                print("  [NTLM] Type 3 received — auth accepted (stub)")
                _set_auth(addr, "ok")
                # Fall through to dispatch the WSMan request below.

            else:
                print(f"  [NTLM] Unknown message type {msg_type.hex()} — rejecting")
                self._send_401(f"Negotiate {NTLM_CHALLENGE}")
                return

        elif _get_auth(addr) != "ok":
            # No auth header and not already authenticated.
            print("  [AUTH] No credentials — issuing 401")
            self._send_401(f"Negotiate {NTLM_CHALLENGE}")
            return

        # ── Authenticated — dispatch WSMan action ─────────────────────────
        action    = _extract_action(body)
        msg_id    = _extract_message_id(body)
        shell_id  = str(uuid.uuid4()).upper()
        cmd_id    = str(uuid.uuid4()).upper()

        print(f"  [WSMan] Action: {action.split('/')[-1]}")

        resp_body = self._dispatch(action, shell_id, cmd_id, body)
        if resp_body is None:
            # Unknown action — return a generic fault
            resp_body = self._fault(msg_id, action)
        else:
            resp_body = _envelope(action + "Response", msg_id, resp_body)

        self.send_response(200)
        self.send_header("Content-Type", "application/soap+xml;charset=UTF-8")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)
        print(f"  → 200 ({len(resp_body)} bytes)")

    # ── WSMan action dispatcher ───────────────────────────────────────────

    def _dispatch(self, action: str, shell_id: str, cmd_id: str, body: bytes):
        a = action.split("/")[-1].lower()

        if a == "create":
            # RunspacePool / Shell Create
            return f"""
                <w:ResourceCreated>
                  <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
                  <a:ReferenceParameters>
                    <w:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
                    <w:SelectorSet>
                      <w:Selector Name="ShellId">{shell_id}</w:Selector>
                    </w:SelectorSet>
                  </a:ReferenceParameters>
                </w:ResourceCreated>
            """

        if a == "command":
            return f"""
                <rsp:CommandResponse>
                  <rsp:CommandId>{cmd_id}</rsp:CommandId>
                </rsp:CommandResponse>
            """

        if a == "send":
            # PSRP Send — client pushes pipeline input; we ACK
            return "<rsp:SendResponse/>"

        if a == "receive":
            # Return hardcoded pipeline output then signal Done
            out_b64  = _psrp_output_b64()
            return f"""
                <rsp:ReceiveResponse>
                  <rsp:Stream Name="stdout" CommandId="{cmd_id}">{out_b64}</rsp:Stream>
                  <rsp:CommandState CommandId="{cmd_id}"
                      State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                    <rsp:ExitCode>0</rsp:ExitCode>
                  </rsp:CommandState>
                </rsp:ReceiveResponse>
            """

        if a == "delete":
            return "<w:DeleteResponse/>"

        return None   # unknown action → caller sends fault

    def _fault(self, msg_id: str, action: str) -> bytes:
        body = f"""
            <s:Fault>
              <s:Code><s:Value>s:Sender</s:Value></s:Code>
              <s:Reason><s:Text xml:lang="en-US">Unknown action: {action}</s:Text></s:Reason>
            </s:Fault>
        """
        return _envelope(
            "http://schemas.xmlsoap.org/ws/2004/08/addressing/fault",
            msg_id, body
        )

    def _send_401(self, www_auth: str):
        msg = b"Unauthorized"
        self.send_response(401)
        self.send_header("WWW-Authenticate", www_auth)
        self.send_header("Content-Type",     "text/plain")
        self.send_header("Content-Length",   str(len(msg)))
        self.end_headers()
        self.wfile.write(msg)
        print(f"  → 401 WWW-Authenticate: {www_auth[:60]}")

    def do_GET(self):
        # Health check endpoint — curl http://127.0.0.1:5985/health
        if self.path == "/health":
            msg = b"mock WinRM OK"
            self.send_response(200)
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
        else:
            self.send_response(404)
            self.end_headers()

# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), WinRMHandler)
    print(f"Mock WinRM server listening on http://0.0.0.0:{PORT}/wsman")
    print(f"Credentials : {VALID_USER} / {VALID_PASS}  (NTLM stub — accepts any Type 3)")
    print(f"Health check: curl http://127.0.0.1:{PORT}/health")
    print(f"Connect with: pwnrm http://127.0.0.1:{PORT} -u {VALID_USER} -p {VALID_PASS}")
    print("─" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()
