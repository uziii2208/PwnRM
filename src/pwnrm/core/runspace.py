"""
core.runspace — MS-PSRP Runspace (command execution layer)
"""

import uuid, logging
from base64 import b64decode
from struct import pack, unpack
import defusedxml.ElementTree as ET
import xml.etree.ElementTree as _ET_std  # used only for tostring() / building outbound XML

from .utils import utfstr, b64str, strip_ansi

from .psrp  import (
    soap_req, soap_ns, xml_get_text, xml_get_attrib,
    ps_capability, ps_runspace_pool, ps_create_pipeline, ps_command,
    SESSION_CAPABILITY, INIT_RUNSPACEPOOL, CREATE_PIPELINE,
    PIPELINE_OUTPUT, ERROR_RECORD, WARNING_RECORD, VERBOSE_RECORD,
    INFORMATION_RECORD, PIPELINE_STATE, PROGRESS_RECORD,
)


class Runspace:
    def __init__(self, transport, timeout=30):
        self.transport      = transport
        self.timeout        = timeout
        self.fragment_buffer= {}
        self.next_object_id = 1
        self.session_id     = str(uuid.uuid4()).upper()
        self.runspace_id    = str(uuid.uuid4()).upper()
        self.pipeline_id    = str(uuid.uuid4()).upper()
        self.shell_id       = None
        self.command_id     = None

    def __enter__(self):
        req     = soap_req("create", self.session_id, timeout=10)
        options = req.find("s:Header").find("wsman:OptionSet")
        ET.SubElement(options, "wsman:Option",
                      {"Name":"protocolversion","MustComply":"true"}).text = "2.1"
        shell = ET.SubElement(req.find("s:Body"), "rsp:Shell")
        ET.SubElement(shell, "rsp:ShellId").text    = "http://localhost/wsman"
        ET.SubElement(shell, "rsp:InputStreams").text = "stdin"
        ET.SubElement(shell, "rsp:OutputStreams").text= "stdout"
        ET.SubElement(shell, "creationXml").text = b64str(self._fragment([
            (SESSION_CAPABILITY, ps_capability),
            (INIT_RUNSPACEPOOL,  ps_runspace_pool),
        ]))
        rsp = self._post(req)
        if "fault" in rsp:
            raise RuntimeError(rsp["reason"])
        self.shell_id = rsp.get("shell_id")
        self._receive(); self._receive()
        return self

    def __exit__(self, *_):
        try:
            req = soap_req("delete", self.session_id, self.shell_id, self.timeout)
            self._post(req)
        except Exception:
            pass

    def run_command(self, cmd):
        self.command_id = self._create_pipeline(cmd)
        if not self.command_id:
            yield {"error": "Pipeline creation failed — restart the shell if this persists"}
            return
        timeouts = 0
        while True:
            rsp = self._receive(self.command_id)
            if "fault" in rsp:
                if rsp["subcode"] == "w:TimedOut":
                    timeouts += 1
                    yield {"timeout": timeouts}
                    continue
                yield {"error": rsp["reason"] + "\n" + rsp["detail"]}
                return
            timeouts = 0
            for msg_type, msg in self._defragment(rsp["streams"]):
                if msg_type == PIPELINE_OUTPUT:
                    if msg.tag == "S":
                        yield {"stdout": strip_ansi(utfstr(msg.text) or "")}
                elif msg_type == ERROR_RECORD:
                    yield {"error": strip_ansi(xml_get_text(msg, ".//ToString", "unknown error"))}
                elif msg_type == WARNING_RECORD:
                    yield {"warn": strip_ansi(xml_get_text(msg, ".//ToString", "unknown warning"))}
                elif msg_type == VERBOSE_RECORD:
                    yield {"verbose": strip_ansi(xml_get_text(msg, ".//ToString", ""))}
                elif msg_type == INFORMATION_RECORD:
                    info  = strip_ansi(xml_get_text(msg, ".//Props/S[@N='Message']", ""))
                    endl  = xml_get_text(msg, ".//Props/B[@N='NoNewLine']", "false") == "false"
                    yield {"info": info, "endl": "\n" if endl else ""}
                elif msg_type == PIPELINE_STATE:
                    # [BUG-10 FIX] Safely parse PIPELINE_STATE to avoid TypeError/ValueError on malformed responses
                    state_txt = xml_get_text(msg, ".//I32[@N='PipelineState']")
                    try:
                        state = int(state_txt) if state_txt is not None else 0
                    except ValueError:
                        state = 0
                    if state in (3, 5, 6):
                        yield {"error": strip_ansi(xml_get_text(msg, ".//ToString", ""))}
                elif msg_type == PROGRESS_RECORD:
                    status   = strip_ansi(xml_get_text(msg, ".//S[@N='StatusDescription']", ""))
                    activity = strip_ansi(xml_get_text(msg, ".//S[@N='Activity']", ""))
                    yield {"progress": status or activity}
            if rsp["state"].endswith(("CommandState/Done", "CommandState/Terminated", "CommandState/Failed")):
                break
        self.command_id = None

    def interrupt(self):
        if self.command_id:
            req = soap_req("signal", self.session_id, self.shell_id, self.timeout)
            sig = ET.SubElement(req.find("s:Body"), "rsp:Signal",
                                {"CommandId": self.command_id})
            ET.SubElement(sig, "rsp:Code").text = "powershell/signal/crtl_c"
            return self._post(req)

    def _post(self, req):
        # tostring() builds outbound XML — use stdlib ET (safe, we control the data)
        # fromstring() parses inbound server XML — ET is aliased to defusedxml (XXE-safe)
        rsp    = ET.fromstring(self.transport.send(_ET_std.tostring(req, encoding="utf8")))

        # Check for SOAP fault directly or via Action header
        action_el = rsp.find("./s:Header/wsa:Action", soap_ns)
        action    = action_el.text if (action_el is not None and action_el.text) else ""
        if action.endswith("wsman/fault") or rsp.find(".//s:Fault", soap_ns) is not None:
            return {
                "fault":   "ok",
                "subcode": xml_get_text(rsp, ".//s:Subcode/s:Value", ""),
                "reason":  xml_get_text(rsp, ".//s:Reason/s:Text", ""),
                "detail":  xml_get_text(rsp, ".//s:Detail/s:Message", ""),
            }
        elif action.endswith("shell/ReceiveResponse"):
            # [BUG-08 FIX] Guard against empty <rsp:Stream/> elements where s.text is None
            return {
                "receive": "ok",
                "streams": [b64decode(s.text or "") for s in rsp.findall(".//rsp:Stream", soap_ns)],
                "state":   xml_get_attrib(rsp, ".//rsp:CommandState", "State", ""),
            }
        elif action.endswith("transfer/CreateResponse"):
            return {"create":"ok", "shell_id": xml_get_text(rsp,".//rsp:Shell/rsp:ShellId","")}
        elif action.endswith("shell/CommandResponse"):
            return {"command":"ok","command_id": xml_get_text(rsp,".//rsp:CommandId","")}
        elif action.endswith("shell/SignalResponse"):
            return {"signal":"ok"}
        elif action.endswith("transfer/DeleteResponse"):
            return {"delete":"ok"}
        else:
            logging.debug(ET.tostring(rsp))
            raise NotImplementedError(action)

    def _receive(self, command_id=None):
        req = soap_req("receive", self.session_id, self.shell_id, self.timeout)
        options = req.find("s:Header").find("wsman:OptionSet")
        ET.SubElement(options, "wsman:Option",
                      {"Name":"WSMAN_CMDSHELL_OPTION_KEEPALIVE"}).text = "true"
        recv = ET.SubElement(req.find("s:Body"), "rsp:Receive")
        attr = {"CommandId": command_id} if command_id else {}
        ET.SubElement(recv, "rsp:DesiredStream", attr).text = "stdout"
        return self._post(req)

    def _create_pipeline(self, cmd, is_script=False):
        pipeline = ps_create_pipeline([
            ps_command("Invoke-Expression", {"Command": cmd}),
            ps_command("Out-String",        {"Stream":  None}),
        ])
        req     = soap_req("command", self.session_id, self.shell_id, self.timeout)
        cmdline = ET.SubElement(req.find("s:Body"), "rsp:CommandLine")
        ET.SubElement(cmdline, "rsp:Command")
        ET.SubElement(cmdline, "rsp:Arguments").text = b64str(
            self._fragment([(CREATE_PIPELINE, pipeline)])
        )
        rsp = self._post(req)
        return rsp.get("command_id")

    # ── MS-PSRP fragmentation ────────────────────────────────────────────────
    def _fragment(self, messages):
        out = b""
        for msg_type, ps_obj in messages:
            obj_id = self.next_object_id
            self.next_object_id += 1
            xml    = ET.tostring(ps_obj, encoding="unicode").encode("utf-8")
            data   = (pack("<QQI", obj_id, 1, msg_type) +
                      self.runspace_id.replace("-","").encode() +
                      self.pipeline_id.replace("-","").encode() +
                      xml)
            out += pack(">BQI", 0b11, 0, len(data)) + data
        return out

    # ── MS-PSRP fragment buffer security limits ──────────────────────────────
    _MAX_FRAGMENT_KEYS  = 256             # max concurrent in-flight object IDs
    _MAX_FRAGMENT_BYTES = 32 * 1024 * 1024  # 32 MB total buffer cap

    def _defragment(self, streams):
        for data in streams:
            # [BUG-07 FIX] Require at least 65 bytes (13 byte header + 20 byte payload prefix + 32 byte UUIDs)
            # to prevent struct.error when slicing payload[:20] on short/malformed streams
            if len(data) < 65: continue
            flags, frag_id, length = unpack(">BQI", data[:13])
            payload  = data[13:]
            obj_id, runspace_id_raw, msg_type = unpack("<QQI", payload[:20])
            xml_data = payload[20 + 32:]
            buf = self.fragment_buffer

            # SECURITY CRIT-02: cap the number of concurrent in-flight object IDs
            if obj_id not in buf:
                if len(buf) >= self._MAX_FRAGMENT_KEYS:
                    logging.warning(
                        "_defragment: fragment_buffer key cap (%d) exceeded — "
                        "possible rogue server; discarding fragment",
                        self._MAX_FRAGMENT_KEYS,
                    )
                    continue
            if flags & 0b10:
                buf[obj_id] = b""
            buf.setdefault(obj_id, b"")
            buf[obj_id] += xml_data

            # SECURITY CRIT-02: cap total accumulated buffer size
            total_buffered = sum(len(v) for v in buf.values())
            if total_buffered > self._MAX_FRAGMENT_BYTES:
                logging.warning(
                    "_defragment: fragment buffer exceeded %d bytes — "
                    "possible rogue server; clearing buffer",
                    self._MAX_FRAGMENT_BYTES,
                )
                buf.clear()
                continue

            if flags & 0b01:
                # ET is aliased to defusedxml.ElementTree (see module imports)
                # which blocks XXE / entity expansion from server-controlled XML.
                try:
                    msg = ET.fromstring(buf.pop(obj_id).decode("utf-8", "replace"))
                    yield msg_type, msg
                except ET.ParseError as e:
                    logging.debug(f"XML parse error in fragment: {e}")