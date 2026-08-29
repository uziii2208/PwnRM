"""
core.psrp — MS-PSRP / SOAP-WSMan wire format builders
"""

import uuid
import xml.etree.ElementTree as ET

try:
    import defusedxml.ElementTree as _defusedET  # [FIX-06] Safe XML parsing with defusedxml
    # Monkey-patch or alias safe parser onto ET for defusedxml protection
    ET.fromstring = _defusedET.fromstring
    ET.parse = _defusedET.parse
except ImportError:
    pass

from typing import Optional, Dict, Any, List
from .utils import utfstr


# ── SOAP helpers ─────────────────────────────────────────────────────────────
soap_actions = {
    "create":  "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
    "delete":  "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete",
    "receive": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
    "command": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
    "signal":  "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal",
}

soap_ns = {
    "s":     "http://www.w3.org/2003/05/soap-envelope",
    "wsa":   "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "rsp":   "http://schemas.microsoft.com/wbem/wsman/1/windows/shell",
    "wsman": "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
    "wsmv":  "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd",
}

def xml_get_text(root, xpath: str, default: Optional[str] = None) -> Optional[str]:
    el = root.find(xpath, soap_ns)
    if el is None or el.text is None: return default
    return utfstr(el.text)

def xml_get_attrib(root, xpath: str, attrib: str, default: Optional[str] = None) -> Optional[str]:
    el = root.find(xpath, soap_ns)
    return (el.get(attrib) or default) if el is not None else default

def soap_req(action: str, session_id: str, shell_id: Optional[str] = None, timeout: int = 30,
             plugin: str = "Microsoft.PowerShell"):
    message_id     = str(uuid.uuid4()).upper()
    must_understand = lambda v=True: {"s:mustUnderstand": str(v).lower()}
    envelope = ET.Element("s:Envelope",
                          {f"xmlns:{ns}": uri for ns, uri in soap_ns.items()})
    header = ET.SubElement(envelope, "s:Header")
    body   = ET.SubElement(envelope, "s:Body")
    ET.SubElement(header, "wsman:ResourceURI",  must_understand()).text = \
        f"http://schemas.microsoft.com/powershell/{plugin}"
    ET.SubElement(ET.SubElement(header, "wsa:ReplyTo"),
                  "wsa:Address", must_understand()).text = \
        "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
    ET.SubElement(header, "wsa:To").text          = "http://localhost/wsman"
    ET.SubElement(header, "wsa:Action",   must_understand()).text = soap_actions[action]
    ET.SubElement(header, "wsa:MessageID").text   = f"uuid:{message_id}"
    ET.SubElement(header, "wsman:MaxEnvelopeSize", must_understand()).text = "153600"
    ET.SubElement(header, "wsman:Locale",  must_understand(False) | {"xml:lang": "en-US"})
    ET.SubElement(header, "wsman:OperationTimeout").text = f"PT{timeout}S"
    ET.SubElement(header, "wsman:OptionSet", must_understand())
    ET.SubElement(header, "wsmv:DataLocale", must_understand(False) | {"xml:lang": "en-US"})
    ET.SubElement(header, "wsmv:SessionId",  must_understand(False)).text = f"uuid:{session_id}"
    sel = ET.SubElement(header, "wsman:SelectorSet")
    if shell_id:
        ET.SubElement(sel, "wsman:Selector", {"Name": "ShellId"}).text = shell_id
    return envelope


# ── PSObject builders ────────────────────────────────────────────────────────
def ps_simple(name: Optional[str], kind: str, value: Any):
    attrs = {"N": name} if name else {}
    el = ET.Element(kind, attrs)
    if value is not None: el.text = str(value)
    return el

def ps_enum(name: Optional[str], value: int):
    attrs = {"N": name} if name else {}
    obj = ET.Element("Obj", attrs)
    ET.SubElement(obj, "I32").text = str(value)
    return obj

def ps_struct(name: Optional[str], elements: List[Any]):
    obj = ET.Element("Obj", ({"N": name} if name else {}))
    ET.SubElement(obj, "MS").extend(elements)
    return obj

def ps_list(name: Optional[str], elements: List[Any]):
    obj = ET.Element("Obj", {"N": name} if name else {})
    ET.SubElement(obj, "LST").extend(elements)
    return obj

ps_capability = ps_struct(None, [
    ps_simple("protocolversion",      "Version", "2.1"),
    ps_simple("PSVersion",            "Version", "2.0"),
    ps_simple("SerializationVersion", "Version", "1.1.0.10"),
])

ps_runspace_pool = ps_struct(None, [
    ps_simple("MinRunspaces",   "I32", 1),
    ps_simple("MaxRunspaces",   "I32", 1),
    ps_enum("PSThreadOptions", 0),
    ps_enum("ApartmentState",  2),
    ps_struct("HostInfo", [
        ps_simple("_isHostNull",        "B", "true"),
        ps_simple("_isHostUINull",      "B", "true"),
        ps_simple("_isHostRawUINull",   "B", "true"),
        ps_simple("_useRunspaceHost",   "B", "true"),
    ]),
    ps_simple("ApplicationArguments",  "Nil", None),
])

def ps_args(args: Dict[str, Any], raw: bool = False) -> List[Any]:
    return [
        ps_struct(None, [
            ps_simple("N", "S", k),
            ps_simple("V", "S" if v else "Nil", v) if not raw else v
        ]) for k, v in args.items()
    ]

def ps_command(cmd: str, args: Dict[str, Any]):
    return ps_struct(None, [
        ps_simple("Cmd",       "S",   cmd),
        ps_list(  "Args",           ps_args(args)),
        ps_simple("IsScript",  "B",    "false"),
        ps_simple("UseLocalScope", "Nil", None),
        ps_enum("MergeMyResult",      0),
        ps_enum("MergeToResult",      0),
        ps_enum("MergePreviousResults",0),
        ps_enum("MergeError",         0),
        ps_enum("MergeWarning",       0),
        ps_enum("MergeVerbose",       0),
        ps_enum("MergeDebug",         0),
        ps_enum("MergeInformation",   0),
    ])

def ps_create_pipeline(commands: List[Any]):
    return ps_struct(None, [
        ps_simple("NoInput",       "B",  "true"),
        ps_simple("AddToHistory",  "B",  "false"),   # ← evasion: no PS history
        ps_simple("IsNested",      "B",  "false"),
        ps_enum("ApartmentState", 2),
        ps_enum("RemoteStreamOptions", 15),
        ps_struct("HostInfo", [
            ps_simple("_isHostNull",       "B",  "true"),
            ps_simple("_isHostUINull",     "B",  "true"),
            ps_simple("_isHostRawUINull",  "B",  "true"),
            ps_simple("_useRunspaceHost",  "B",  "true"),
        ]),
        ps_struct("PowerShell", [
            ps_simple("IsNested",                     "B",    "false"),
            ps_simple("RedirectShellErrorOutputPipe", "B",    "false"),
            ps_simple("ExtraCmds",  "Nil", None),
            ps_simple("History",    "Nil", None),
            ps_list(  "Cmds",     commands),
        ]),
    ])


# ── Message IDs ──────────────────────────────────────────────────────────────
msg_ids = {
    0x00010002: "SESSION_CAPABILITY",
    0x00010004: "INIT_RUNSPACEPOOL",
    0x00010005: "PUBLIC_KEY",
    0x00010006: "ENCRYPTED_SESSION_KEY",
    0x00010007: "PUBLIC_KEY_REQUEST",
    0x00010008: "CONNECT_RUNSPACEPOOL",
    0x0002100B: "RUNSPACEPOOL_INIT_DATA",
    0x0002100C: "RESET_RUNSPACE_STATE",
    0x00021002: "SET_MAX_RUNSPACES",
    0x00021003: "SET_MIN_RUNSPACES",
    0x00021004: "RUNSPACE_AVAILABILITY",
    0x00021005: "RUNSPACEPOOL_STATE",
    0x00021006: "CREATE_PIPELINE",
    0x00021007: "GET_AVAILABLE_RUNSPACES",
    0x00021008: "USER_EVENT",
    0x00021009: "APPLICATION_PRIVATE_DATA",
    0x0002100A: "GET_COMMAND_METADATA",
    0x00021100: "RUNSPACEPOOL_HOST_CALL",
    0x00021101: "RUNSPACEPOOL_HOST_RESPONSE",
    0x00041002: "PIPELINE_INPUT",
    0x00041003: "END_OF_PIPELINE_INPUT",
    0x00041004: "PIPELINE_OUTPUT",
    0x00041005: "ERROR_RECORD",
    0x00041006: "PIPELINE_STATE",
    0x00041007: "DEBUG_RECORD",
    0x00041008: "VERBOSE_RECORD",
    0x00041009: "WARNING_RECORD",
    0x00041010: "PROGRESS_RECORD",
    0x00041011: "INFORMATION_RECORD",
    0x00041100: "PIPELINE_HOST_CALL",
    0x00041101: "PIPELINE_HOST_RESPONSE",
}

for k, v in msg_ids.items():
    globals()[v] = k