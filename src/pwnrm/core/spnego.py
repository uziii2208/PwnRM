"""
core.spnego — SPNEGO / Kerberos GSSAPI proxies
"""

from struct    import pack, unpack
from random    import randbytes
from datetime  import datetime, UTC

from pyasn1.codec.ber import encoder, decoder
from pyasn1.type.univ import noValue

from impacket.ntlm import (
    getNTLMSSPType1, getNTLMSSPType3,
    SEALKEY, SIGNKEY, SEAL, SIGN,
    NTLMAuthNegotiate, NTLMAuthChallenge, NTLMAuthChallengeResponse,
    AV_PAIRS, NTLMSSP_AV_CHANNEL_BINDINGS,
)
from impacket.krb5.asn1      import (AP_REQ, AP_REP, Authenticator, EncAPRepPart, seq_set)
from impacket.krb5.types     import Principal, KerberosTime, Ticket
from impacket.krb5.crypto    import Key, _enctype_table
from impacket.krb5.constants import (PrincipalNameType, ApplicationTagNumbers, encodeFlags)
from impacket.krb5.gssapi    import (
    GSSAPI, KRB5_AP_REQ, CheckSumField,
    GSS_C_MUTUAL_FLAG, GSS_C_REPLAY_FLAG,
    GSS_C_SEQUENCE_FLAG, GSS_C_CONF_FLAG,
    GSS_C_INTEG_FLAG, KG_USAGE_INITIATOR_SEAL,
    KG_USAGE_ACCEPTOR_SEAL,
)
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech

from Cryptodome.Hash   import HMAC, MD5
from Cryptodome.Cipher import ARC4

from .credentials import SPNEGOError
from .utils       import krb5_mech_indep_token_decode


class SPNEGOProxyNTLM:
    def __init__(self, creds, gss_bindings=None):
        self.creds        = creds
        self.gss_bindings = gss_bindings
        self.complete     = False

    def step(self, data_in=None):
        if data_in is None:
            self._type1 = getNTLMSSPType1()
            self._type1["flags"] = 0xe0088237
            init = SPNEGO_NegTokenInit()
            init["MechTypes"] = [TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]]
            init["MechToken"] = self._type1.getData()
            return init.getData()
        try:
            targ      = SPNEGO_NegTokenResp(data_in)
            neg_state = targ["NegState"][0]
        except:
            raise SPNEGOError("SPNEGO: bad response")
        if neg_state == 0:
            self.complete = True
        elif neg_state == 1:
            type2 = targ["ResponseToken"]
            if self.gss_bindings:
                chal  = NTLMAuthChallenge(type2)
                info  = AV_PAIRS(chal["TargetInfoFields"])
                info[NTLMSSP_AV_CHANNEL_BINDINGS] = self.gss_bindings
                chal["TargetInfoFields"]          = info.getData()
                chal["TargetInfoFields_len"]      = len(info.getData())
                chal["TargetInfoFields_max_len"]  = len(info.getData())
                type2 = chal.getData()
            nt_hash = bytes.fromhex(self.creds.nt_hash) if self.creds.nt_hash else ""
            type3, key = getNTLMSSPType3(self._type1, type2,
                                         self.creds.username, self.creds.password,
                                         "", "", nt_hash)
            resp = SPNEGO_NegTokenResp()
            resp["NegState"]     = b"\x01"
            resp["SupportedMech"]= b""
            resp["ResponseToken"]= type3.getData()
            self.seq_cli  = 0; self.seq_srv = 0
            self.key_cli  = SIGNKEY(type3["flags"], key, "Client")
            self.key_srv  = SIGNKEY(type3["flags"], key, "Server")
            self.rc4_cli  = ARC4.new(SEALKEY(type3["flags"], key, "Client"))
            self.rc4_srv  = ARC4.new(SEALKEY(type3["flags"], key, "Server"))
            return resp.getData()
        elif neg_state == 2:
            raise SPNEGOError("NTLM rejected")
        else:
            raise NotImplementedError("request-mic")

    def wrap(self, req, joined=False):
        seq = pack("<I", self.seq_cli)
        enc = self.rc4_cli.encrypt(req)
        sig = HMAC.new(self.key_cli, seq + req, digestmod=MD5).digest()[:8]
        sig = pack("<I", 1) + self.rc4_cli.encrypt(sig) + seq
        self.seq_cli += 1
        return (sig + enc) if joined else (sig, enc)

    def unwrap(self, sig, enc):
        plaintext = self.rc4_srv.decrypt(enc)
        seq       = pack("<I", self.seq_srv)
        sig_test  = HMAC.new(self.key_srv, seq + plaintext, digestmod=MD5).digest()[:8]
        sig_test  = self.rc4_srv.decrypt(sig_test)
        if sig[4:12] != sig_test:
            raise SPNEGOError("unwrap(): message integrity failure")
        self.seq_srv += 1
        return plaintext


class SPNEGOProxyKerberos:
    def __init__(self, creds, gss_bindings=None):
        self.creds        = creds
        self.gss_bindings = gss_bindings
        self.complete     = False

    def step(self, data_in=None):
        if data_in is None:
            user   = Principal(self.creds.username,
                               type=PrincipalNameType.NT_PRINCIPAL.value)
            cipher = _enctype_table[self.creds.tgskey.enctype]
            cksum  = CheckSumField()
            cksum["Lgth"]  = 16
            cksum["Flags"] = (GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG |
                              GSS_C_SEQUENCE_FLAG | GSS_C_MUTUAL_FLAG)
            if self.gss_bindings:
                cksum["Bnd"] = self.gss_bindings
            now  = datetime.now(UTC)
            auth = Authenticator()
            seq_set(auth, "cname", user.components_to_asn1)
            auth["authenticator-vno"] = 5
            auth["crealm"]            = self.creds.domain.upper()
            auth["cusec"]             = now.microsecond
            auth["ctime"]             = KerberosTime.to_asn1(now)
            auth["cksum"]             = noValue
            auth["cksum"]["cksumtype"]= 0x8003
            auth["cksum"]["checksum"] = cksum.getData()
            auth["seq-number"]        = 0
            auth["subkey"]            = noValue
            auth["subkey"]["keyvalue"]= randbytes(32)
            auth["subkey"]["keytype"] = 18   # AES256
            enc_auth = cipher.encrypt(self.creds.tgskey, 11, encoder.encode(auth), None)
            ap_req                        = AP_REQ()
            ap_req["pvno"]                = 5
            ap_req["msg-type"]            = int(ApplicationTagNumbers.AP_REQ.value)
            ap_req["ap-options"]          = encodeFlags([2])
            ap_req["authenticator"]       = noValue
            ap_req["authenticator"]["etype"]  = cipher.enctype
            ap_req["authenticator"]["cipher"] = enc_auth
            seq_set(ap_req, "ticket", self.creds.ticket.to_asn1)
            init               = SPNEGO_NegTokenInit()
            init["MechTypes"]  = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]
            init["MechToken"]  = encoder.encode(ap_req)
            return init.getData()
        try:
            targ      = SPNEGO_NegTokenResp(data_in)
            neg_state = targ["NegState"][0]
        except:
            raise SPNEGOError("Kerberos: unexpected response")
        if neg_state == 0:
            blob    = krb5_mech_indep_token_decode(targ["ResponseToken"])[1]
            ap_rep  = decoder.decode(blob[2:], asn1Spec=AP_REP())[0]
            cipher  = _enctype_table[self.creds.tgskey.enctype]
            rep_enc = cipher.decrypt(self.creds.tgskey, 12, ap_rep["enc-part"]["cipher"])
            rep_dec = decoder.decode(rep_enc, asn1Spec=EncAPRepPart())[0]
            keydata = rep_dec["subkey"]["keyvalue"].asOctets()
            keytype = rep_dec["subkey"]["keytype"]
            self.subkey  = Key(keytype, keydata)
            self.cipher  = _enctype_table[keytype]
            self.seq_cli = 0
            self.seq_srv = int(rep_dec["seq-number"])
            self.complete = True
        elif neg_state == 2:
            raise SPNEGOError("Kerberos: rejected")
        else:
            raise SPNEGOError("Kerberos: unexpected state")

    def wrap(self, req, joined=False):
        sig = pack(">BBBBHHQ", 5, 4, 6, 0xff, 0, 0, self.seq_cli)
        enc = self.cipher.encrypt(self.subkey, KG_USAGE_INITIATOR_SEAL, req + sig, None)
        rot = len(enc) - (28 % len(enc))
        enc = enc[rot:] + enc[:rot]
        sig = pack(">BBBBHHQ", 5, 4, 6, 0xff, 0, 28, self.seq_cli)
        self.seq_cli += 1
        return sig + enc if joined else (sig + enc[:44], enc[44:])

    def unwrap(self, sig, enc):
        _, _, _, _, ec, rrc, seq_srv = unpack(">BBBBHHQ", sig[:16])
        if seq_srv != self.seq_srv:
            raise SPNEGOError("Kerberos: replay detected")
        self.seq_srv += 1
        enc = sig[16:] + enc
        rot = (rrc + ec) % len(enc)
        enc = enc[rot:] + enc[:rot]
        return self.cipher.decrypt(self.subkey, KG_USAGE_ACCEPTOR_SEAL, enc)[:-(ec + 16)]