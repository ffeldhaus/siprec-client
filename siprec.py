#!/usr/env/ python3
# -*- coding: utf-8 -*-

"""
A Python command-line client for testing SIPREC (RFC 7865) servers using TLS,
including SRTP media streaming from a 2-channel audio file using SDES keys
parsed from the server's SDP answer. Uses 'pylibsrtp'.

(Manual multipart body construction, no email library for INVITE body)

This script:
1. Establishes a TLS connection to a SIPREC SRS.
2. Optionally sends OPTIONS pings.
3. Sends a SIP INVITE with SDP offer (including client crypto attributes).
4. Handles the SIP response (1xx, 2xx).
5. If INVITE succeeds (2xx), sends an ACK.
6. Parses the server's SDP answer (from 200 OK) to get destination RTP IP/ports
   and the SRTP SDES keys the server expects the client to use.
7. If an audio file is provided, starts two threads for SRTP streaming.
8. Waits for streaming to finish (file end or specified duration) or Ctrl+C.
9. **Attempts to send a SIP BYE request if the INVITE was successful.**
10. Closes the connection.

Requires: pylibsrtp, soundfile, numpy
  pip install pylibsrtp soundfile numpy

Requires client-side TLS certificates.

Packet Capture (Optional):
Uses tshark/editcap if --pcap-file is provided and tools are in PATH.
Allows specifying IP ranges/ports for SIP and Media traffic capture.
Requires SSLKEYLOGFILE environment variable for decryption injection.

Default Capture Filters (based on common Google Telephony integration):
- SIP Signaling: TCP traffic to/from 74.125.88.128/25 on port 5672.
- Media (RTP): UDP traffic to/from 74.125.39.0/24 (any UDP port).
These can be overridden using --capture-sip-range/--port and --capture-media-range.

Example Usage (Streaming with Default Capture and BYE):
  # Ensure audio.wav is a 2-channel, 8000 Hz WAV file for PCMA/PCMU
  export SSLKEYLOGFILE=/tmp/sslkeys.log # For Wireshark decryption
  python siprec_client_streamer_pylibsrtp.py \\
      rec-target@domain srs.domain.tld \\
      --src-number client@client.domain.tld \\
      --src-host 1.2.3.4 \\
      --cert-file client.crt \\
      --key-file client.key \\
      --ca-file ca.crt \\
      --audio-file /path/to/audio.wav \\
      --stream-duration 30 \\
      --pcap-file /tmp/siprec_capture.pcapng
"""

import argparse
import base64
import logging
import os
import random
import re
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections import namedtuple # Use standard collections for NamedTuple

# --- 3rd Party Libs ---
try:
    import numpy as np
except ImportError:
    print("Error: numpy library not found. Please install it: pip install numpy", file=sys.stderr)
    sys.exit(1)
try:
    import soundfile as sf
except ImportError:
    print("Error: soundfile library not found. Please install it: pip install soundfile", file=sys.stderr)
    print("Note: soundfile may require system dependencies like 'libsndfile'. Check its documentation.", file=sys.stderr)
    sys.exit(1)
try:
    import pylibsrtp
except ImportError:
    print("Error: pylibsrtp library not found (import name 'pylibsrtp'). Please install it: pip install pylibsrtp", file=sys.stderr)
    sys.exit(1)


# --- Type Definitions ---
SdpMediaInfo = namedtuple("SdpMediaInfo", [
    "media_type", # str: e.g., "audio"
    "port",       # int
    "protocol",   # str: e.g., "RTP/SAVP"
    "payload_types", # list[int]
    "connection_ip", # Optional[str]
    "label",         # Optional[str]
    "crypto_suite",  # Optional[str]
    "crypto_key_material", # Optional[bytes]
    "rtpmap" # dict[int, tuple[str, int]] : {pt: (encoding_name, rate)}
    ]
)


# --- Constants ---
LOG_FORMAT: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
SIP_VERSION: str = "SIP/2.0"
DEFAULT_SIPS_PORT: int = 5061
DEFAULT_MAX_FORWARDS: int = 70
VIA_BRANCH_PREFIX: str = "z9hG4bK"
USER_AGENT: str = "PythonSIPRECStreamer/2.3" # Version number updated
DEFAULT_SDP_AUDIO_PORT_BASE: int = 16000 # Local port base for *offering*
CRLF: str = "\r\n"
CRLF_BYTES: bytes = b"\r\n"
DTMF_PAYLOAD_TYPE: int = 100 # Common payload type for telephone-event
DEFAULT_AUDIO_ENCODING: str = "PCMA/8000"
TSHARK_STARTUP_WAIT_SEC: float = 2.0
TSHARK_TERMINATE_TIMEOUT_SEC: float = 5.0
DEFAULT_PACKET_TIME_MS: int = 20
OPTIONS_PING_DELAY = 10
BYE_RESPONSE_TIMEOUT = 2.0 # Timeout waiting for 200 OK to BYE

# Supported SRTP cipher suites (align with pylibsrtp capabilities for SDES)
SUPPORTED_SRTP_CIPHERS_SDES = [
    "AES_CM_128_HMAC_SHA1_80",
    "AES_CM_128_HMAC_SHA1_32",
]

# Mapping from common audio encoding names (uppercase) to RTP payload types
AUDIO_ENCODING_TO_PAYLOAD_TYPE: dict[str, int] = {
    "PCMU": 0, "G711U": 0,
    "PCMA": 8, "G711A": 8,
    "G722": 9,
    "G729": 18,
}

# Packet Capture Defaults (Based on Google Cloud Telephony example)
DEFAULT_CAPTURE_SIP_RANGE = "74.125.88.128/25"
DEFAULT_CAPTURE_SIP_PORT = 5672
DEFAULT_CAPTURE_MEDIA_RANGE = "74.125.39.0/24"

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("siprec_streamer")
logger.setLevel(logging.INFO)

# --- G.711 Standard Calculation ---
BIAS = 0x84
def linear16_to_ulaw(samples: np.ndarray) -> bytes:
    """ Convert linear 16-bit PCM samples (numpy array) to mu-law bytes. """
    if samples.dtype != np.int16:
        samples = (samples * 32767).astype(np.int16)
    samples_int32 = samples.astype(np.int32)
    sign = (samples_int32 < 0)
    magnitude = np.abs(samples_int32)
    magnitude += BIAS
    magnitude = np.clip(magnitude, 0, 0x7FFF)
    exponent = np.zeros_like(magnitude, dtype=np.uint8)
    thresholds = [32635, 16383, 8191, 4095, 2047, 1023, 511, 255]
    for i, threshold in enumerate(thresholds):
        exponent[magnitude <= threshold] = 7 - i
    mantissa = (magnitude >> (exponent + 3)) & 0x0F
    ulaw_byte = ~( (sign.astype(np.uint8) << 7) | (exponent << 4) | mantissa )
    return ulaw_byte.astype(np.uint8).tobytes()

def linear16_to_alaw(samples: np.ndarray) -> bytes:
    """ Convert linear 16-bit PCM samples (numpy array) to A-law bytes. """
    if samples.dtype != np.int16:
        samples = (samples * 32767).astype(np.int16)
    samples_int32 = samples.astype(np.int32)
    sign = (samples_int32 < 0)
    magnitude = np.abs(samples_int32)
    exponent = np.ones_like(magnitude, dtype=np.uint8)
    threshold = 32
    exponent[magnitude < threshold] = 0
    if np.any(magnitude >= threshold):
        shifted_magnitude = magnitude[magnitude >= threshold] >> 4
        exponent[magnitude >= threshold] = np.floor(np.log2(shifted_magnitude + 1e-9)).astype(np.uint8) + 1
        exponent = np.clip(exponent, 1, 7)
    mantissa = np.zeros_like(magnitude, dtype=np.uint8)
    mantissa[exponent == 0] = (magnitude[exponent == 0] >> 1) & 0x0F
    mantissa[exponent > 0] = (magnitude[exponent > 0] >> (exponent[exponent > 0] + 3)) & 0x0F
    alaw_byte = (sign.astype(np.uint8) << 7) | (exponent << 4) | mantissa
    alaw_byte ^= 0x55
    return alaw_byte.astype(np.uint8).tobytes()


# --- Helper Functions ---

def generate_branch() -> str:
    """Generates a unique Via branch parameter."""
    return f"{VIA_BRANCH_PREFIX}{uuid.uuid4().hex}"

def generate_tag() -> str:
    """Generates a unique From/To tag parameter."""
    return uuid.uuid4().hex[:10]

def generate_call_id() -> str:
    """Generates a unique Call-ID."""
    return uuid.uuid4().hex

def get_ip_by_name(hostname: str) -> str:
    """Resolves a hostname to an IPv4 address."""
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
        if not addr_info:
            raise socket.gaierror(f"No IPv4 address found for {hostname}")
        ip_address = addr_info[0][4][0]
        logger.debug(f"Resolved {hostname} to IPv4 {ip_address}")
        return ip_address
    except socket.gaierror as e:
        logger.error(f"Could not resolve hostname '{hostname}': {e}")
        raise ValueError(f"Failed to resolve hostname {hostname}") from e
    except Exception as e:
        logger.error(f"Unexpected error resolving hostname '{hostname}': {e}")
        raise ValueError(f"Unexpected error resolving {hostname}") from e

def create_sdp_offer(local_ip: str, local_port_base: int, audio_encoding_str: str, packet_time_ms: int) -> str:
    """Creates the initial SDP OFFER (client's view)."""
    # ... (SDP creation logic remains the same)
    encoding_name = ""
    sample_rate = 0
    payload_type = None
    try:
        parts = audio_encoding_str.split('/')
        if len(parts) == 2:
            encoding_name = parts[0].strip().upper()
            sample_rate = int(parts[1].strip())
            payload_type = AUDIO_ENCODING_TO_PAYLOAD_TYPE.get(encoding_name)
        if payload_type is None: raise ValueError("Invalid format/payload")
    except (ValueError, IndexError, TypeError):
        logger.warning(f"Invalid or unsupported audio encoding '{audio_encoding_str}'. Falling back to '{DEFAULT_AUDIO_ENCODING}'.")
        audio_encoding_str = DEFAULT_AUDIO_ENCODING
        encoding_name = audio_encoding_str.split('/')[0].upper()
        sample_rate = int(audio_encoding_str.split('/')[1])
        payload_type = AUDIO_ENCODING_TO_PAYLOAD_TYPE.get(encoding_name, 8) # Default to PCMA

    logger.info(f"Creating SDP Offer with: {encoding_name}/{sample_rate} (Payload Type: {payload_type}), DTMF PT: {DTMF_PAYLOAD_TYPE}, PTime: {packet_time_ms}ms")

    random_key_salt = base64.b64encode(os.urandom(30)).decode('ascii')
    offer_crypto_line = f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{random_key_salt}"

    sdp = f"""v=0
o=PythonSIPClient {int(time.time())} {int(time.time())+1} IN IP4 {local_ip}
s=SIPREC Test Call Stream
t=0 0
m=audio {local_port_base} RTP/SAVP {payload_type} {DTMF_PAYLOAD_TYPE}
c=IN IP4 {local_ip}
a=label:1
{offer_crypto_line}
a=rtpmap:{payload_type} {encoding_name}/{sample_rate}
a=rtpmap:{DTMF_PAYLOAD_TYPE} telephone-event/{sample_rate}
a=fmtp:{DTMF_PAYLOAD_TYPE} 0-15
a=sendonly
a=maxptime:{packet_time_ms}
m=audio {local_port_base+2} RTP/SAVP {payload_type} {DTMF_PAYLOAD_TYPE}
c=IN IP4 {local_ip}
a=label:2
{offer_crypto_line}
a=rtpmap:{payload_type} {encoding_name}/{sample_rate}
a=rtpmap:{DTMF_PAYLOAD_TYPE} telephone-event/{sample_rate}
a=fmtp:{DTMF_PAYLOAD_TYPE} 0-15
a=sendonly
a=maxptime:{packet_time_ms}
"""
    return sdp.replace('\r\n', '\n').replace('\n', CRLF)


def parse_sdp_answer(sdp_body: bytes) -> list[SdpMediaInfo]:
    """
    Parses the SDP answer (from 200 OK) to extract media line details.
    """
    # ... (SDP parsing logic remains the same)
    media_info_list: list[SdpMediaInfo] = []
    global_ip: str | None = None
    current_media_dict: dict | None = None

    try:
        sdp_str = sdp_body.decode('utf-8', errors='ignore')
        lines = sdp_str.splitlines()

        for line in lines:
            line = line.strip()
            if line.startswith("c=IN IP4 "):
                global_ip = line.split()[-1]
                logger.debug(f"SDP Answer: Found global connection IP: {global_ip}")
                break

        for line in lines:
            line = line.strip()
            if line.startswith("m="):
                if current_media_dict:
                     try:
                         current_media_dict.setdefault("rtpmap", {})
                         media_info_list.append(SdpMediaInfo(**current_media_dict))
                     except TypeError as te:
                          logger.error(f"Failed to finalize SdpMediaInfo: {te}. Data: {current_media_dict}")
                     current_media_dict = None

                parts = line.split()
                if len(parts) >= 4 and parts[0] == "m=audio":
                    try:
                        current_media_dict = {
                            "media_type": parts[0][2:],
                            "port": int(parts[1]),
                            "protocol": parts[2],
                            "payload_types": [int(pt) for pt in parts[3:] if pt.isdigit()],
                            "connection_ip": global_ip,
                            "label": None,
                            "crypto_suite": None,
                            "crypto_key_material": None,
                            "rtpmap": {}
                        }
                        logger.debug(f"SDP Answer: Found m= line: Port={current_media_dict['port']}, Proto={current_media_dict['protocol']}, PTs={current_media_dict['payload_types']}")
                    except ValueError:
                        logger.warning(f"SDP Answer: Could not parse m= line details: {line}")
                        current_media_dict = None
                else:
                    current_media_dict = None

            elif current_media_dict and line.startswith("c=IN IP4 "):
                current_media_dict["connection_ip"] = line.split()[-1]
                logger.debug(f"SDP Answer: Found media-specific IP for port {current_media_dict['port']}: {current_media_dict['connection_ip']}")

            elif current_media_dict and line.startswith("a=label:"):
                 current_media_dict["label"] = line.split(":", 1)[1]
                 logger.debug(f"SDP Answer: Found label for port {current_media_dict['port']}: {current_media_dict['label']}")

            elif current_media_dict and line.startswith("a=rtpmap:"):
                 try:
                      rtpmap_parts = line.split(":", 1)[1].split(maxsplit=1)
                      pt = int(rtpmap_parts[0])
                      name_rate_parts = rtpmap_parts[1].split('/')
                      name = name_rate_parts[0]
                      rate = int(name_rate_parts[1])
                      if pt in current_media_dict["payload_types"]:
                            current_media_dict["rtpmap"][pt] = (name, rate)
                            logger.debug(f"SDP Answer: Found rtpmap for port {current_media_dict['port']}: PT={pt}, Name={name}, Rate={rate}")
                 except (ValueError, IndexError):
                      logger.warning(f"SDP Answer: Could not parse rtpmap line: {line}")


            elif current_media_dict and line.startswith("a=crypto:"):
                crypto_parts = line.split()
                if len(crypto_parts) >= 3 and crypto_parts[2].startswith("inline:"):
                    tag = crypto_parts[0].split(':')[1]
                    suite = crypto_parts[1]
                    key_b64 = crypto_parts[2].split(':', 1)[1]

                    if suite in SUPPORTED_SRTP_CIPHERS_SDES:
                        try:
                            key_material = base64.b64decode(key_b64)
                            expected_len = 30
                            if len(key_material) == expected_len:
                                if current_media_dict["crypto_suite"] is None:
                                    current_media_dict["crypto_suite"] = suite
                                    current_media_dict["crypto_key_material"] = key_material
                                    logger.info(f"SDP Answer: Parsed valid crypto for port {current_media_dict['port']} (Tag:{tag}): Suite={suite}, KeyLen={len(key_material)}")
                                else:
                                     logger.debug(f"SDP Answer: Ignoring additional crypto line for port {current_media_dict['port']} (already have one).")
                            else:
                                logger.warning(f"SDP Answer: Crypto key material length mismatch for port {current_media_dict['port']}, suite {suite}. Expected {expected_len}, got {len(key_material)}. Line: {line}")
                        except (base64.binascii.Error, ValueError) as e:
                            logger.warning(f"SDP Answer: Error decoding base64 key material for port {current_media_dict['port']}: {e}. Line: {line}")
                    else:
                         logger.warning(f"SDP Answer: Unsupported crypto suite for port {current_media_dict['port']}: {suite}. Line: {line}")
                else:
                    logger.warning(f"SDP Answer: Could not parse crypto line format for port {current_media_dict['port']}: {line}")

        if current_media_dict:
             try:
                 current_media_dict.setdefault("rtpmap", {})
                 media_info_list.append(SdpMediaInfo(**current_media_dict))
             except TypeError as te:
                  logger.error(f"Failed to finalize last SdpMediaInfo: {te}. Data: {current_media_dict}")

    except Exception as e:
        logger.exception(f"Error parsing SDP answer: {e}")

    valid_media_info: list[SdpMediaInfo] = []
    for info in media_info_list:
        is_savp = info.protocol.endswith("SAVP")
        if info.port == 0:
            logger.warning(f"SDP Answer: Skipping media stream for label '{info.label}' (port is 0).")
        elif not info.connection_ip:
             logger.warning(f"SDP Answer: Skipping media stream on port {info.port} (no connection IP).")
        elif is_savp and not info.crypto_key_material:
             logger.warning(f"SDP Answer: Skipping media stream on port {info.port} (RTP/SAVP specified but no valid crypto key found/parsed).")
        else:
             valid_media_info.append(info)

    if not valid_media_info:
        logger.error("SDP Answer: Failed to parse any usable media descriptions from the server's response.")

    return valid_media_info

def create_siprec_metadata(config: argparse.Namespace, dest_number: str, dest_host: str) -> str:
    """Creates sample SIPREC metadata XML."""
    # ... (Metadata creation logic remains the same)
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    session_id = generate_call_id()
    conversation_id = "PY_TEST_CONV_" + uuid.uuid4().hex[:8]
    project_id = "unknown-project"

    if config.call_info_url:
        try:
            url_to_parse = config.call_info_url
            if 'CID-$(' in url_to_parse:
                logger.warning("Call-Info URL seems to contain unexpanded shell command. Using placeholder conversation ID.")
                url_to_parse = url_to_parse.split('CID-$(',1)[0] + "CID-GENERATED-" + uuid.uuid4().hex[:8]
            if '/' in url_to_parse.rstrip('/'):
                conversation_id = url_to_parse.rstrip('/').split('/')[-1]
            if 'projects/' in url_to_parse:
                project_id = url_to_parse.split('projects/')[1].split('/')[0]
            logger.debug(f"Parsed from Call-Info URL: Project='{project_id}', Conversation='{conversation_id}'")
        except Exception as e:
             logger.warning(f"Error parsing project/conversation from Call-Info URL ({config.call_info_url}): {e}")

    metadata = f"""<?xml version="1.0" encoding="UTF-8"?>
<recording xmlns="urn:ietf:params:xml:ns:recording:1">
  <session session_id="{session_id}">
    <associate-time>{timestamp}</associate-time>
  </session>
  <participant participant_id="src_participant_{generate_tag()}">
     <associate-time>{timestamp}</associate-time>
     <nameID aor="sip:{config.src_number}"/>
  </participant>
    <participant participant_id="dest_participant_{generate_tag()}">
     <associate-time>{timestamp}</associate-time>
     <nameID aor="sip:{dest_number}@{dest_host}"/>
  </participant>
  <stream stream_id="stream_label_1_{generate_tag()}" media_label="1">
      <associate-time>{timestamp}</associate-time>
      <label>Caller_Stream</label>
  </stream>
    <stream stream_id="stream_label_2_{generate_tag()}" media_label="2">
      <associate-time>{timestamp}</associate-time>
      <label>Callee_Stream</label>
  </stream>
  <extensiondata xmlns:google="http://google.com/siprec">
     <google:call id="{conversation_id}" project="{project_id}"/>
  </extensiondata>
</recording>
"""
    return metadata.replace('\r\n', '\n').replace('\n', CRLF)


def parse_sip_response(data: bytes) -> tuple[int | None, dict[str, str | list[str]], bytes]:
    """
    Parses a SIP response buffer into status code, headers, and body.
    """
    # ... (Response parsing logic remains the same)
    headers: dict[str, str | list[str]] = {}
    status_code: int | None = None
    body: bytes = b''

    try:
        header_part, body = data.split(CRLF_BYTES * 2, 1)
    except ValueError:
        header_part = data
        body = b''
        logger.debug("No body found in response (no CRLFCRLF separator)")

    lines: list[bytes] = header_part.split(CRLF_BYTES)
    if not lines:
        logger.error("Received empty or malformed response data.")
        return None, {}, b''

    match = re.match(rb'SIP/2.0\s+(\d{3})\s+(.*)', lines[0], re.IGNORECASE)
    if not match:
        logger.error(f"Could not parse status line: {lines[0].decode(errors='ignore')}")
        return None, {}, body
    try:
        status_code = int(match.group(1))
        headers['reason-phrase'] = match.group(2).decode(errors='ignore').strip()
    except (ValueError, IndexError):
        logger.error(f"Error parsing status code/reason from status line: {lines[0].decode(errors='ignore')}")
        return None, {}, body

    current_key: str | None = None
    for line_bytes in lines[1:]:
        line_bytes = line_bytes.strip()
        if not line_bytes: continue

        if line_bytes.startswith((b' ', b'\t')):
            if current_key and current_key in headers:
                value_to_append = b' ' + line_bytes.strip()
                try:
                    current_value = headers[current_key]
                    decoded_append = value_to_append.decode(errors='ignore')
                    if isinstance(current_value, list):
                        headers[current_key][-1] += decoded_append
                    elif isinstance(current_value, str):
                        headers[current_key] += decoded_append
                except Exception as e:
                     logger.warning(f"Error appending continuation line to header '{current_key}': {e}")
            else:
                logger.warning(f"Ignoring continuation line with no preceding header: {line_bytes.decode(errors='ignore')}")
            continue

        try:
            key_bytes, value_bytes = line_bytes.split(b':', 1)
            key = key_bytes.strip().lower().decode(errors='ignore')
            value = value_bytes.strip().decode(errors='ignore')
            current_key = key

            if key in headers:
                existing_value = headers[key]
                if isinstance(existing_value, list):
                    existing_value.append(value)
                else:
                    headers[key] = [existing_value, value]
            else:
                headers[key] = value
        except ValueError:
            logger.warning(f"Malformed header line (no colon?): {line_bytes.decode(errors='ignore')}")
            current_key = None
        except Exception as e:
            logger.warning(f"Error processing header line '{line_bytes.decode(errors='ignore')}': {e}")
            current_key = None

    return status_code, headers, body


# --- Main SIP Client Class ---
class SiprecTester:
    """ Manages the SIPREC test session (TLS connection, SIP messaging, state). """
    def __init__(self, config: argparse.Namespace):
        self.config: argparse.Namespace = config
        try:
            self.local_ip: str = get_ip_by_name(config.src_host)
        except ValueError as e:
            logger.error(f"Cannot proceed: Failed to resolve source host '{config.src_host}': {e}")
            raise
        self.local_sip_port: int = int(config.local_port) if config.local_port else 0
        self.call_id: str = generate_call_id()
        self.from_tag: str = generate_tag()
        self.to_tag: str | None = None # Populated after successful INVITE (2xx)
        self.cseq: int = random.randint(1, 10000) # Start CSeq randomly, increment after non-ACK/BYE req
        self.sock: socket.socket | None = None
        self.ssl_sock: ssl.SSLSocket | None = None
        self._last_branch: str = "" # Stores Via branch of last non-ACK/BYE request (for ACK/BYE Via)
        self.last_invite_offer_sdp: str | None = None
        self.last_invite_response_status: int | None = None
        self.last_invite_response_headers: dict[str, str | list[str]] = {}
        self.last_invite_response_body: bytes = b''
        self.last_invite_response_sdp_info: list[SdpMediaInfo] = []
        # State tracking for BYE logic
        self.dialog_established: bool = False # Set to True after 2xx for INVITE is processed

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Creates an SSL context for TLS with client authentication."""
        # ... (SSL context creation remains the same)
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if not self.config.cert_file or not self.config.key_file:
            raise ValueError("Certificate and Key files must be specified (--cert-file, --key-file)")
        logger.info(f"Loading client cert: {self.config.cert_file}, key: {self.config.key_file}")
        try:
            context.load_cert_chain(certfile=self.config.cert_file, keyfile=self.config.key_file)
        except ssl.SSLError as e:
            logger.error(f"SSL Error loading client certificate/key: {e}")
            if "key values mismatch" in str(e): logger.error("Hint: Ensure certificate and private key match.")
            if "bad decrypt" in str(e): logger.error("Hint: Ensure private key is not password-protected.")
            raise
        except Exception as e:
             logger.error(f"Unexpected error loading client certificate/key: {e}")
             raise

        if self.config.ca_file:
            logger.info(f"Loading CA file for server verification: {self.config.ca_file}")
            try:
                context.load_verify_locations(cafile=self.config.ca_file)
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True
                logger.info("Server certificate verification enabled.")
            except Exception as e:
                logger.error(f"Failed to load CA file '{self.config.ca_file}': {e}")
                raise
        else:
            logger.warning("*******************************************************")
            logger.warning("! WARNING: CA file not provided (--ca-file). Disabling")
            logger.warning("! server certificate verification (INSECURE!).")
            logger.warning("*******************************************************")
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        if os.environ.get('SSLKEYLOGFILE'):
             logger.info(f"SSLKEYLOGFILE detected ({os.environ['SSLKEYLOGFILE']}), TLS keys will be logged by Python's SSL module.")
        return context

    def connect(self) -> None:
        """Establishes the TCP and TLS connection to the SIP server."""
        # ... (Connect logic remains the same)
        context = self._create_ssl_context()
        bind_addr = ('', self.local_sip_port)
        dest_addr = (self.config.dest_host, self.config.dest_port)
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10.0)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            if self.local_sip_port != 0:
                 logger.info(f"Attempting to bind SIP socket to local port {self.local_sip_port}")
            self.sock.bind(bind_addr)
            actual_bound_ip, self.local_sip_port = self.sock.getsockname()
            logger.info(f"SIP Socket bound to {actual_bound_ip}:{self.local_sip_port} (using source IP '{self.local_ip}' for SIP headers)")

            logger.info(f"Connecting SIP socket to {self.config.dest_host}:{self.config.dest_port}...")
            self.sock.connect(dest_addr)
            logger.info("TCP connection established.")

            self.ssl_sock = context.wrap_socket(self.sock, server_hostname=self.config.dest_host)
            logger.info(f"TLS handshake successful. Protocol: {self.ssl_sock.version()}, Cipher: {self.ssl_sock.cipher()}")
            try:
                peer_cert = self.ssl_sock.getpeercert()
                logger.debug(f"Peer certificate details: {peer_cert}")
            except ssl.SSLError:
                logger.warning("Could not get peer certificate details (verification might be disabled).")

        except Exception as e:
            self._close_socket()
            if isinstance(e, ssl.SSLCertVerificationError):
                 logger.error(f"SSL Certificate Verification Error: {e}")
                 logger.error("Hint: Ensure CA file (--ca-file) is correct for the server, or hostname matches cert.")
                 raise ConnectionError(f"SSL Certificate Verification Error: {e}") from e
            elif isinstance(e, ssl.SSLError):
                 logger.error(f"SSL Handshake Error: {e}")
                 raise ConnectionError(f"SSL Handshake Error: {e}") from e
            elif isinstance(e, socket.timeout):
                 logger.error(f"Timeout connecting to {dest_addr}")
                 raise ConnectionError(f"Timeout connecting to {dest_addr}") from e
            elif isinstance(e, OSError):
                 logger.error(f"OS Error during connect/bind: {e}")
                 raise ConnectionError(f"OS Error during connection setup: {e}") from e
            else:
                 logger.exception(f"Unexpected connection error: {e}")
                 raise ConnectionError(f"Unexpected connection error: {e}") from e

    def _send_request(self, method: str, headers: dict[str, any], body: bytes = b'') -> bool:
        """
        Constructs and sends a SIP request over the TLS connection.
        Internal method. Increments CSeq for non-ACK requests.
        """
        # **Important**: This method now increments CSeq for all non-ACK requests.
        # We need to be careful when calling it for BYE.
        if not self.ssl_sock:
            logger.error("Cannot send request: Not connected.")
            return False

        port_suffix = f":{self.config.dest_port}" if self.config.dest_port != DEFAULT_SIPS_PORT else ""
        if method == "OPTIONS" and self.config.options_target_uri:
            request_uri = self.config.options_target_uri
        # For BYE, the Request-URI should typically be the Contact from the 200 OK.
        # For simplicity here, we'll reuse the original destination URI.
        # A robust client might store and use the peer's Contact.
        # elif method == "BYE" and self.last_invite_response_headers.get('contact'):
             # Parse and use contact URI - more complex
        else:
            request_uri = f"sip:{self.config.dest_number}@{self.config.dest_host}{port_suffix}"
        req_line = f"{method} {request_uri} {SIP_VERSION}"

        current_cseq_num: int
        cseq_method_str = method
        # Determine CSeq number based on method
        if method == "ACK":
            # ACK uses the CSeq number from the INVITE it acknowledges.
            # It should be provided in the 'headers' dict for ACK.
            try:
                cseq_header_val = str(headers.get('CSeq', ''))
                current_cseq_num = int(cseq_header_val.split(maxsplit=1)[0])
                headers['CSeq'] = f"{current_cseq_num} ACK" # Ensure header being sent is correct
            except (ValueError, IndexError, TypeError):
                 # Fallback: Assume INVITE was the last non-ACK/BYE message
                 invite_cseq_num = self.cseq - 1 if self.cseq > 0 else 1 # Needs careful check
                 logger.warning(f"Could not parse CSeq number for ACK from provided header. Using previous CSeq {invite_cseq_num}.")
                 current_cseq_num = invite_cseq_num
                 headers['CSeq'] = f"{current_cseq_num} ACK" # Correct the header being sent
        else:
            # For other methods (OPTIONS, INVITE, BYE), use the current counter before incrementing
            current_cseq_num = self.cseq

        # --- Via Header ---
        # Generate new branch for non-ACK requests
        branch = generate_branch()
        # ACK uses the same branch as the INVITE it acknowledges.
        # BYE uses a *new* branch.
        via_branch_to_use = self._last_branch if method == "ACK" else branch
        # Store the branch used for this request *if* it's not ACK (for potential future ACK)
        # We don't store the branch for BYE as it terminates the dialog.
        if method not in ["ACK", "BYE"]:
             self._last_branch = branch
        # Use the actual bound local SIP port and resolved local IP
        via_header = f"{SIP_VERSION}/TLS {self.local_ip}:{self.local_sip_port};branch={via_branch_to_use}"

        # --- From Header ---
        from_header = f"\"{self.config.src_display_name}\" <sip:{self.config.src_number}>;tag={self.from_tag}"

        # --- To Header ---
        to_uri_part = f"sip:{self.config.dest_number}@{self.config.dest_host}{port_suffix}"
        to_header = f"\"SIPREC-SRS\" <{to_uri_part}>"
        # Add To tag if we have one (i.e., in a dialog) for non-INVITE requests.
        # ACK and BYE *must* have the to_tag.
        if self.to_tag and method != "INVITE":
             # Allow explicit 'To' header override for flexibility (e.g., if passed by caller)
             if headers.get("To") and ";tag=" in str(headers.get("To")):
                 logger.debug(f"Using To header provided explicitly for {method}.")
                 to_header = headers["To"]
             else:
                 to_header += f";tag={self.to_tag}"

        # --- Contact Header (usually only needed in INVITE/OPTIONS/REGISTER) ---
        contact_header = None
        if method in ["INVITE", "OPTIONS"]:
            contact_header = f"\"{self.config.src_display_name}\" <sip:{self.config.src_number.split('@')[0]}@{self.local_ip}:{self.local_sip_port};transport=tls>"

        # --- Default Headers ---
        default_hdrs: dict[str, any] = {
            'Via': via_header,
            'From': from_header,
            'To': to_header,
            'Call-ID': self.call_id,
            'CSeq': f"{current_cseq_num} {cseq_method_str}", # Use determined CSeq num & method string
            'Max-Forwards': str(DEFAULT_MAX_FORWARDS),
            'Contact': contact_header, # Will be None if not INVITE/OPTIONS
            'User-Agent': USER_AGENT,
            'Content-Length': str(len(body))
        }

        # --- Final Headers ---
        # Merge default headers with custom ones. Custom headers overwrite defaults.
        # Remove keys with None values from default_hdrs before merging
        final_hdrs = {k: v for k, v in default_hdrs.items() if v is not None}
        final_hdrs.update(headers) # Custom headers overwrite
        # Ensure Content-Length is always correct based on the body provided
        final_hdrs['Content-Length'] = str(len(body))

        # --- Construct Message ---
        message_lines: list[str] = [req_line]
        for key, value in final_hdrs.items():
            # Use canonical capitalization for headers
            canonical_key = '-'.join(word.capitalize() for word in key.split('-'))
            if isinstance(value, list):
                for v_item in value: message_lines.append(f"{canonical_key}: {v_item}")
            else: message_lines.append(f"{canonical_key}: {value}")

        full_message_str: str = CRLF.join(message_lines) + CRLF * 2
        full_message_bytes: bytes = full_message_str.encode('utf-8') + body

        # --- Logging ---
        logger.debug(f"--- Sending {method} (CSeq: {final_hdrs['CSeq']}) --->")
        logger.debug(full_message_str.strip())
        if body:
             try: logger.debug(CRLF + body.decode('utf-8', errors='replace').strip())
             except Exception: logger.debug(CRLF + f"<Body: {len(body)} bytes>")
        else: logger.debug(CRLF + "<No Body>")
        logger.debug("--- End Message --->")

        # --- Send Data ---
        try:
            self.ssl_sock.sendall(full_message_bytes)
            # Increment CSeq counter *after* sending, but *not* for ACK.
            if method != "ACK":
                 self.cseq += 1
            return True
        except socket.error as e:
            logger.error(f"Socket error sending {method}: {e}")
            # Critical: Close the connection if send fails, as it's likely broken.
            self.close()
            return False
        except Exception as e:
             logger.exception(f"Unexpected error sending {method}: {e}")
             self.close()
             return False

    def _receive_response(self, timeout: float = 10.0) -> tuple[int | None, dict[str, str | list[str]], bytes, bytes]:
        """
        Receives a SIP response using select for timeout. Handles potential read errors.
        """
        # ... (Receive logic remains mostly the same, ensures robust timeout/error handling)
        if not self.ssl_sock:
            logger.error("Cannot receive response: Not connected.")
            return None, {}, b'', b''

        buffer = bytearray()
        raw_buffer_log = bytearray()
        headers_parsed = False
        content_length: int | None = None
        expected_total_len: int | None = None
        header_len = 0
        start_time = time.monotonic()

        try:
            while True:
                elapsed_time = time.monotonic() - start_time
                if elapsed_time >= timeout:
                     # Distinguish timeout from no data at all vs timeout waiting for more data
                     if not raw_buffer_log:
                         logger.warning(f"Timeout ({timeout:.1f}s) waiting for initial SIP response data.")
                     else:
                          logger.warning(f"Timeout ({timeout:.1f}s) waiting for further SIP response data (received {len(raw_buffer_log)} bytes).")
                     break

                remaining_timeout = max(0.01, timeout - elapsed_time)
                try:
                    # Check if socket is readable or if there's an error
                    readable, _, exceptional = select.select([self.ssl_sock], [], [self.ssl_sock], remaining_timeout)
                except ValueError:
                     logger.warning("Socket closed unexpectedly during select().")
                     break
                except Exception as sel_err:
                     logger.error(f"Error during select(): {sel_err}")
                     break

                if exceptional:
                     logger.error("Socket reported exceptional condition during select(). Connection likely lost.")
                     # Mark dialog as potentially invalid if one existed
                     self.dialog_established = False
                     break
                if not readable:
                     # select timed out this interval, loop will check overall timeout
                     continue

                # Socket is readable, attempt to receive data
                try:
                    chunk = self.ssl_sock.recv(4096)
                except (socket.timeout, ssl.SSLWantReadError):
                     logger.debug("Socket recv timed out or SSLWantReadError after select, retrying.")
                     time.sleep(0.01)
                     continue
                except ssl.SSLError as ssl_err:
                     logger.error(f"SSL error during recv: {ssl_err}. Connection likely lost.")
                     self.dialog_established = False # Mark dialog invalid
                     break
                except socket.error as sock_err:
                    logger.error(f"Socket error receiving data: {sock_err}. Connection likely lost.")
                    self.dialog_established = False # Mark dialog invalid
                    break
                except Exception as recv_err: # Catch other potential errors
                     logger.exception(f"Unexpected error during recv: {recv_err}")
                     self.dialog_established = False
                     break

                # Handle connection closed by peer
                if not chunk:
                    logger.warning("Connection closed by peer while receiving response.")
                    self.dialog_established = False # Dialog terminated by peer
                    break

                raw_buffer_log.extend(chunk)
                buffer.extend(chunk)

                # --- Try parsing headers and determining body length ---
                if not headers_parsed and CRLF_BYTES * 2 in buffer:
                    try:
                        header_part_bytes, _ = buffer.split(CRLF_BYTES * 2, 1)
                        header_len = len(header_part_bytes) + len(CRLF_BYTES * 2)
                        cl_match = re.search(rb'^[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ll][Ee][Nn][Gg][Tt][Hh]\s*:\s*(\d+)\s*$', header_part_bytes, re.MULTILINE)
                        if cl_match:
                            content_length = int(cl_match.group(1))
                            expected_total_len = header_len + content_length
                            logger.debug(f"Parsed Content-Length: {content_length}. Expecting total {expected_total_len} bytes.")
                        else:
                            logger.debug("No Content-Length header found in response.")
                        headers_parsed = True
                    except Exception as parse_err:
                        logger.warning(f"Error parsing headers for Content-Length: {parse_err}.")
                        headers_parsed = True # Mark as processed anyway

                # --- Check if we have received the complete message ---
                if headers_parsed and content_length is not None:
                    if len(buffer) >= expected_total_len:
                        logger.debug(f"Received {len(buffer)} bytes >= expected {expected_total_len}. Assuming complete message.")
                        if len(buffer) > expected_total_len:
                             logger.warning(f"Read {len(buffer) - expected_total_len} extra bytes past Content-Length. Trimming.")
                             buffer = buffer[:expected_total_len]
                        break
                elif not headers_parsed and len(buffer) > 16384: # Header limit safeguard
                     logger.warning("Buffer exceeds 16KB without finding header end (CRLFCRLF). Treating as incomplete/malformed.")
                     break

        except Exception as e:
             logger.exception(f"Unexpected error during receive loop: {e}")
             self.dialog_established = False # Assume error invalidates dialog

        # --- Process the final buffer ---
        if raw_buffer_log:
            logger.debug(f"--- Received Raw Response ({len(raw_buffer_log)} bytes total) ---")
            try: logger.debug(bytes(raw_buffer_log).decode('utf-8', errors='replace'))
            except Exception: logger.debug("<Unable to decode raw buffer as UTF-8>")
            logger.debug("--- End Raw Response ---")
        else:
            logger.debug("No raw data was received for this response.")
            # If buffer is also empty, return signifies complete failure/timeout
            if not buffer: return None, {}, b'', b''

        status, headers, body = parse_sip_response(bytes(buffer))
        if status is None and buffer: # Parsing failed, but we had data
             logger.error("Failed to parse the received SIP response buffer.")
             return None, {}, bytes(buffer), bytes(raw_buffer_log)

        return status, headers, body, bytes(raw_buffer_log)


    def send_options(self) -> bool:
        """Sends a SIP OPTIONS request."""
        # ... (OPTIONS logic remains the same)
        options_cseq = self.cseq
        logger.info(f"Sending OPTIONS ping (CSeq: {options_cseq})...")
        headers = {
            'Accept': 'application/sdp, application/rs-metadata+xml',
        }
        if not self._send_request("OPTIONS", headers, b''):
             logger.error("Failed to send OPTIONS request.")
             return False

        status, headers_resp, body_resp, raw_resp = self._receive_response(timeout=5.0)

        if status is None:
             logger.error("No response received for OPTIONS request.")
             return False

        cseq_resp = headers_resp.get('cseq', 'N/A')
        reason = headers_resp.get('reason-phrase', '')
        if 200 <= status < 300:
            logger.info(f"Received {status} {reason} for OPTIONS (CSeq: {cseq_resp}). Connection alive.")
            logger.debug(f"OPTIONS Response Headers: {headers_resp}")
            if body_resp: logger.debug(f"OPTIONS Response Body:\n{body_resp.decode(errors='ignore')}")
            return True
        else:
            logger.error(f"Received non-2xx status for OPTIONS: {status} {reason} (CSeq: {cseq_resp})")
            logger.debug(f"Raw OPTIONS error response:\n{raw_resp.decode(errors='ignore')}")
            return False

    def send_invite(self) -> bool:
        """
        Sends the SIPREC INVITE request. Sets dialog_established on success.
        Returns True if a 2xx final response was received and processed, False otherwise.
        """
        # ... (INVITE sending logic mostly same, but adds dialog state)
        invite_cseq_num = self.cseq # Capture CSeq number *before* sending
        logger.info(f"Sending SIPREC INVITE (CSeq: {invite_cseq_num})...")

        self.last_invite_offer_sdp = create_sdp_offer(
            self.local_ip, DEFAULT_SDP_AUDIO_PORT_BASE, self.config.audio_encoding, self.config.packet_time
        )
        if not self.last_invite_offer_sdp:
             logger.error("Failed to generate SDP offer.")
             return False
        sdp_bytes = self.last_invite_offer_sdp.encode('utf-8')

        metadata_body_str = create_siprec_metadata(
            self.config, self.config.dest_number, self.config.dest_host
        )
        metadata_bytes = metadata_body_str.encode('utf-8')

        boundary = f"boundary-{uuid.uuid4().hex}"
        boundary_bytes = boundary.encode('utf-8')
        boundary_line = b'--' + boundary_bytes
        closing_boundary_line = b'--' + boundary_bytes + b'--'
        parts = [
            boundary_line, b'Content-Type: application/sdp', b'Content-Disposition: session; handling=required', CRLF_BYTES, sdp_bytes,
            boundary_line, b'Content-Type: application/rs-metadata+xml', b'Content-Disposition: recording-session; handling=required', CRLF_BYTES, metadata_bytes,
            closing_boundary_line
        ]
        body_bytes = CRLF_BYTES.join(parts)

        invite_headers = {
            'Content-Type': f'multipart/mixed; boundary="{boundary}"',
            'Accept': 'application/sdp',
            'Allow': 'INVITE, ACK, CANCEL, BYE, OPTIONS',
            'Supported': 'timer, replaces, 100rel',
            'Require': 'siprec',
            'Session-Expires': '1800; refresher=uac',
            'Min-SE': '90',
            'Call-Info': (f'<{self.config.call_info_url}>;purpose=Goog-ContactCenter-Conversation'
                          if self.config.call_info_url else None),
        }
        invite_headers = {k: v for k, v in invite_headers.items() if v is not None}

        if not self._send_request("INVITE", invite_headers, body_bytes):
             logger.error("Failed to send INVITE request.")
             self.last_invite_response_status = None
             self.dialog_established = False # Ensure state is false
             return False

        final_status: int | None = None
        final_headers: dict[str, str | list[str]] = {}
        final_body: bytes = b''
        response_count = 0
        max_responses = 10

        while response_count < max_responses:
            response_count += 1
            logger.debug(f"Waiting for INVITE response (attempt {response_count})...")
            status, headers, body, raw = self._receive_response(timeout=30.0)

            if status is None:
                if response_count == 1: logger.error("Failed to receive any response for INVITE.")
                else: logger.error(f"Timed out waiting for final response after receiving status {final_status}.")
                self.last_invite_response_status = final_status
                self.dialog_established = False # Ensure state is false
                return False

            reason = headers.get('reason-phrase', '')
            cseq_resp = headers.get('cseq', 'N/A')
            logger.info(f"Received response for INVITE: {status} {reason} (CSeq: {cseq_resp})")

            if 100 <= status < 200:
                logger.info(f"Received provisional response {status} {reason}. Waiting for final response.")
                final_status = status
                # Optional: Check for early dialog info (e.g., To tag in 183)
                # if status == 183 and not self.to_tag: ... parse tag ...
                if body: logger.debug(f"Provisional response body:\n{body.decode(errors='ignore')}")
                continue

            elif status >= 200:
                final_status = status; final_headers = headers; final_body = body
                logger.debug(f"Received final response {status}. Processing result.")
                break
            else: # Should not happen
                logger.warning(f"Received invalid status code {status}, ignoring and waiting.")
                final_status = status

        if final_status is None or final_status < 200:
            logger.error(f"Loop finished after {response_count} responses without receiving a final (>=200) response for INVITE.")
            self.last_invite_response_status = final_status
            self.dialog_established = False # Ensure state is false
            return False

        self.last_invite_response_status = final_status
        self.last_invite_response_headers = final_headers
        self.last_invite_response_body = final_body

        if 200 <= final_status < 300:
            logger.info(f"Received final {final_status} {final_headers.get('reason-phrase', '')} for INVITE. Call establishing...")
            logger.debug(f"Final Response Headers: {final_headers}")
            if final_body: logger.debug(f"Final Response Body (SDP):\n{final_body.decode(errors='ignore')}")

            # Capture To tag (essential for ACK/BYE)
            to_header_val = final_headers.get('to')
            to_headers_list = to_header_val if isinstance(to_header_val, list) else [to_header_val] if to_header_val else []
            tag_found = False
            for hdr in to_headers_list:
                if isinstance(hdr, str):
                    match = re.search(r'[;,\s]tag=([\w.-]+)', hdr)
                    if match:
                        self.to_tag = match.group(1)
                        tag_found = True
                        break
            if tag_found:
                logger.info(f"Captured To tag from {final_status} response: {self.to_tag}")
            else:
                logger.error(f"CRITICAL: Received {final_status} success, but could not find 'tag=' in To header: {to_header_val}")
                self.dialog_established = False # Cannot establish dialog without tag
                return False # Treat as failure

            # Parse SDP if 200 OK and body exists
            if final_status == 200 and final_body:
                logger.info("Parsing SDP answer from 200 OK...")
                self.last_invite_response_sdp_info = parse_sdp_answer(final_body)
                if not self.last_invite_response_sdp_info and self.config.audio_file:
                     logger.error("CRITICAL: Received 200 OK but failed to parse required media info from SDP answer. Streaming will fail.")
                     self.dialog_established = False # Cannot proceed with streaming
                     return False
                for i, info in enumerate(self.last_invite_response_sdp_info):
                    crypto_ok = info.crypto_suite is not None
                    logger.info(f"  Parsed Answer Stream {i+1}: Label='{info.label}', Target={info.connection_ip}:{info.port}, Proto={info.protocol}, Crypto={crypto_ok}")

            # If we reached here with a 2xx and got the To tag, the dialog is established
            self.dialog_established = True
            logger.debug("Dialog established state set to True.")
            return True

        else: # Failure Case (>= 300)
            logger.error(f"INVITE failed with final status: {final_status} {final_headers.get('reason-phrase', '')}")
            if final_body: logger.error(f"Failure Body:\n{final_body.decode(errors='ignore')}")
            self.dialog_established = False # Ensure state is false
            return False

    def send_ack(self, invite_cseq_num: int) -> bool:
        """Sends an ACK request for a successful INVITE."""
        # ... (ACK logic remains the same)
        if not self.to_tag:
             logger.error("Cannot send ACK: Missing To tag (must be captured from INVITE 2xx response).")
             return False
        if not self._last_branch:
             logger.error("Cannot send ACK: Missing Via branch from INVITE (internal error).")
             return False

        logger.info(f"Sending ACK for INVITE (CSeq: {invite_cseq_num} ACK)...")

        ack_via = f"{SIP_VERSION}/TLS {self.local_ip}:{self.local_sip_port};branch={self._last_branch}"
        ack_from = f"\"{self.config.src_display_name}\" <sip:{self.config.src_number}>;tag={self.from_tag}"
        port_suffix = f":{self.config.dest_port}" if self.config.dest_port != DEFAULT_SIPS_PORT else ""
        ack_to_uri = f"sip:{self.config.dest_number}@{self.config.dest_host}{port_suffix}"
        ack_to = f"\"SIPREC-SRS\" <{ack_to_uri}>;tag={self.to_tag}"

        ack_headers = {
            'Via': ack_via,
            'From': ack_from,
            'To': ack_to,
            'Call-ID': self.call_id,
            'CSeq': f"{invite_cseq_num} ACK", # Use INVITE's CSeq num, Method ACK
            'Max-Forwards': str(DEFAULT_MAX_FORWARDS),
            'Content-Length': "0"
        }

        # Note: _send_request does NOT increment self.cseq for ACK
        ack_sent = self._send_request("ACK", ack_headers, b'')
        if ack_sent: logger.info("ACK sent successfully.")
        else: logger.error("Failed to send ACK.")
        return ack_sent

    def send_bye(self) -> bool:
        """
        Attempts to send a BYE request to terminate the established dialog.

        This should only be called if `self.dialog_established` is True.
        It's a best-effort attempt; failure (e.g., if the connection is already
        down) is logged but doesn't prevent cleanup.

        Returns:
            bool: True if the BYE request was successfully sent, False otherwise.
        """
        if not self.dialog_established:
            logger.debug("Cannot send BYE: Dialog not established (INVITE likely failed or To tag missing).")
            return False
        if not self.ssl_sock:
            logger.error("Cannot send BYE: Not connected.")
            self.dialog_established = False # Mark dialog ended due to connection issue
            return False
        if not self.to_tag:
             logger.error("Cannot send BYE: Missing To tag (internal state error).")
             self.dialog_established = False # Mark dialog ended due to state issue
             return False

        bye_cseq_num = self.cseq # Use the current CSeq number *before* sending
        logger.info(f"Sending BYE to terminate dialog (CSeq: {bye_cseq_num} BYE)...")

        # Construct BYE headers
        bye_headers = {
            # Via uses a *new* branch, created by _send_request
            # From includes from_tag
            # To includes to_tag
            'Content-Length': "0" # BYE has no body
            # Other essential headers (Via, From, To, Call-ID, CSeq, Max-Forwards)
            # are added by _send_request using the current state.
        }

        # Call _send_request for BYE. This will use the current self.cseq
        # and increment it afterwards if successful.
        bye_sent = self._send_request("BYE", bye_headers, b'')

        if bye_sent:
            logger.info("BYE request sent successfully.")
            # Mark dialog as terminated locally *after* sending BYE
            self.dialog_established = False
            logger.debug("Dialog established state set to False after sending BYE.")

            # Optionally, wait briefly for a 200 OK response to the BYE
            logger.debug(f"Waiting up to {BYE_RESPONSE_TIMEOUT}s for BYE response...")
            status, headers, _, _ = self._receive_response(timeout=BYE_RESPONSE_TIMEOUT)
            if status == 200:
                logger.info(f"Received 200 OK for BYE (CSeq: {headers.get('cseq', 'N/A')}).")
            elif status is not None:
                logger.warning(f"Received unexpected response to BYE: {status} {headers.get('reason-phrase', '')}")
            else:
                logger.debug("No response received for BYE within timeout.")
            return True # Return True because BYE was sent
        else:
            logger.error("Failed to send BYE request.")
            # If sending failed, the connection might be broken. Mark dialog ended.
            self.dialog_established = False
            return False

    def _close_socket(self) -> None:
        """Internal helper to close the plain socket if it exists."""
        # ... (Close socket logic remains the same)
        if self.sock:
             sock_fd = -1
             try: sock_fd = self.sock.fileno()
             except Exception: pass
             logger.debug(f"Closing plain socket (fd={sock_fd if sock_fd != -1 else 'N/A'})...")
             try:
                 try: self.sock.shutdown(socket.SHUT_RDWR)
                 except (socket.error, OSError) as shut_err:
                      if shut_err.errno not in (socket.errno.ENOTCONN, socket.errno.EBADF, 107): # 107: EPIPE on some systems?
                           logger.warning(f"Error shutting down plain socket {sock_fd}: {shut_err}")
                 self.sock.close()
                 logger.debug(f"Plain socket (fd={sock_fd}) closed.")
             except (socket.error, OSError) as close_err:
                 logger.warning(f"Error closing plain socket {sock_fd}: {close_err}")
             finally:
                self.sock = None

    def close(self) -> None:
        """
        Closes the TLS and underlying socket connection gracefully.
        Sets dialog_established to False.
        """
        # Mark dialog ended as connection is closing
        self.dialog_established = False
        if self.ssl_sock:
            sock_fd = -1
            try: sock_fd = self.ssl_sock.fileno()
            except Exception: pass
            logger.info(f"Closing TLS connection (socket fd={sock_fd if sock_fd != -1 else 'N/A'})...")
            try:
                # Perform TLS shutdown (send close_notify)
                self.ssl_sock.unwrap()
                logger.debug(f"TLS layer unwrapped for socket {sock_fd}.")
            except ssl.SSLError as ssl_err:
                 # Ignore common errors during unwrap on already closed sockets
                 err_str = str(ssl_err).upper()
                 if "SOCKET_CLOSED" in err_str or "WRONG_VERSION_NUMBER" in err_str or \
                    "SHUTDOWN_WHILE_ASYNC_OPERATIONS" in err_str or "SSL_ERROR_EOF" in err_str or \
                    "UNEXPECTED EOF" in err_str: # Add common variations
                      logger.debug(f"Ignoring expected SSL error during unwrap (socket likely closed): {ssl_err}")
                 else:
                      logger.warning(f"SSL error during unwrap() on socket {sock_fd}: {ssl_err}")
            except (socket.error, OSError) as sock_err:
                 if sock_err.errno not in (socket.errno.ENOTCONN, socket.errno.EBADF, 107, socket.errno.EPIPE): # Add EPIPE
                      logger.warning(f"Socket error during unwrap() on socket {sock_fd}: {sock_err}")
                 else:
                      logger.debug(f"Socket closed or not connected during unwrap: {sock_err}")
            except Exception as e:
                 logger.warning(f"Unexpected error during unwrap() on socket {sock_fd}: {e}")
            finally:
                 # Always try to close the SSL socket object
                 try:
                      self.ssl_sock.close()
                      logger.info(f"TLS connection closed (socket fd={sock_fd}).")
                 except (socket.error, OSError, ssl.SSLError) as close_err:
                      logger.warning(f"Error closing SSL socket object (fd={sock_fd}): {close_err}")
                 finally:
                      self.ssl_sock = None
                      self.sock = None # Underlying socket closed by ssl_sock.close()
        elif self.sock:
             logger.info("Closing plain socket (no TLS layer was active)...")
             self._close_socket()
        else:
             logger.debug("No active connection to close.")


# --- Media Streaming Function ---

def stream_channel(
    channel_index: int,
    audio_file_path: str,
    dest_ip: str,
    dest_port: int,
    payload_type: int,
    codec_name: str,
    sample_rate: int,
    packet_time_ms: int,
    srtp_session: pylibsrtp.Session,
    local_rtp_port: int,
    stop_event: threading.Event,
    max_duration_sec: float | None = None,
):
    """
    Reads one audio channel, encodes, packetizes, encrypts (SRTP), and sends it.
    """
    # ... (Streaming logic remains the same)
    thread_name = f"Streamer-{channel_index}"
    logger.info(f"[{thread_name}] Starting: Target={dest_ip}:{dest_port}, Local UDP Port={local_rtp_port}, PT={payload_type}, Codec={codec_name}/{sample_rate}, PTime={packet_time_ms}ms")

    samples_per_packet = int(sample_rate * packet_time_ms / 1000)
    packet_interval_sec = packet_time_ms / 1000.0
    timestamp_increment = samples_per_packet

    rtp_socket: socket.socket | None = None
    audio_file: sf.SoundFile | None = None
    stream_start_time = time.monotonic()
    packets_sent = 0
    bytes_sent = 0

    try:
        rtp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp_socket.bind(('', local_rtp_port))
        logger.info(f"[{thread_name}] UDP sending socket bound successfully to local port {local_rtp_port}")

        ssrc = random.randint(0, 0xFFFFFFFF)
        sequence_number = random.randint(0, 0xFFFF)
        timestamp = random.randint(0, 0xFFFFFFFF)

        audio_file = sf.SoundFile(audio_file_path, 'r')

        if audio_file.channels < channel_index + 1:
             logger.error(f"[{thread_name}] Audio file '{audio_file_path}' has only {audio_file.channels} channels, cannot stream channel {channel_index}.")
             raise ValueError(f"Insufficient channels in audio file for channel index {channel_index}")
        if audio_file.samplerate != sample_rate:
            logger.warning(f"[{thread_name}] Audio file sample rate ({audio_file.samplerate}Hz) differs from negotiated rate ({sample_rate}Hz). Streaming will proceed, but quality/timing may be affected.")

        logger.info(f"[{thread_name}] Audio File Info: Rate={audio_file.samplerate}, Channels={audio_file.channels}, Frames={audio_file.frames or 'Unknown'}")
        logger.info(f"[{thread_name}] RTP Params: SSRC={ssrc:08X}, StartSeq={sequence_number}, StartTS={timestamp}, Samples/Pkt={samples_per_packet}")

        encode_func = None
        if codec_name == "PCMA": encode_func = linear16_to_alaw
        elif codec_name == "PCMU": encode_func = linear16_to_ulaw
        else: raise ValueError(f"Unsupported codec for encoding: {codec_name}")

        for block_num, block in enumerate(audio_file.blocks(blocksize=samples_per_packet, dtype='int16', fill_value=0)):
            loop_start_time = time.monotonic()

            if stop_event.is_set():
                logger.info(f"[{thread_name}] Stop event received. Halting stream.")
                break
            current_duration = loop_start_time - stream_start_time
            if max_duration_sec and max_duration_sec > 0 and current_duration >= max_duration_sec:
                logger.info(f"[{thread_name}] Maximum stream duration ({max_duration_sec:.1f}s) reached. Halting stream.")
                break
            if block.shape[0] == 0:
                logger.info(f"[{thread_name}] End of audio file reached.")
                break

            channel_data = block[:, channel_index]

            if channel_data.shape[0] < samples_per_packet:
                 padding_needed = samples_per_packet - channel_data.shape[0]
                 padding = np.zeros(padding_needed, dtype=np.int16)
                 channel_data = np.concatenate((channel_data, padding))

            payload = encode_func(channel_data)

            version = 2; padding_flag = 0; extension_flag = 0; csrc_count = 0; marker_bit = 0
            header_byte1 = (version << 6) | (padding_flag << 5) | (extension_flag << 4) | csrc_count
            header_byte2 = (marker_bit << 7) | payload_type
            rtp_header = struct.pack('!BBHLL',
                                      header_byte1, header_byte2,
                                      sequence_number & 0xFFFF,
                                      timestamp & 0xFFFFFFFF,
                                      ssrc)
            rtp_packet = rtp_header + payload

            try:
                srtp_packet = srtp_session.protect(rtp_packet)
            except pylibsrtp.Error as srtp_err:
                logger.error(f"[{thread_name}] SRTP protection failed (Seq={sequence_number}): {srtp_err}")
                stop_event.set()
                break
            except Exception as protect_err:
                logger.exception(f"[{thread_name}] Unexpected error during SRTP protect (Seq={sequence_number}): {protect_err}")
                stop_event.set()
                break

            try:
                bytes_sent_this_packet = rtp_socket.sendto(srtp_packet, (dest_ip, dest_port))
                bytes_sent += bytes_sent_this_packet
                packets_sent += 1
                if packets_sent % 100 == 1:
                    logger.debug(f"[{thread_name}] Sent SRTP packet: Seq={sequence_number}, TS={timestamp}, Size={bytes_sent_this_packet}")
            except socket.error as send_err:
                logger.error(f"[{thread_name}] Socket error sending SRTP (Seq={sequence_number}): {send_err}")
                stop_event.set()
                break
            except Exception as send_exc:
                logger.exception(f"[{thread_name}] Unexpected error sending SRTP (Seq={sequence_number}): {send_exc}")
                stop_event.set()
                break

            sequence_number = (sequence_number + 1) & 0xFFFF
            timestamp = (timestamp + timestamp_increment) & 0xFFFFFFFF

            elapsed_time = time.monotonic() - loop_start_time
            sleep_time = packet_interval_sec - elapsed_time
            if sleep_time > 0:
                time.sleep(sleep_time)
            elif packets_sent > 10:
                 logger.warning(f"[{thread_name}] Loop processing time ({elapsed_time:.4f}s) exceeded packet interval ({packet_interval_sec:.4f}s). Stream may be falling behind.")

        logger.info(f"[{thread_name}] Streaming loop finished. Packets sent: {packets_sent}, Bytes sent: {bytes_sent}")

    except sf.SoundFileError as e:
        logger.error(f"[{thread_name}] Error accessing audio file '{audio_file_path}': {e}")
        stop_event.set()
    except pylibsrtp.Error as e:
         logger.error(f"[{thread_name}] SRTP context configuration error: {e}")
         stop_event.set()
    except ValueError as e:
         logger.error(f"[{thread_name}] Configuration or file processing error: {e}")
         stop_event.set()
    except OSError as e:
         logger.error(f"[{thread_name}] Socket OS error (bind/config?): {e}")
         stop_event.set()
    except Exception as e:
        logger.exception(f"[{thread_name}] Unexpected error during streaming setup or loop: {e}")
        stop_event.set()
    finally:
        if audio_file:
            try: audio_file.close()
            except Exception as close_err: logger.warning(f"[{thread_name}] Error closing audio file: {close_err}")
        if rtp_socket:
            try: rtp_socket.close()
            except Exception as close_err: logger.warning(f"[{thread_name}] Error closing RTP socket: {close_err}")
        logger.info(f"[{thread_name}] Streaming thread terminated.")


# --- Main Execution ---

def main() -> None:
    """ Main function: Parse args, run SIP client, optionally stream, send BYE, clean up. """

    # ... (Argument parsing remains the same)
    ssl_key_log_file_path = os.environ.get('SSLKEYLOGFILE')
    if ssl_key_log_file_path: print(f"INFO: SSLKEYLOGFILE environment variable detected: {ssl_key_log_file_path}", file=sys.stderr)
    else: print("INFO: SSLKEYLOGFILE environment variable not set. Set it to log TLS keys for potential decryption (e.g., in Wireshark).", file=sys.stderr)

    parser = argparse.ArgumentParser(
        description=f"Python SIPREC Test Client with SRTP Streaming using pylibsrtp (v{USER_AGENT.split('/')[1]})",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="Requires pylibsrtp, soundfile, numpy. Sends BYE on exit if INVITE succeeded.\n"
               f"Default packet capture filters match Google Telephony ranges:\n"
               f"  SIP: TCP to/from {DEFAULT_CAPTURE_SIP_RANGE} port {DEFAULT_CAPTURE_SIP_PORT}\n"
               f"  Media: UDP to/from {DEFAULT_CAPTURE_MEDIA_RANGE}\n"
               "Use --capture-* arguments to override."
    )
    # Destination Server Details
    parser.add_argument("dest_number", help="Destination user/number part for Request-URI")
    parser.add_argument("dest_host", help="Destination SIP server hostname or IP address")
    parser.add_argument("-p", "--dest-port", type=int, default=DEFAULT_SIPS_PORT, help="Destination SIP server port for SIPS/TLS")
    # Source Client Details
    parser.add_argument("-s", "--src-number", required=True, help="Source AOR (e.g., 'siprec-client@example.com')")
    parser.add_argument("--src-host", required=True, help="Source host FQDN or public IP (must be resolvable)")
    parser.add_argument("--src-display-name", default="PythonSIPRECClient", help="Source display name")
    # Local Network Configuration
    parser.add_argument("--local-port", type=int, default=0, help="Local TCP port for SIP signaling (0=OS default)")
    # TLS Configuration
    parser.add_argument("--cert-file", required=True, help="Path to client TLS certificate file (PEM)")
    parser.add_argument("--key-file", required=True, help="Path to client TLS private key file (PEM, unencrypted)")
    parser.add_argument("--ca-file", help="Path to CA certificate file for server verification (PEM). Omit=INSECURE.")
    # SIP/SDP Behavior
    parser.add_argument("--audio-encoding", default=DEFAULT_AUDIO_ENCODING,
                        help=f"Audio encoding for SDP ('NAME/Rate'). Supported: {list(AUDIO_ENCODING_TO_PAYLOAD_TYPE.keys())}")
    parser.add_argument("--options-ping-count", type=int, default=0,
                        help="Number of OPTIONS pings before INVITE.")
    parser.add_argument("--options-target-uri", help="Optional Request-URI for OPTIONS.")
    parser.add_argument("--call-info-url", help="URL for Call-Info header (e.g., CCAI conversation URL)")
    # Media Streaming Configuration
    parser.add_argument("--audio-file", help="Path to 2-channel audio file (e.g., WAV) for SRTP streaming.")
    parser.add_argument("--packet-time", type=int, default=DEFAULT_PACKET_TIME_MS, help="RTP packet duration (ms)")
    parser.add_argument("--stream-duration", type=float, default=0, help="Max stream duration (sec, 0=until file end/Ctrl+C)")
    # Tooling and Debugging
    parser.add_argument("-d", "--debug", action="store_true", help="Enable DEBUG level logging.")
    # Packet Capture Configuration
    parser.add_argument("--pcap-file", help="Output file path for packet capture (requires tshark).")
    parser.add_argument("--capture-interface", default="any", help="Network interface for tshark ('any' needs root/admin).")
    parser.add_argument("--capture-sip-range", default=DEFAULT_CAPTURE_SIP_RANGE,
                        help="IP/CIDR for SIP signaling capture.")
    parser.add_argument("--capture-sip-port", type=int, default=DEFAULT_CAPTURE_SIP_PORT,
                        help="TCP port for SIP signaling capture.")
    parser.add_argument("--capture-media-range", default=DEFAULT_CAPTURE_MEDIA_RANGE,
                        help="IP/CIDR for RTP/media capture (UDP).")

    args = parser.parse_args()

    # --- Logging Setup ---
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.getLogger().setLevel(log_level)
    logger.setLevel(log_level)
    if log_level == logging.DEBUG: logger.debug("Debug logging enabled.")

    # --- Argument Validation ---
    # ... (Validation logic remains the same)
    if '@' not in args.src_number:
        logger.warning(f"Source number '{args.src_number}' doesn't contain '@'. Appending '@{args.src_host}'.")
        args.src_number = f"{args.src_number}@{args.src_host}"
    try:
         required_files = {'cert-file': args.cert_file, 'key-file': args.key_file}
         if args.ca_file: required_files['ca-file'] = args.ca_file
         if args.audio_file: required_files['audio-file'] = args.audio_file
         for name, path in required_files.items():
              if not os.path.isfile(path):
                   raise FileNotFoundError(f"Required file --{name} not found or is not a file: {path}")
    except FileNotFoundError as fnf_error:
         print(f"Error: {fnf_error}", file=sys.stderr)
         sys.exit(1)

    parsed_encoding = False
    try:
        parts = args.audio_encoding.split('/')
        if len(parts) == 2 and parts[1].isdigit():
            enc_name = parts[0].strip().upper()
            if enc_name in AUDIO_ENCODING_TO_PAYLOAD_TYPE:
                parsed_encoding = True
            else: logger.warning(f"Audio encoding name '{enc_name}' not explicitly mapped. Ensure server supports it.")
        if not parsed_encoding: raise ValueError("Invalid format")
    except ValueError:
        logger.warning(f"Provided --audio-encoding '{args.audio_encoding}' is invalid. Using default '{DEFAULT_AUDIO_ENCODING}'.")
        args.audio_encoding = DEFAULT_AUDIO_ENCODING

    # --- Packet Capture Setup ---
    # ... (Packet capture setup logic remains the same)
    tshark_process: subprocess.Popen | None = None
    tshark_failed_to_start: bool = False
    pcap_base_file = args.pcap_file
    pcap_decrypted_file: str | None = None

    if args.pcap_file:
        tshark_path = shutil.which("tshark")
        if not tshark_path:
             logger.error("'tshark' executable not found in system PATH. Skipping packet capture.")
             tshark_failed_to_start = True
        else:
            logger.info("Packet capture requested (--pcap-file). Constructing filter...")
            try:
                 sip_target = args.capture_sip_range
                 sip_keyword = "net" if '/' in sip_target else "host"
                 sip_condition = f"({sip_keyword} {sip_target} and tcp port {args.capture_sip_port})"
                 media_target = args.capture_media_range
                 media_keyword = "net" if '/' in media_target else "host"
                 media_condition = f"({media_keyword} {media_target} and udp)"
                 bpf_filter = f"{sip_condition} or {media_condition}"
                 logger.info(f"Using tshark BPF filter: {bpf_filter}")

                 if ssl_key_log_file_path and os.path.exists(ssl_key_log_file_path):
                     base, ext = os.path.splitext(pcap_base_file)
                     pcap_decrypted_file = f"{base}-decrypted{ext or '.pcapng'}"
                     logger.info(f"SSLKEYLOGFILE is set. Will attempt key injection into '{pcap_decrypted_file}' using editcap after capture.")
                 elif ssl_key_log_file_path:
                      logger.warning(f"SSLKEYLOGFILE is set ('{ssl_key_log_file_path}') but file not found. Pcap won't be automatically decrypted.")
                 else:
                     logger.warning("SSLKEYLOGFILE is not set. Captured pcap file will not be automatically decrypted.")

                 tshark_cmd = [tshark_path, "-i", args.capture_interface, "-f", bpf_filter, "-w", pcap_base_file]
                 logger.info(f"Starting packet capture command: {' '.join(tshark_cmd)}")
                 if args.capture_interface == 'any': logger.info("Interface 'any' may require root/admin privileges.")

                 tshark_process = subprocess.Popen(
                     tshark_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
                 )
                 time.sleep(TSHARK_STARTUP_WAIT_SEC)
                 if tshark_process.poll() is not None:
                     stderr_output = tshark_process.stderr.read() if tshark_process.stderr else ""
                     logger.error(f"tshark process terminated unexpectedly shortly after start (exit code: {tshark_process.returncode}).")
                     logger.error(f"Check permissions, interface name ('{args.capture_interface}'), filter syntax ('{bpf_filter}'), or tshark installation.")
                     if stderr_output: logger.error(f"tshark stderr: {stderr_output.strip()}")
                     tshark_process = None
                     tshark_failed_to_start = True
                 else:
                     logger.info("tshark process appears to have started successfully.")

            except Exception as e:
                 logger.error(f"Failed to start tshark process: {e}. Capture disabled.", exc_info=args.debug)
                 if tshark_process and tshark_process.poll() is None: tshark_process.kill()
                 tshark_process = None
                 tshark_failed_to_start = True

    # --- Main Client Logic ---
    client: SiprecTester | None = None
    stream_threads: list[threading.Thread] = []
    stop_stream_event = threading.Event()
    exit_code = 0

    try:
        if tshark_failed_to_start:
            raise RuntimeError("Packet capture process (tshark) failed to start. Aborting test.")

        # Instantiate and connect the SIP client
        client = SiprecTester(args)
        client.connect()

        # --- OPTIONS Pings ---
        if args.options_ping_count > 0:
            # ... (OPTIONS ping logic remains the same)
            logger.info(f"Starting OPTIONS ping sequence: {args.options_ping_count} pings requested.")
            ping_success = True
            for i in range(args.options_ping_count):
                 if i > 0:
                    logger.info(f"Waiting {OPTIONS_PING_DELAY} seconds...")
                    time.sleep(OPTIONS_PING_DELAY)
                 ping_number = i + 1
                 logger.info(f"Sending OPTIONS ping {ping_number}/{args.options_ping_count}...")
                 if not client or not client.ssl_sock:
                      logger.error(f"Connection lost before sending OPTIONS ping {ping_number}. Aborting sequence.")
                      ping_success = False
                      break
                 if not client.send_options():
                     logger.error(f"OPTIONS ping {ping_number}/{args.options_ping_count} failed.")
                     ping_success = False
                 else:
                      logger.info(f"OPTIONS ping {ping_number}/{args.options_ping_count} successful.")
            if not ping_success and (not client or not client.ssl_sock):
                raise ConnectionError("Connection lost during OPTIONS ping sequence.")
            elif not ping_success:
                 logger.warning("One or more OPTIONS pings failed, but connection seems alive. Proceeding with INVITE.")
            else:
                 logger.info("OPTIONS ping sequence finished.")

        # --- Send INVITE and Handle Response ---
        if not client or not client.ssl_sock: raise ConnectionError("Connection lost before sending INVITE.")
        logger.info("Proceeding to send INVITE...")
        # send_invite now returns True only on 2xx success and sets client.dialog_established
        invite_successful = client.send_invite()
        invite_cseq = client.cseq - 1 # CSeq used for the INVITE

        # Only proceed with ACK and streaming if INVITE was successful (2xx received and processed)
        if invite_successful:
            logger.info("INVITE successful (received 2xx), sending ACK.")
            if not client.send_ack(invite_cseq):
                logger.error("Failed to send ACK after successful INVITE. Session might be unstable.")
                # Consider if ACK failure should prevent BYE? Let's allow BYE attempt anyway.
                exit_code = 1

            # --- Attempt Media Streaming ---
            if args.audio_file:
                # ... (Streaming setup and execution logic remains the same)
                logger.info(f"Audio file specified ({args.audio_file}). Preparing SRTP media streaming...")
                sdp_answer_info = client.last_invite_response_sdp_info

                if len(sdp_answer_info) < 2:
                    logger.error(f"Expected at least 2 valid media streams in SDP answer, found {len(sdp_answer_info)}. Cannot stream.")
                    exit_code = 1
                else:
                    try:
                        valid_audio_streams = [info for info in sdp_answer_info if info.media_type == 'audio']
                        if len(valid_audio_streams) < 2:
                             raise ValueError(f"Found only {len(valid_audio_streams)} usable audio streams in SDP answer.")

                        stream_info_1 = next((info for info in valid_audio_streams if info.label == '1'), None)
                        stream_info_2 = next((info for info in valid_audio_streams if info.label == '2'), None)
                        if stream_info_1 is None: stream_info_1 = valid_audio_streams[0]
                        if stream_info_2 is None:
                            potential_s2 = valid_audio_streams[1] if len(valid_audio_streams)>1 else None
                            stream_info_2 = potential_s2 if potential_s2 is not stream_info_1 else None
                        if stream_info_1 is None or stream_info_2 is None or stream_info_1 is stream_info_2:
                            raise ValueError("Could not determine two distinct audio streams from SDP answer.")

                        logger.info(f"Stream 1 mapped to SDP Answer: Port={stream_info_1.port}, Label='{stream_info_1.label}', Target={stream_info_1.connection_ip}")
                        logger.info(f"Stream 2 mapped to SDP Answer: Port={stream_info_2.port}, Label='{stream_info_2.label}', Target={stream_info_2.connection_ip}")

                        if not all([stream_info_1.connection_ip, stream_info_1.port > 0, stream_info_1.crypto_key_material, stream_info_1.crypto_suite,
                                    stream_info_2.connection_ip, stream_info_2.port > 0, stream_info_2.crypto_key_material, stream_info_2.crypto_suite]):
                             raise ValueError("Missing required IP, Port, or Crypto Key information in parsed SDP answer streams.")

                        parts = args.audio_encoding.split('/')
                        codec_name = parts[0].strip().upper()
                        sample_rate = int(parts[1].strip())
                        payload_type = AUDIO_ENCODING_TO_PAYLOAD_TYPE.get(codec_name)
                        if payload_type is None: raise ValueError(f"Internal error: Codec PT lookup failed for {codec_name}")

                        policy1 = pylibsrtp.Policy(key=stream_info_1.crypto_key_material, ssrc_type=pylibsrtp.Policy.SSRC_ANY_OUTBOUND)
                        srtp_session1 = pylibsrtp.Session(policy=policy1)
                        logger.info(f"Created SRTP context 1 for target {stream_info_1.connection_ip}:{stream_info_1.port} (Suite: {stream_info_1.crypto_suite})")

                        policy2 = pylibsrtp.Policy(key=stream_info_2.crypto_key_material, ssrc_type=pylibsrtp.Policy.SSRC_ANY_OUTBOUND)
                        srtp_session2 = pylibsrtp.Session(policy=policy2)
                        logger.info(f"Created SRTP context 2 for target {stream_info_2.connection_ip}:{stream_info_2.port} (Suite: {stream_info_2.crypto_suite})")

                        local_rtp_port1 = DEFAULT_SDP_AUDIO_PORT_BASE
                        local_rtp_port2 = DEFAULT_SDP_AUDIO_PORT_BASE + 2

                        thread1 = threading.Thread(
                            target=stream_channel,
                            args=(0, args.audio_file, stream_info_1.connection_ip, stream_info_1.port,
                                  payload_type, codec_name, sample_rate, args.packet_time,
                                  srtp_session1, local_rtp_port1, stop_stream_event, args.stream_duration),
                            daemon=True, name="Streamer-0"
                        )
                        thread2 = threading.Thread(
                            target=stream_channel,
                            args=(1, args.audio_file, stream_info_2.connection_ip, stream_info_2.port,
                                  payload_type, codec_name, sample_rate, args.packet_time,
                                  srtp_session2, local_rtp_port2, stop_stream_event, args.stream_duration),
                            daemon=True, name="Streamer-1"
                        )
                        stream_threads.extend([thread1, thread2])

                        logger.info("Starting media streaming threads...")
                        thread1.start()
                        thread2.start()

                        logger.info("Streaming in progress. Press Ctrl+C to stop early.")
                        start_wait = time.monotonic()
                        while any(t.is_alive() for t in stream_threads):
                             if stop_stream_event.is_set():
                                  logger.warning("Stop event detected during wait loop, likely due to thread error.")
                                  exit_code = 1
                                  break
                             if args.stream_duration > 0 and (time.monotonic() - start_wait > args.stream_duration + 2.0):
                                  logger.info(f"Maximum stream duration ({args.stream_duration}s) elapsed. Signaling threads to stop.")
                                  stop_stream_event.set()
                                  break
                             time.sleep(0.5)

                        logger.info("Streaming wait loop finished.")
                        if not stop_stream_event.is_set() and not any(t.is_alive() for t in stream_threads):
                             logger.info("Streaming threads appear to have completed normally.")

                    except (ValueError, pylibsrtp.Error, Exception) as stream_setup_err:
                        logger.error(f"Failed to setup or start media streaming: {stream_setup_err}", exc_info=args.debug)
                        exit_code = 1
                        stop_stream_event.set() # Signal stop

            else: # No audio file specified, but INVITE was successful
                logger.info("No audio file specified (--audio-file), skipping media streaming.")
                logger.info("Holding connection open for 2 seconds before sending BYE...")
                time.sleep(2)

        # Handle INVITE failure cases (non-2xx final response or critical error during processing)
        else:
             logger.error(f"INVITE failed or did not result in a usable session (Last Status: {client.last_invite_response_status}). ACK/Streaming skipped.")
             exit_code = 1
             # No BYE should be sent here as dialog wasn't established

    # --- Exception Handling & Cleanup ---
    except (ConnectionError, socket.gaierror, socket.timeout, ssl.SSLError, OSError, RuntimeError, ValueError) as e:
         logger.error(f"Execution Error: {e}", exc_info=args.debug)
         exit_code = 1
         stop_stream_event.set()
    except KeyboardInterrupt:
         logger.info("Keyboard interrupt detected. Signaling stop and cleaning up...")
         stop_stream_event.set()
         exit_code = 2
    except Exception as e:
        logger.exception(f"An unexpected critical error occurred: {e}")
        stop_stream_event.set()
        exit_code = 1
    finally:
        # --- Cleanup ---
        # Ensure streaming threads are signaled to stop
        if not stop_stream_event.is_set():
            logger.debug("Signaling potentially running stream threads to stop during final cleanup.")
            stop_stream_event.set()

        # Wait briefly for streaming threads (best effort)
        if stream_threads:
            logger.debug("Waiting briefly (up to 1s) for streaming threads...")
            join_timeout = 1.0
            start_join = time.monotonic()
            for t in stream_threads:
                remaining_time = join_timeout - (time.monotonic() - start_join)
                if remaining_time > 0:
                    try: t.join(timeout=remaining_time)
                    except Exception: pass
                # else: break # No more time left
            alive_threads = [t.name for t in stream_threads if t.is_alive()]
            if alive_threads: logger.warning(f"Threads still alive after cleanup wait: {alive_threads}")

        # --- Attempt to send BYE before closing connection ---
        if client and client.dialog_established:
            logger.info("Attempting to send BYE before closing connection...")
            try:
                # send_bye() will log its own success/failure
                client.send_bye()
            except Exception as bye_err:
                 # Catch unexpected errors during the BYE attempt itself
                 logger.error(f"Unexpected error occurred during send_bye(): {bye_err}", exc_info=args.debug)
            # Proceed to close connection regardless of BYE success
        elif client:
             logger.debug("Skipping BYE attempt (dialog was not established).")

        # Close SIP connection
        if client:
            logger.info("Closing client SIP connection...")
            client.close() # This also sets client.dialog_established to False

        # Stop packet capture (tshark process)
        if tshark_process and tshark_process.poll() is None:
            # ... (tshark stopping logic remains the same)
            logger.info(f"Stopping tshark process (PID: {tshark_process.pid})...")
            try:
                tshark_process.terminate()
                try:
                    tshark_process.wait(timeout=TSHARK_TERMINATE_TIMEOUT_SEC)
                    logger.info(f"tshark process terminated gracefully (exit code: {tshark_process.returncode}).")
                except subprocess.TimeoutExpired:
                    logger.warning(f"tshark did not terminate within {TSHARK_TERMINATE_TIMEOUT_SEC}s, sending KILL signal.")
                    tshark_process.kill()
                    try: tshark_process.wait(timeout=2.0)
                    except subprocess.TimeoutExpired: logger.error("tshark process did not respond to KILL signal.")
                logger.debug("Waiting briefly for capture file to finalize...")
                time.sleep(1.0)
                logger.info(f"Packet capture stopped. Raw output should be in '{pcap_base_file}'")
            except Exception as e:
                logger.error(f"Error stopping tshark process: {e}")
        elif tshark_process:
            logger.warning(f"tshark process (PID: {tshark_process.pid}) was found already terminated before cleanup (exit code: {tshark_process.returncode}). Capture might be incomplete.")
        elif args.pcap_file and not tshark_failed_to_start:
             logger.warning("Capture file was requested, tshark didn't fail start, but process object is missing at cleanup.")


        # --- Attempt to inject keys using editcap ---
        if args.pcap_file and not tshark_failed_to_start and pcap_decrypted_file:
             # ... (editcap logic remains the same)
            logger.info(f"Attempting to inject TLS keys into pcap file using editcap...")
            editcap_path = shutil.which("editcap")
            if not editcap_path:
                logger.error("'editcap' executable not found in system PATH. Cannot inject keys.")
            elif not os.path.exists(pcap_base_file):
                 logger.error(f"Cannot inject keys: Raw pcap file '{pcap_base_file}' not found or not created.")
            elif not ssl_key_log_file_path or not os.path.exists(ssl_key_log_file_path):
                 logger.error(f"Cannot inject keys: SSLKEYLOGFILE '{ssl_key_log_file_path}' not found.")
            elif os.path.getsize(pcap_base_file) == 0:
                 logger.warning(f"Raw pcap file '{pcap_base_file}' is empty. Skipping key injection.")
            else:
                 cmd = [editcap_path, "--inject-secrets", f"tls,{ssl_key_log_file_path}", pcap_base_file, pcap_decrypted_file]
                 logger.debug(f"Running command: {' '.join(cmd)}")
                 try:
                     result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
                     logger.info(f"Successfully injected keys into '{pcap_decrypted_file}'")
                     if result.stdout: logger.debug(f"editcap stdout:\n{result.stdout.strip()}")
                     if result.stderr: logger.debug(f"editcap stderr:\n{result.stderr.strip()}")
                 except FileNotFoundError:
                     logger.error(f"Error running editcap: Command not found at '{editcap_path}'.")
                 except subprocess.CalledProcessError as e:
                     logger.error(f"editcap command failed with exit code {e.returncode}:")
                     if e.stdout: logger.error(f"  stdout: {e.stdout.strip()}")
                     if e.stderr: logger.error(f"  stderr: {e.stderr.strip()}")
                     logger.error(f"Failed to create decrypted pcap file '{pcap_decrypted_file}'.")
                 except subprocess.TimeoutExpired:
                     logger.error(f"editcap command timed out after 30 seconds.")
                 except Exception as e:
                     logger.error(f"An unexpected error occurred while running editcap: {e}", exc_info=args.debug)
        elif args.pcap_file and ssl_key_log_file_path and not pcap_decrypted_file:
             logger.warning("Capture ran and SSLKEYLOGFILE was set, but conditions for key injection not fully met. Skipping.")
        elif args.pcap_file and not ssl_key_log_file_path:
             logger.info("SSLKEYLOGFILE not set, skipping key injection step.")


        logger.info(f"SIPREC client finished with exit code {exit_code}.")
        sys.exit(exit_code)


if __name__ == "__main__":
    if sys.version_info < (3, 8):
         print("Error: This script requires Python 3.8 or later for some features.", file=sys.stderr)
         sys.exit(1)
    main()