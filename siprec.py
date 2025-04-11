#!/usr/env/ python3
# -*- coding: utf-8 -*-

"""
A Python command-line client for testing SIPREC (RFC 7865) servers using TLS,
including SRTP media streaming from a 2-channel audio file using SDES keys
parsed from the server's SDP answer. Uses 'pylibsrtp'.

Allows selection of SRTP encryption profile or disabling encryption (plain RTP).

Relies on 'soundfile' library for reliable G.711 (PCMA/PCMU) encoding.

This script:
1. Establishes a TLS connection to a SIPREC SRS.
2. Optionally sends OPTIONS pings.
3. Sends a SIP INVITE with SDP offer (including client crypto attributes or offering plain RTP)
   and SIPREC metadata (offering media labels "1" and "2").
4. Handles the SIP response (1xx, 2xx).
5. If INVITE succeeds (2xx), sends an ACK.
6. Parses the server's SDP answer (from 200 OK) to get destination RTP IP/ports
   and potentially the SRTP SDES keys the server expects (if SAVP is negotiated).
7. Crucially, it extracts the 'a=label:' values from the server's SDP answer.
8. If an audio file is provided, finds the SDP media descriptions corresponding
   to the labels offered in the client's metadata (expects "1" and "2") and
   starts two threads for RTP/SRTP streaming based on negotiation.
9. Optionally saves the original *unencrypted* encoded audio payload (PCMA/PCMU)
   for each stream to separate WAV files, complete with headers, associating
   them based on the parsed SDP labels.
10. Waits for streaming to finish (file end or specified duration) or Ctrl+C.
11. Attempts to send a SIP BYE request if the INVITE was successful.
12. Closes the connection.

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

Example Usage (Streaming SRTP with Default Cipher, Capture, BYE, and Saving Streams as WAV):
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
      --pcap-file /tmp/siprec_capture.pcapng \\
      --save-stream1-file /tmp/stream1_caller.wav \\
      --save-stream2-file /tmp/stream2_callee.wav \\
      --debug

Example Usage (Streaming Plain RTP, No Encryption, Saving Streams as WAV):
  python siprec_client_streamer_pylibsrtp.py \\
      rec-target@domain srs.domain.tld \\
      --src-number client@client.domain.tld \\
      --src-host 1.2.3.4 \\
      --cert-file client.crt \\
      --key-file client.key \\
      --ca-file ca.crt \\
      --audio-file /path/to/audio.wav \\
      --srtp-encryption NONE \\
      --save-stream1-file /tmp/stream1_caller_rtp.wav \\
      --save-stream2-file /tmp/stream2_callee_rtp.wav
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
from collections import namedtuple
import io
from typing import Union, Any # Using built-in types (list, dict, etc.) and Union (X | Y)

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
# Using collections.namedtuple as in the original code for consistency
SdpMediaInfo = namedtuple("SdpMediaInfo", [
    "media_type", # str: e.g., "audio"
    "port",       # int
    "protocol",   # str: e.g., "RTP/SAVP" or "RTP/AVP"
    "payload_types", # list[int]
    "connection_ip", # str | None
    "label",         # str | None
    "crypto_suite",  # str | None (Only relevant if protocol is RTP/SAVP)
    "crypto_key_material", # bytes | None (Only relevant if protocol is RTP/SAVP)
    "rtpmap" # dict[int, tuple[str, int]] : {pt: (encoding_name, rate)}
    ]
)


# --- Constants ---
LOG_FORMAT: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
SIP_VERSION: str = "SIP/2.0"
DEFAULT_SIPS_PORT: int = 5061
DEFAULT_MAX_FORWARDS: int = 70
VIA_BRANCH_PREFIX: str = "z9hG4bK"
USER_AGENT: str = "PythonSIPRECStreamer/2.11" # Version number updated for refactor
DEFAULT_SDP_AUDIO_PORT_BASE: int = 16000 # Local port base for *offering*
CRLF: str = "\r\n"
CRLF_BYTES: bytes = b"\r\n"
DTMF_PAYLOAD_TYPE: int = 100 # Common payload type for telephone-event
DEFAULT_AUDIO_ENCODING: str = "PCMA/8000"
TSHARK_STARTUP_WAIT_SEC: float = 2.0
TSHARK_TERMINATE_TIMEOUT_SEC: float = 5.0
DEFAULT_PACKET_TIME_MS: int = 20
OPTIONS_PING_DELAY_SEC: float = 10.0
BYE_RESPONSE_TIMEOUT_SEC: float = 2.0 # Timeout waiting for 200 OK to BYE
RTP_HEADER_LENGTH: int = 12 # Standard RTP header length without CSRCs
WAV_HEADER_SIZE: int = 44 # Standard size for PCM/G711 WAV header
MAX_HEADER_BUFFER_SIZE: int = 16384 # Safeguard for receive buffer

# Supported SRTP cipher suites (align with pylibsrtp capabilities for SDES)
SUPPORTED_SRTP_CIPHERS_SDES: list[str] = [
    "AES_CM_128_HMAC_SHA1_80",
    "AES_CM_128_HMAC_SHA1_32",
]
# Add NONE as a special value for the choice
SRTP_ENCRYPTION_CHOICES: list[str] = SUPPORTED_SRTP_CIPHERS_SDES + ["NONE"]
DEFAULT_SRTP_ENCRYPTION: str = "AES_CM_128_HMAC_SHA1_80"

# Mapping from common audio encoding names (uppercase) to RTP payload types
AUDIO_ENCODING_TO_PAYLOAD_TYPE: dict[str, int] = {
    "PCMU": 0, "G711U": 0,
    "PCMA": 8, "G711A": 8,
    "G722": 9,
    "G729": 18,
}

# Mapping from common audio encoding names (uppercase) to WAV format codes
AUDIO_ENCODING_TO_WAV_FORMAT_CODE: dict[str, int] = {
    "PCMU": 7, "G711U": 7, # WAVE_FORMAT_MULAW
    "PCMA": 6, "G711A": 6, # WAVE_FORMAT_ALAW
}

# Mapping from SDP suite names to pylibsrtp constants
SDP_SUITE_TO_PYLIBSRTP_PROFILE: dict[str, int] = {
    "AES_CM_128_HMAC_SHA1_80": pylibsrtp.Policy.SRTP_PROFILE_AES128_CM_SHA1_80,
    "AES_CM_128_HMAC_SHA1_32": pylibsrtp.Policy.SRTP_PROFILE_AES128_CM_SHA1_32,
}

# Packet Capture Defaults (Based on Google Cloud Telephony example)
DEFAULT_CAPTURE_SIP_RANGE: str = "74.125.88.128/25"
DEFAULT_CAPTURE_SIP_PORT: int = 5672
DEFAULT_CAPTURE_MEDIA_RANGE: str = "74.125.39.0/24"

# *** Client-offered labels ***
# These are the labels the client PUTS in its SDP offer and metadata
# and expects the server to use in its SDP answer.
CLIENT_OFFERED_LABEL_1: str = "1"
CLIENT_OFFERED_LABEL_2: str = "2"

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger: logging.Logger = logging.getLogger("siprec_streamer")
logger.setLevel(logging.INFO)
encoder_logger: logging.Logger = logging.getLogger("siprec_streamer.encoder")
encoder_logger.setLevel(logging.INFO)

# --- Reliable G.711 Encoding using soundfile ---

def encode_audio_segment(samples: np.ndarray, codec_name: str, sample_rate: int) -> bytes:
    """
    Encodes linear 16-bit PCM samples to the specified codec (PCMA/ALAW, PCMU/ULAW)
    using the soundfile library.

    Args:
        samples: NumPy array of dtype int16 audio samples.
        codec_name: The target codec name ("PCMA" or "PCMU").
        sample_rate: The audio sample rate (e.g., 8000).

    Returns:
        Bytes representing the encoded audio payload (header-less).

    Raises:
        ValueError: If the codec_name is unsupported or samples invalid.
        TypeError: If input samples cannot be converted to int16.
        sf.SoundFileError: If soundfile encounters an encoding error.
    """
    if samples.dtype != np.int16:
        try:
            if np.issubdtype(samples.dtype, np.floating):
                encoder_logger.debug("Input samples were float, scaling to int16 for encoding.")
                samples = (samples * 32767).astype(np.int16)
            else:
                encoder_logger.warning(f"Input samples were {samples.dtype}, attempting conversion to int16 for encoding.")
                samples = samples.astype(np.int16)
        except ValueError:
            encoder_logger.error("Input samples could not be converted to int16 for encoding.")
            raise TypeError("Input samples must be convertible to int16")
        except Exception as conv_err:
            encoder_logger.error(f"Unexpected error converting samples to int16: {conv_err}")
            raise TypeError(f"Could not convert samples to int16: {conv_err}")

    codec_name_upper = codec_name.upper()
    audio_format = "RAW"
    subtype: str | None = None

    if codec_name_upper in ("PCMA", "G711A"):
        subtype = "ALAW"
    elif codec_name_upper in ("PCMU", "G711U"):
        subtype = "ULAW"
    else:
        encoder_logger.error(f"Unsupported codec for soundfile encoding: {codec_name}")
        raise ValueError(f"Unsupported codec for encoding: {codec_name}")

    if not sf.check_format(audio_format, subtype):
         encoder_logger.error(f"Soundfile library does not support format='{audio_format}', subtype='{subtype}' combination.")
         raise ValueError(f"Invalid soundfile format/subtype combination: {audio_format}/{subtype}")

    buffer = io.BytesIO()
    try:
        sf.write(buffer, samples, sample_rate, format=audio_format, subtype=subtype)
        encoded_data = buffer.getvalue()
        # encoder_logger.debug(f"Encoded {len(samples)} samples to {len(encoded_data)} bytes using {codec_name}")
        return encoded_data
    except sf.SoundFileError as e:
        encoder_logger.error(f"Soundfile error encoding to {codec_name} ({audio_format}/{subtype}): {e}")
        raise
    except Exception as e:
        encoder_logger.exception(f"Unexpected error during soundfile encoding: {e}")
        raise


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
    """
    Resolves a hostname to an IPv4 address.

    Args:
        hostname: The hostname to resolve.

    Returns:
        The resolved IPv4 address as a string.

    Raises:
        ValueError: If the hostname cannot be resolved or another error occurs.
    """
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

def create_sdp_offer(
        local_ip: str,
        local_port_base: int,
        audio_encoding_str: str,
        packet_time_ms: int,
        srtp_encryption_choice: str
        ) -> str:
    """
    Creates the initial SDP OFFER (client's view).

    Includes crypto attributes based on srtp_encryption_choice.
    Uses RTP/SAVP if encryption is chosen, RTP/AVP otherwise.
    Uses CLIENT_OFFERED_LABEL_1 and CLIENT_OFFERED_LABEL_2 for a=label.

    Args:
        local_ip: The local IP address to advertise in SDP.
        local_port_base: The base local UDP port for the first media stream.
        audio_encoding_str: The audio encoding string (e.g., "PCMA/8000").
        packet_time_ms: The desired packetization time in milliseconds.
        srtp_encryption_choice: The SRTP encryption profile name or "NONE".

    Returns:
        The SDP offer as a multi-line string.

    Raises:
        ValueError: If the SRTP encryption choice is invalid.
    """
    encoding_name: str = ""
    sample_rate: int = 0
    payload_type: int | None = None
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

    offer_crypto_line: str | None = None
    sdp_protocol: str = "RTP/AVP" # Default to no encryption

    if srtp_encryption_choice.upper() != "NONE":
        if srtp_encryption_choice not in SUPPORTED_SRTP_CIPHERS_SDES:
            logger.error(f"Unsupported SRTP encryption choice '{srtp_encryption_choice}'. Supported: {SUPPORTED_SRTP_CIPHERS_SDES}. Aborting SDP generation.")
            raise ValueError(f"Unsupported SRTP encryption choice: {srtp_encryption_choice}")

        sdp_protocol = "RTP/SAVP" # Secure RTP
        random_key_salt = base64.b64encode(os.urandom(30)).decode('ascii') # 16 byte key + 14 byte salt
        offer_crypto_line = f"a=crypto:1 {srtp_encryption_choice} inline:{random_key_salt}"
        logger.info(f"Offering SRTP with encryption: {srtp_encryption_choice} (Protocol: {sdp_protocol})")
    else:
        logger.info(f"Offering plain RTP (No encryption) (Protocol: {sdp_protocol})")

    logger.info(f"Creating SDP Offer with: {encoding_name}/{sample_rate} (Payload Type: {payload_type}), DTMF PT: {DTMF_PAYLOAD_TYPE}, PTime: {packet_time_ms}ms")
    logger.info(f"SDP Offer will use labels: {CLIENT_OFFERED_LABEL_1} and {CLIENT_OFFERED_LABEL_2}")

    sdp_lines = [
        "v=0",
        f"o=PythonSIPClient {int(time.time())} {int(time.time())+1} IN IP4 {local_ip}",
        "s=SIPREC Test Call Stream",
        "t=0 0",
        # --- Media Stream 1 (Label CLIENT_OFFERED_LABEL_1) ---
        f"m=audio {local_port_base} {sdp_protocol} {payload_type} {DTMF_PAYLOAD_TYPE}",
        f"c=IN IP4 {local_ip}",
        f"a=label:{CLIENT_OFFERED_LABEL_1}",
    ]
    if offer_crypto_line:
        sdp_lines.append(offer_crypto_line)
    sdp_lines.extend([
        f"a=rtpmap:{payload_type} {encoding_name}/{sample_rate}",
        f"a=rtpmap:{DTMF_PAYLOAD_TYPE} telephone-event/{sample_rate}",
        f"a=fmtp:{DTMF_PAYLOAD_TYPE} 0-15",
        "a=sendonly",
        f"a=maxptime:{packet_time_ms}",
        # --- Media Stream 2 (Label CLIENT_OFFERED_LABEL_2) ---
        f"m=audio {local_port_base+2} {sdp_protocol} {payload_type} {DTMF_PAYLOAD_TYPE}",
        f"c=IN IP4 {local_ip}",
        f"a=label:{CLIENT_OFFERED_LABEL_2}",
    ])
    if offer_crypto_line:
        sdp_lines.append(offer_crypto_line)
    sdp_lines.extend([
        f"a=rtpmap:{payload_type} {encoding_name}/{sample_rate}",
        f"a=rtpmap:{DTMF_PAYLOAD_TYPE} telephone-event/{sample_rate}",
        f"a=fmtp:{DTMF_PAYLOAD_TYPE} 0-15",
        "a=sendonly",
        f"a=maxptime:{packet_time_ms}",
        "" # Add trailing empty line before joining
    ])

    return CRLF.join(sdp_lines)


def parse_sdp_answer(sdp_body: bytes) -> list[SdpMediaInfo]:
    """
    Parses the SDP answer (from 200 OK) to extract media line details.

    Handles both RTP/AVP and RTP/SAVP protocols.
    Captures the 'a=label:' attribute. Extracts crypto details if SAVP.

    Args:
        sdp_body: The raw bytes of the SDP body.

    Returns:
        A list of SdpMediaInfo named tuples representing valid media descriptions.
        Returns an empty list if parsing fails or no valid descriptions are found.
    """
    media_info_list: list[SdpMediaInfo] = []
    global_ip: str | None = None
    current_media_dict: dict[str, Any] | None = None

    try:
        sdp_str = sdp_body.decode('utf-8', errors='ignore')
        lines = sdp_str.splitlines()

        # First pass for session-level connection line
        for line in lines:
            line = line.strip()
            if line.startswith("c=IN IP4 "):
                global_ip = line.split()[-1]
                logger.debug(f"SDP Answer: Found global connection IP: {global_ip}")
                # Continue processing other session-level attributes

        # Second pass for media descriptions
        for line in lines:
            line = line.strip()
            if line.startswith("m="):
                # Finalize the previous media description
                if current_media_dict:
                     try:
                         current_media_dict.setdefault("rtpmap", {}) # Ensure rtpmap exists
                         media_info_list.append(SdpMediaInfo(**current_media_dict))
                     except TypeError as te:
                          logger.error(f"Failed to finalize SdpMediaInfo: {te}. Data: {current_media_dict}")
                     current_media_dict = None # Reset

                parts = line.split()
                if len(parts) >= 4 and parts[0] == "m=audio":
                    try:
                        protocol = parts[2]
                        if protocol not in ("RTP/AVP", "RTP/SAVP"):
                            logger.warning(f"SDP Answer: Unexpected media protocol '{protocol}' in m= line: {line}. Skipping.")
                            continue

                        current_media_dict = {
                            "media_type": parts[0][2:],
                            "port": int(parts[1]),
                            "protocol": protocol,
                            "payload_types": [int(pt) for pt in parts[3:] if pt.isdigit()],
                            "connection_ip": global_ip, # Start with global IP
                            "label": None,
                            "crypto_suite": None,
                            "crypto_key_material": None,
                            "rtpmap": {}
                        }
                        logger.debug(f"SDP Answer: Found m= line: Port={current_media_dict['port']}, Proto={current_media_dict['protocol']}, PTs={current_media_dict['payload_types']}")
                    except (ValueError, IndexError):
                        logger.warning(f"SDP Answer: Could not parse m= line details: {line}")
                        current_media_dict = None
                else:
                    current_media_dict = None # Not a valid audio line

            # Process attributes only if we have a current media description
            elif current_media_dict:
                if line.startswith("c=IN IP4 "):
                    current_media_dict["connection_ip"] = line.split()[-1]
                    logger.debug(f"SDP Answer: Found media-specific IP for port {current_media_dict['port']}: {current_media_dict['connection_ip']}")

                elif line.startswith("a=label:"):
                     current_media_dict["label"] = line.split(":", 1)[1].strip()
                     logger.debug(f"SDP Answer: Found label for port {current_media_dict['port']}: {current_media_dict['label']}")

                elif line.startswith("a=rtpmap:"):
                     try:
                          rtpmap_parts = line.split(":", 1)[1].split(maxsplit=1)
                          pt = int(rtpmap_parts[0])
                          name_rate_parts = rtpmap_parts[1].split('/')
                          name = name_rate_parts[0]
                          rate = int(name_rate_parts[1])
                          if pt in current_media_dict["payload_types"]:
                                current_media_dict["rtpmap"][pt] = (name, rate)
                                logger.debug(f"SDP Answer: Found rtpmap for port {current_media_dict['port']}: PT={pt}, Name={name}, Rate={rate}")
                     except (ValueError, IndexError, TypeError):
                          logger.warning(f"SDP Answer: Could not parse rtpmap line: {line}")

                elif line.startswith("a=crypto:") and current_media_dict["protocol"] == "RTP/SAVP":
                    crypto_parts = line.split()
                    if len(crypto_parts) >= 3 and crypto_parts[2].startswith("inline:"):
                        tag = crypto_parts[0].split(':')[1]
                        suite = crypto_parts[1]
                        key_b64 = crypto_parts[2].split(':', 1)[1]

                        if suite in SUPPORTED_SRTP_CIPHERS_SDES:
                            try:
                                key_material = base64.b64decode(key_b64)
                                expected_len = 30 # AES_CM_128_HMAC_SHA1_* requires 16 key + 14 salt
                                if len(key_material) == expected_len:
                                    # Store the first valid crypto line
                                    if current_media_dict.get("crypto_suite") is None:
                                        current_media_dict["crypto_suite"] = suite
                                        current_media_dict["crypto_key_material"] = key_material
                                        logger.info(f"SDP Answer: Parsed valid crypto for port {current_media_dict['port']} (Label:'{current_media_dict.get('label','N/A')}', Tag:{tag}): Suite={suite}, KeyLen={len(key_material)}")
                                    else:
                                         logger.debug(f"SDP Answer: Ignoring additional crypto line for port {current_media_dict['port']}.")
                                else:
                                    logger.warning(f"SDP Answer: Crypto key length mismatch for port {current_media_dict['port']} (Label:'{current_media_dict.get('label','N/A')}', Suite:{suite}). Expected {expected_len}, got {len(key_material)}. Line: {line}")
                            except (base64.binascii.Error, ValueError) as e:
                                logger.warning(f"SDP Answer: Error decoding base64 key for port {current_media_dict['port']} (Label:'{current_media_dict.get('label','N/A')}'): {e}. Line: {line}")
                        else:
                             logger.warning(f"SDP Answer: Server offered unsupported crypto suite for port {current_media_dict['port']} (Label:'{current_media_dict.get('label','N/A')}'): {suite}. Line: {line}")
                    else:
                        logger.warning(f"SDP Answer: Could not parse crypto line format for port {current_media_dict['port']} (Label:'{current_media_dict.get('label','N/A')}'): {line}")
                elif line.startswith("a=crypto:") and current_media_dict["protocol"] == "RTP/AVP":
                     logger.warning(f"SDP Answer: Ignoring crypto attribute for non-SAVP stream on port {current_media_dict['port']} (Label:'{current_media_dict.get('label','N/A')}'): {line}")

        # Append the last parsed media description
        if current_media_dict:
             try:
                 current_media_dict.setdefault("rtpmap", {})
                 media_info_list.append(SdpMediaInfo(**current_media_dict))
             except TypeError as te:
                  logger.error(f"Failed to finalize last SdpMediaInfo: {te}. Data: {current_media_dict}")

    except Exception as e:
        logger.exception(f"Error parsing SDP answer: {e}")

    # --- Validation of parsed streams ---
    valid_media_info: list[SdpMediaInfo] = []
    for info in media_info_list:
        is_savp = info.protocol == "RTP/SAVP"
        # Basic checks for usability
        if info.port <= 0:
            logger.warning(f"SDP Answer: Skipping media stream for label '{info.label}' (port is {info.port}).")
        elif not info.connection_ip:
             logger.warning(f"SDP Answer: Skipping media stream on port {info.port} (Label:'{info.label}') (no connection IP).")
        # If SAVP was negotiated, crypto material MUST be present and parsed correctly
        elif is_savp and not info.crypto_key_material:
             logger.warning(f"SDP Answer: Skipping media stream on port {info.port} (Label:'{info.label}') (RTP/SAVP negotiated but no valid/supported crypto key found/parsed).")
        else:
             valid_media_info.append(info)

    if not valid_media_info:
        logger.error("SDP Answer: Failed to parse any usable media descriptions from the server's response.")

    return valid_media_info

def create_siprec_metadata(config: argparse.Namespace, dest_number: str, dest_host: str) -> str:
    """
    Creates sample SIPREC metadata XML.

    Uses CLIENT_OFFERED_LABEL_1 and CLIENT_OFFERED_LABEL_2 for media_label.
    Parses Conversation ID and Project ID from Call-Info URL if provided.

    Args:
        config: The argparse namespace containing script configuration.
        dest_number: The destination number part of the AOR.
        dest_host: The destination host part of the AOR.

    Returns:
        The SIPREC metadata XML as a string with CRLF line endings.
    """
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    session_id = generate_call_id()
    conversation_id = f"PY_TEST_CONV_{uuid.uuid4().hex[:8]}" # Default
    project_id = "unknown-project" # Default

    if config.call_info_url:
        try:
            url_to_parse = config.call_info_url
            # Basic parsing attempt for Google CCAI URL format
            if 'CID-$(' in url_to_parse: # Handle unexpanded shell commands gracefully
                logger.warning("Call-Info URL seems to contain unexpanded shell command. Using placeholder conversation ID.")
                # Use placeholder to avoid errors, don't try to parse partial URL
            else:
                 if '/conversations/' in url_to_parse:
                     parts = url_to_parse.split('/conversations/')
                     if len(parts) > 1:
                         conversation_id = parts[1].split('/')[0].split('?')[0] # Get part after /conversations/, remove query params
                 if '/projects/' in url_to_parse:
                     parts = url_to_parse.split('/projects/')
                     if len(parts) > 1:
                          project_id = parts[1].split('/')[0]
            logger.debug(f"Parsed from Call-Info URL: Project='{project_id}', Conversation='{conversation_id}'")
        except Exception as e:
             logger.warning(f"Error parsing project/conversation from Call-Info URL ({config.call_info_url}): {e}. Using defaults.")

    metadata_template = f"""<?xml version="1.0" encoding="UTF-8"?>
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
  <stream stream_id="stream_label_1_{generate_tag()}" media_label="{CLIENT_OFFERED_LABEL_1}">
      <associate-time>{timestamp}</associate-time>
      <label>Caller_Stream</label>
  </stream>
    <stream stream_id="stream_label_2_{generate_tag()}" media_label="{CLIENT_OFFERED_LABEL_2}">
      <associate-time>{timestamp}</associate-time>
      <label>Callee_Stream</label>
  </stream>
  <extensiondata xmlns:google="http://google.com/siprec">
     <google:call id="{conversation_id}" project="{project_id}"/>
  </extensiondata>
</recording>
"""
    # Ensure correct line endings (CRLF) for SIP body part
    return metadata_template.replace('\r\n', '\n').replace('\n', CRLF)


def parse_sip_response(data: bytes) -> tuple[int | None, dict[str, Union[str, list[str]]], bytes]:
    """
    Parses a SIP response buffer into status code, headers, and body.

    Handles multi-line headers and potential decoding errors.

    Args:
        data: The raw bytes received from the socket.

    Returns:
        A tuple containing:
        - Status code (int) or None if parsing fails.
        - Dictionary of headers (keys are lowercase strings, values are strings or lists of strings).
        - Body as bytes.
    """
    headers: dict[str, Union[str, list[str]]] = {}
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

    # Parse Status Line (SIP/2.0 XXX Reason)
    status_line_match = re.match(rb'SIP/2.0\s+(\d{3})\s+(.*)', lines[0], re.IGNORECASE)
    if not status_line_match:
        logger.error(f"Could not parse status line: {lines[0].decode(errors='ignore')}")
        return None, {}, body
    try:
        status_code = int(status_line_match.group(1))
        headers['reason-phrase'] = status_line_match.group(2).decode(errors='ignore').strip()
    except (ValueError, IndexError):
        logger.error(f"Error parsing status code/reason from status line: {lines[0].decode(errors='ignore')}")
        return None, {}, body

    # Parse Headers
    current_key: str | None = None
    for line_bytes in lines[1:]:
        line_bytes = line_bytes.strip()
        if not line_bytes: continue

        # Handle header line continuations (starts with whitespace)
        if line_bytes.startswith((b' ', b'\t')):
            if current_key and current_key in headers:
                value_to_append = b' ' + line_bytes.strip()
                try:
                    current_value = headers[current_key]
                    decoded_append = value_to_append.decode(errors='ignore')
                    if isinstance(current_value, list):
                        headers[current_key][-1] += decoded_append
                    elif isinstance(current_value, str):
                        headers[current_key] = current_value + decoded_append
                except Exception as e:
                     logger.warning(f"Error appending continuation line to header '{current_key}': {e}")
            else:
                logger.warning(f"Ignoring continuation line with no preceding header: {line_bytes.decode(errors='ignore')}")
            continue

        # Handle normal header lines (Key: Value)
        try:
            key_bytes, value_bytes = line_bytes.split(b':', 1)
            key = key_bytes.strip().lower().decode(errors='ignore') # Lowercase key for consistency
            value = value_bytes.strip().decode(errors='ignore')
            current_key = key

            # Store header, handling multi-value headers (like Via)
            if key in headers:
                existing_value = headers[key]
                if isinstance(existing_value, list):
                    existing_value.append(value)
                else:
                    headers[key] = [existing_value, value] # Convert to list
            else:
                headers[key] = value
        except ValueError:
            logger.warning(f"Malformed header line (no colon?): {line_bytes.decode(errors='ignore')}")
            current_key = None
        except Exception as e:
            logger.warning(f"Error processing header line '{line_bytes.decode(errors='ignore')}': {e}")
            current_key = None

    return status_code, headers, body

# --- WAV Header Helper Functions ---
def write_wav_header(outfile: io.BufferedWriter, sample_rate: int, format_code: int) -> None:
    """
    Writes a standard 44-byte WAV header to the beginning of the output file.

    Uses placeholder values for file size and data chunk size, which must be
    updated later using update_wav_header.

    Args:
        outfile: The file object (opened in 'wb' mode) to write to.
        sample_rate: The audio sample rate (e.g., 8000).
        format_code: The WAV format code (6 for ALAW/PCMA, 7 for ULAW/PCMU).
    """
    num_channels: int = 1
    bits_per_sample: int = 8 # G.711 is 8-bit
    byte_rate: int = sample_rate * num_channels * bits_per_sample // 8
    block_align: int = num_channels * bits_per_sample // 8
    chunk_size_placeholder: int = 0 # Overall file size - 8
    data_size_placeholder: int = 0  # Size of the raw audio data

    outfile.seek(0) # Ensure writing starts at the beginning

    # RIFF chunk descriptor (12 bytes)
    outfile.write(b'RIFF')
    outfile.write(struct.pack('<I', chunk_size_placeholder)) # ChunkSize
    outfile.write(b'WAVE')

    # 'fmt ' sub-chunk (24 bytes)
    outfile.write(b'fmt ')
    outfile.write(struct.pack('<I', 16))                 # Subchunk1Size (16 for PCM/G711)
    outfile.write(struct.pack('<H', format_code))        # AudioFormat
    outfile.write(struct.pack('<H', num_channels))       # NumChannels
    outfile.write(struct.pack('<I', sample_rate))        # SampleRate
    outfile.write(struct.pack('<I', byte_rate))          # ByteRate
    outfile.write(struct.pack('<H', block_align))        # BlockAlign
    outfile.write(struct.pack('<H', bits_per_sample))    # BitsPerSample

    # 'data' sub-chunk (8 bytes)
    outfile.write(b'data')
    outfile.write(struct.pack('<I', data_size_placeholder)) # Subchunk2Size

    # Header is now 44 bytes long. File pointer is at byte 44.

def update_wav_header(outfile: io.BufferedWriter, header_size: int, data_bytes_written: int) -> None:
    """
    Updates the ChunkSize and Subchunk2Size fields in a WAV header.

    This should be called after all audio data has been written to the file.

    Args:
        outfile: The file object (opened in 'wb' mode).
        header_size: The size of the WAV header (e.g., 44 bytes).
        data_bytes_written: The total number of raw audio data bytes written.
    """
    if data_bytes_written <= 0:
        logger.warning(f"No data bytes written to '{outfile.name}'. Header update skipped.")
        return

    try:
        outfile.flush() # Ensure buffered data is physically written

        # Calculate final sizes
        # ChunkSize = Overall file size - 8 bytes (RIFF tag and ChunkSize field)
        chunk_size = header_size + data_bytes_written - 8
        # DataSize = Size of the raw audio data only
        data_size = data_bytes_written

        logger.debug(f"Updating WAV header for '{outfile.name}': ChunkSize={chunk_size}, DataSize={data_size}")

        # Seek to ChunkSize position (byte 4) and write the value (little-endian)
        outfile.seek(4)
        outfile.write(struct.pack('<I', chunk_size))

        # Seek to Subchunk2Size position (byte 40 for a 44-byte header) and write the value
        outfile.seek(header_size - 4) # Go to the start of the data size field
        outfile.write(struct.pack('<I', data_size))

        outfile.flush() # Ensure updates are written
        # Seek to end of file after update
        outfile.seek(header_size + data_bytes_written)

    except (IOError, struct.error, OSError) as e:
        logger.error(f"Error updating WAV header for '{outfile.name}': {e}")
    except Exception as e:
        logger.exception(f"Unexpected error updating WAV header for '{outfile.name}': {e}")

# --- Main SIP Client Class ---
class SiprecTester:
    """
    Manages the SIPREC test session including TLS connection, SIP messaging,
    dialog state, and interaction with media streaming.
    """
    def __init__(self, config: argparse.Namespace):
        """
        Initializes the SIPREC tester state.

        Args:
            config: The argparse namespace containing script configuration.

        Raises:
            ValueError: If the source host cannot be resolved.
        """
        self.config: argparse.Namespace = config
        try:
            self.local_ip: str = get_ip_by_name(config.src_host)
        except ValueError as e:
            logger.error(f"Cannot proceed: Failed to resolve source host '{config.src_host}': {e}")
            raise
        self.local_sip_port: int = int(config.local_port) if config.local_port else 0
        self.call_id: str = generate_call_id()
        self.from_tag: str = generate_tag()
        self.to_tag: str | None = None # Populated from 2xx response To header
        self.cseq: int = random.randint(1, 10000) # Current CSeq number to use (increments after sending non-ACK)
        self.sock: socket.socket | None = None
        self.ssl_sock: ssl.SSLSocket | None = None
        self._last_branch: str = "" # Via branch of the last non-ACK/BYE request (used for ACK)
        self.last_invite_offer_sdp: str | None = None
        self.last_invite_response_status: int | None = None
        self.last_invite_response_headers: dict[str, Union[str, list[str]]] = {}
        self.last_invite_response_body: bytes = b''
        self.last_invite_response_sdp_info: list[SdpMediaInfo] = []
        self.dialog_established: bool = False # True after INVITE 2xx processed, False on termination/failure

    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Creates an SSL context for TLS with client authentication.

        Reads certificate/key/CA paths from self.config.

        Returns:
            An initialized SSLContext object.

        Raises:
            ValueError: If certificate or key file paths are missing.
            FileNotFoundError: If certificate, key, or CA file is not found.
            ssl.SSLError: If there's an error loading certificates/keys.
            Exception: For other unexpected errors during context creation.
        """
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Client certificate and key are mandatory
        if not self.config.cert_file or not self.config.key_file:
            raise ValueError("Certificate and Key files must be specified (--cert-file, --key-file)")
        if not os.path.isfile(self.config.cert_file):
            raise FileNotFoundError(f"Certificate file not found: {self.config.cert_file}")
        if not os.path.isfile(self.config.key_file):
            raise FileNotFoundError(f"Key file not found: {self.config.key_file}")

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

        # CA file for server verification is optional but recommended
        if self.config.ca_file:
            if not os.path.isfile(self.config.ca_file):
                raise FileNotFoundError(f"CA file not found: {self.config.ca_file}")
            logger.info(f"Loading CA file for server verification: {self.config.ca_file}")
            try:
                context.load_verify_locations(cafile=self.config.ca_file)
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True # Ensures CN/SAN matches dest_host
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

        # Check for SSLKEYLOGFILE environment variable
        if os.environ.get('SSLKEYLOGFILE'):
             logger.info(f"SSLKEYLOGFILE detected ({os.environ['SSLKEYLOGFILE']}), TLS keys will be logged by Python's SSL module.")
        return context

    def connect(self) -> None:
        """
        Establishes the TCP and TLS connection to the SIP server.

        Binds to the local address/port and connects to the destination.

        Raises:
            ConnectionError: If the connection fails (DNS, TCP, TLS handshake, timeout, cert verification).
            ValueError: If configuration is invalid (e.g., missing certs).
            OSError: For socket-level errors during bind/connect.
        """
        context = self._create_ssl_context()
        bind_addr = ('', self.local_sip_port) # Bind to all interfaces on the specified port
        dest_addr = (self.config.dest_host, self.config.dest_port)
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10.0) # Connection timeout
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            if self.local_sip_port != 0:
                 logger.info(f"Attempting to bind SIP socket to local port {self.local_sip_port}")
            self.sock.bind(bind_addr)
            actual_bound_ip, self.local_sip_port = self.sock.getsockname() # Get actual port if 0 was used
            logger.info(f"SIP Socket bound to {actual_bound_ip}:{self.local_sip_port} (using source IP '{self.local_ip}' for SIP headers)")

            logger.info(f"Connecting SIP socket to {self.config.dest_host}:{self.config.dest_port}...")
            self.sock.connect(dest_addr)
            logger.info("TCP connection established.")

            # Wrap socket for TLS
            self.ssl_sock = context.wrap_socket(self.sock, server_hostname=self.config.dest_host)
            logger.info(f"TLS handshake successful. Protocol: {self.ssl_sock.version()}, Cipher: {self.ssl_sock.cipher()}")
            try:
                peer_cert = self.ssl_sock.getpeercert()
                logger.debug(f"Peer certificate details: {peer_cert}")
            except ssl.SSLError:
                logger.warning("Could not get peer certificate details (verification might be disabled).")

        except Exception as e:
            self._close_socket() # Clean up the plain socket if partially opened
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

    def _send_request(self, method: str, headers: dict[str, Any], body: bytes = b'') -> bool:
        """
        Constructs and sends a SIP request over the TLS connection.

        Internal method. Increments CSeq for non-ACK requests.
        Uses current state (call_id, tags, local ip/port) to build headers.
        Allows overriding default headers via the `headers` argument.

        Args:
            method: The SIP method (e.g., "INVITE", "ACK", "BYE").
            headers: A dictionary of headers to include or override defaults.
                     Values can be strings or lists of strings.
            body: The request body as bytes.

        Returns:
            True if the request was sent successfully, False otherwise.
        """
        if not self.ssl_sock:
            logger.error("Cannot send request: Not connected.")
            return False

        # --- Determine Request-URI ---
        port_suffix = f":{self.config.dest_port}" if self.config.dest_port != DEFAULT_SIPS_PORT else ""
        if method == "OPTIONS" and self.config.options_target_uri:
            request_uri = self.config.options_target_uri
        else: # INVITE, ACK, BYE usually use the original destination URI in simple cases
            request_uri = f"sip:{self.config.dest_number}@{self.config.dest_host}{port_suffix}"
            # Note: A robust client might use the Contact header from the 200 OK for ACK/BYE Request-URI.
        req_line = f"{method} {request_uri} {SIP_VERSION}"

        # --- Determine CSeq ---
        current_cseq_num: int
        cseq_method_str = method
        if method == "ACK":
            # ACK must use the CSeq number from the INVITE it acknowledges.
            # The caller (send_ack) must provide the correct number in 'headers'.
            try:
                cseq_header_val = str(headers.get('CSeq', ''))
                current_cseq_num = int(cseq_header_val.split(maxsplit=1)[0])
                headers['CSeq'] = f"{current_cseq_num} ACK" # Ensure the header being sent is correct
            except (ValueError, IndexError, TypeError):
                 # Fallback: Assume INVITE was the last non-ACK message sent
                 invite_cseq_num = self.cseq - 1 if self.cseq > 1 else 1 # CSeq was already incremented after INVITE
                 logger.warning(f"Could not parse CSeq number for ACK from provided header. Using previous CSeq {invite_cseq_num}.")
                 current_cseq_num = invite_cseq_num
                 headers['CSeq'] = f"{current_cseq_num} ACK"
        else:
            # For other methods (OPTIONS, INVITE, BYE), use the current counter value.
            # self.cseq will be incremented *after* sending these requests.
            current_cseq_num = self.cseq
            # Use the method itself in the CSeq header (e.g., "INVITE", "BYE")
            headers['CSeq'] = f"{current_cseq_num} {method}"

        # --- Determine Via Header ---
        # ACK reuses the branch from the corresponding INVITE.
        # Other requests (OPTIONS, INVITE, BYE) generate a new branch.
        branch = generate_branch()
        via_branch_to_use = self._last_branch if method == "ACK" else branch
        # Store the branch used for potential future ACK (only for non-ACK/BYE)
        if method not in ("ACK", "BYE"):
             self._last_branch = branch
        # Use the actual bound local SIP port and resolved local IP
        via_header = f"{SIP_VERSION}/TLS {self.local_ip}:{self.local_sip_port};branch={via_branch_to_use}"

        # --- Determine From/To Headers ---
        from_header = f"\"{self.config.src_display_name}\" <sip:{self.config.src_number}>;tag={self.from_tag}"
        to_uri_part = f"sip:{self.config.dest_number}@{self.config.dest_host}{port_suffix}"
        to_header_base = f"\"SIPREC-SRS\" <{to_uri_part}>"
        to_header = to_header_base
        # Add To tag for requests within a dialog (ACK, BYE), unless overridden
        if self.to_tag and method != "INVITE":
             # Allow explicit 'To' header override for flexibility
             explicit_to = headers.get("To")
             if isinstance(explicit_to, str) and ";tag=" in explicit_to:
                 logger.debug(f"Using To header provided explicitly for {method}.")
                 to_header = explicit_to
             else:
                 to_header += f";tag={self.to_tag}"

        # --- Determine Contact Header ---
        contact_header: str | None = None
        if method in ("INVITE", "OPTIONS"): # Contact usually sent in initial requests
            contact_header = f"\"{self.config.src_display_name}\" <sip:{self.config.src_number.split('@')[0]}@{self.local_ip}:{self.local_sip_port};transport=tls>"

        # --- Build Final Headers ---
        # Start with calculated defaults, then override/add from 'headers' arg
        final_hdrs: dict[str, Any] = {
            'Via': via_header,
            'From': from_header,
            'To': to_header,
            'Call-ID': self.call_id,
            'CSeq': headers.get('CSeq', f"{current_cseq_num} {method}"), # Use CSeq calculated above
            'Max-Forwards': str(DEFAULT_MAX_FORWARDS),
            'Contact': contact_header, # May be None
            'User-Agent': USER_AGENT,
            'Content-Length': str(len(body)), # Correct length based on actual body
            'MIME-Version': '1.0' if body else None # Only add if body exists
        }
        # Remove None values from defaults before merging
        final_hdrs = {k: v for k, v in final_hdrs.items() if v is not None}
        # Update with caller-provided headers (overwrites defaults)
        final_hdrs.update(headers)
        # Ensure Content-Length is always correct
        final_hdrs['Content-Length'] = str(len(body))

        # --- Construct Full Message ---
        message_lines: list[str] = [req_line]
        for key, value in final_hdrs.items():
            # Canonical capitalization (e.g., Content-Length)
            canonical_key = '-'.join(word.capitalize() for word in key.split('-'))
            if isinstance(value, list):
                for v_item in value: message_lines.append(f"{canonical_key}: {v_item}")
            else:
                message_lines.append(f"{canonical_key}: {value}")

        full_message_str: str = CRLF.join(message_lines) + CRLF * 2
        full_message_bytes: bytes = full_message_str.encode('utf-8') + body

        # --- Logging ---
        logger.debug(f"--- Sending {method} (CSeq: {final_hdrs['CSeq']}) --->")
        # Avoid logging potentially sensitive body content unless debug is very high
        log_body = body.decode('utf-8', errors='replace').strip() if len(body) < 500 else f"<Body: {len(body)} bytes>"
        logger.debug(full_message_str.strip() + (CRLF + log_body if body else CRLF + "<No Body>"))
        logger.debug("--- End Message --->")

        # --- Send Data ---
        try:
            self.ssl_sock.sendall(full_message_bytes)
            # Increment CSeq counter *after* successfully sending, but *not* for ACK.
            if method != "ACK":
                 self.cseq += 1
                 logger.debug(f"Incremented CSeq to {self.cseq} after sending {method}")
            return True
        except socket.error as e:
            logger.error(f"Socket error sending {method}: {e}")
            # Critical: Assume connection is broken if send fails.
            self.close() # Trigger cleanup
            return False
        except Exception as e:
             logger.exception(f"Unexpected error sending {method}: {e}")
             self.close() # Trigger cleanup
             return False

    def _receive_response(self, timeout: float = 10.0) -> tuple[int | None, dict[str, Union[str, list[str]]], bytes, bytes]:
        """
        Receives a SIP response using select() for timeout handling.

        Handles partial reads, determines message boundaries based on
        Content-Length or CRLFCRLF, and parses the result.

        Args:
            timeout: Maximum time in seconds to wait for a complete response.

        Returns:
            A tuple containing:
            - Status code (int) or None if timeout/error/parsing failure.
            - Dictionary of headers (keys lowercase).
            - Body as bytes.
            - Raw received bytes (for debugging).
        """
        if not self.ssl_sock:
            logger.error("Cannot receive response: Not connected.")
            return None, {}, b'', b''

        buffer = bytearray()
        raw_buffer_log = bytearray() # Store all raw bytes received
        headers_parsed = False
        content_length: int | None = None
        expected_total_len: int | None = None
        header_len = 0
        start_time = time.monotonic()

        try:
            while True:
                elapsed_time = time.monotonic() - start_time
                if elapsed_time >= timeout:
                     if not raw_buffer_log: logger.warning(f"Timeout ({timeout:.1f}s) waiting for initial SIP response data.")
                     else: logger.warning(f"Timeout ({timeout:.1f}s) waiting for response data completion (received {len(raw_buffer_log)} bytes).")
                     break # Timeout reached

                remaining_timeout = max(0.01, timeout - elapsed_time) # Minimum select timeout
                try:
                    # Wait for socket readability or error
                    readable, _, exceptional = select.select([self.ssl_sock], [], [self.ssl_sock], remaining_timeout)
                except ValueError: # Socket likely closed
                     logger.warning("Socket closed unexpectedly during select().")
                     break
                except Exception as sel_err:
                     logger.error(f"Error during select(): {sel_err}")
                     break # Treat as fatal error

                if exceptional:
                     logger.error("Socket reported exceptional condition during select(). Connection likely lost.")
                     self.dialog_established = False # Assume dialog invalid
                     break
                if not readable:
                     continue # Select timed out for this interval, loop will check overall timeout

                # Socket is readable, attempt to receive data
                try:
                    # Read reasonably large chunk to reduce recv calls
                    chunk = self.ssl_sock.recv(8192)
                except (socket.timeout, ssl.SSLWantReadError):
                     # Should not happen often with select, but handle defensively
                     logger.debug("Socket recv timed out or SSLWantReadError after select, retrying.")
                     time.sleep(0.01)
                     continue
                except ssl.SSLError as ssl_err:
                     logger.error(f"SSL error during recv: {ssl_err}. Connection likely lost.")
                     self.dialog_established = False # Assume dialog invalid
                     break
                except socket.error as sock_err:
                    logger.error(f"Socket error receiving data: {sock_err}. Connection likely lost.")
                    self.dialog_established = False # Assume dialog invalid
                    break
                except Exception as recv_err:
                     logger.exception(f"Unexpected error during recv: {recv_err}")
                     self.dialog_established = False
                     break

                # Handle connection closed by peer (recv returns empty bytes)
                if not chunk:
                    logger.warning("Connection closed by peer while receiving response.")
                    self.dialog_established = False # Dialog terminated if one existed
                    break

                # Append received data
                raw_buffer_log.extend(chunk)
                buffer.extend(chunk)

                # --- Try parsing headers and determining expected body length ---
                if not headers_parsed and CRLF_BYTES * 2 in buffer:
                    try:
                        header_part_bytes, _ = buffer.split(CRLF_BYTES * 2, 1)
                        header_len = len(header_part_bytes) + len(CRLF_BYTES * 2)
                        # Case-insensitive search for Content-Length
                        cl_match = re.search(rb'^[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ll][Ee][Nn][Gg][Tt][Hh]\s*:\s*(\d+)\s*$', header_part_bytes, re.MULTILINE)
                        if cl_match:
                            content_length = int(cl_match.group(1))
                            expected_total_len = header_len + content_length
                            logger.debug(f"Parsed Content-Length: {content_length}. Expecting total {expected_total_len} bytes.")
                        else:
                            content_length = 0 # Assume no body if header is present but no C-L
                            expected_total_len = header_len
                            logger.debug("No Content-Length header found. Assuming body-less message or chunked encoding (not supported).")
                        headers_parsed = True
                    except Exception as parse_err:
                        logger.warning(f"Error parsing headers for Content-Length: {parse_err}. Assuming headers processed.")
                        headers_parsed = True # Avoid getting stuck if header parsing fails badly

                # --- Check if we have received the complete message ---
                if headers_parsed and expected_total_len is not None:
                    # Message is complete if we have received at least the expected length
                    if len(buffer) >= expected_total_len:
                        logger.debug(f"Received {len(buffer)} bytes >= expected {expected_total_len}. Assuming complete message.")
                        # Trim any extra bytes read beyond content-length (e.g., next message pipelined)
                        if len(buffer) > expected_total_len:
                             logger.warning(f"Read {len(buffer) - expected_total_len} extra bytes past Content-Length. Trimming.")
                             # TODO: Handle potential pipelined messages if needed in future
                             buffer = buffer[:expected_total_len]
                        break # Complete message received
                elif not headers_parsed and len(buffer) > MAX_HEADER_BUFFER_SIZE:
                     logger.warning(f"Buffer exceeds {MAX_HEADER_BUFFER_SIZE} bytes without finding header end (CRLFCRLF). Treating as incomplete/malformed.")
                     break # Prevent excessive memory usage

        except Exception as e:
             logger.exception(f"Unexpected error during receive loop: {e}")
             self.dialog_established = False # Assume error invalidates dialog

        # --- Process the final buffer ---
        received_data = bytes(buffer)
        raw_data_for_log = bytes(raw_buffer_log)
        if raw_data_for_log:
            logger.debug(f"--- Received Raw Response ({len(raw_data_for_log)} bytes total) ---")
            try: logger.debug(raw_data_for_log.decode('utf-8', errors='replace'))
            except Exception: logger.debug("<Unable to decode raw buffer as UTF-8>")
            logger.debug("--- End Raw Response ---")
        else:
            logger.debug("No raw data was received for this response.")
            if not received_data: # If buffer is also empty, signifies complete failure/timeout
                 return None, {}, b'', b''

        # Parse the potentially complete message buffer
        status, headers, body = parse_sip_response(received_data)
        if status is None and received_data: # Parsing failed, but we had data
             logger.error("Failed to parse the received SIP response buffer.")
             # Return raw data for debugging, but indicate failure with None status
             return None, {}, received_data, raw_data_for_log

        return status, headers, body, raw_data_for_log


    def send_options(self) -> bool:
        """
        Sends a SIP OPTIONS request and waits for a 2xx response.

        Returns:
            True if a 2xx response was received, False otherwise.
        """
        options_cseq = self.cseq # Capture CSeq number before sending
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
        Sends the SIPREC INVITE request with SDP and metadata.

        Handles provisional (1xx) and final (>=200) responses.
        Parses the SDP answer from a 200 OK.
        Sets `self.dialog_established = True` on successful 2xx response and To tag parsing.
        Stores response details in `self.last_invite_response_*` attributes.

        Returns:
            True if a 2xx final response was received and processed successfully
            (including parsing To tag and SDP if applicable), False otherwise.
        """
        invite_cseq_num = self.cseq # Capture CSeq *before* sending INVITE
        logger.info(f"Sending SIPREC INVITE (CSeq: {invite_cseq_num})...")

        # Create SDP Offer
        try:
            self.last_invite_offer_sdp = create_sdp_offer(
                self.local_ip,
                DEFAULT_SDP_AUDIO_PORT_BASE,
                self.config.audio_encoding,
                self.config.packet_time,
                self.config.srtp_encryption # Pass the encryption choice
            )
        except ValueError as sdp_err:
             logger.error(f"Failed to generate SDP offer: {sdp_err}")
             return False
        sdp_bytes = self.last_invite_offer_sdp.encode('utf-8')

        # Create SIPREC Metadata
        metadata_body_str = create_siprec_metadata(
            self.config, self.config.dest_number, self.config.dest_host
        )
        metadata_bytes = metadata_body_str.encode('utf-8')

        # Construct multipart/mixed body
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

        # Prepare INVITE headers
        invite_headers: dict[str, str | None] = {
            'Content-Type': f'multipart/mixed; boundary="{boundary}"',
            'Accept': 'application/sdp, application/rs-metadata+xml', # Accept metadata too
            'Allow': 'INVITE, ACK, CANCEL, BYE, OPTIONS',
            'Supported': 'timer, replaces, 100rel',
            'Require': 'siprec', # Indicate SIPREC requirement
            'Session-Expires': '1800; refresher=uac', # Example session timer
            'Min-SE': '90',
            'Call-Info': (f'<{self.config.call_info_url}>;purpose=Goog-ContactCenter-Conversation'
                          if self.config.call_info_url else None),
        }
        # Filter out None values before passing to _send_request
        invite_headers_filtered = {k: v for k, v in invite_headers.items() if v is not None}

        # Send the INVITE request
        if not self._send_request("INVITE", invite_headers_filtered, body_bytes):
             logger.error("Failed to send INVITE request.")
             self.last_invite_response_status = None
             self.dialog_established = False
             return False

        # --- Wait for and process responses ---
        final_status: int | None = None
        final_headers: dict[str, Union[str, list[str]]] = {}
        final_body: bytes = b''
        response_count = 0
        max_responses_to_process = 10 # Avoid infinite loop on flapping 1xx

        while response_count < max_responses_to_process:
            response_count += 1
            logger.debug(f"Waiting for INVITE response (attempt {response_count})...")
            status, headers, body, raw = self._receive_response(timeout=30.0) # Longer timeout for INVITE

            if status is None:
                # Timeout or fatal receive error
                log_msg = "Timed out" if raw else "Failed to receive any"
                logger.error(f"{log_msg} response for INVITE (last provisional: {final_status}).")
                self.last_invite_response_status = final_status # Store last known status
                self.dialog_established = False
                return False

            reason = headers.get('reason-phrase', '')
            cseq_resp = headers.get('cseq', 'N/A')
            logger.info(f"Received response for INVITE: {status} {reason} (CSeq: {cseq_resp})")

            # Process provisional (1xx) responses
            if 100 <= status < 200:
                logger.info(f"Received provisional response {status} {reason}. Waiting for final response.")
                final_status = status # Keep track of the latest provisional status
                # Optionally: Check for early media/dialog info (e.g., To tag, SDP in 183)
                if status == 183 and body:
                     logger.debug("Received 183 with potential early SDP.")
                     # Could parse SDP here if early media handling was needed
                if body: logger.debug(f"Provisional response body:\n{body.decode(errors='ignore')}")
                continue # Wait for the next response

            # Process final (>=200) responses
            elif status >= 200:
                final_status = status
                final_headers = headers
                final_body = body
                logger.debug(f"Received final response {status}. Processing result.")
                break # Exit the loop, we have the final answer
            else: # Should not happen (status < 100)
                logger.warning(f"Received invalid status code {status}, ignoring and waiting.")
                final_status = status

        # --- Handle outcome based on final status ---
        self.last_invite_response_status = final_status
        self.last_invite_response_headers = final_headers
        self.last_invite_response_body = final_body

        if final_status is None or final_status < 200:
            logger.error(f"No final (>=200) response received for INVITE after {response_count} responses (last status: {final_status}).")
            self.dialog_established = False
            return False

        # Success Case (2xx)
        if 200 <= final_status < 300:
            logger.info(f"Received final {final_status} {final_headers.get('reason-phrase', '')} for INVITE. Call establishing...")
            logger.debug(f"Final Response Headers: {final_headers}")
            if final_body: logger.debug(f"Final Response Body:\n{final_body.decode(errors='ignore')}")

            # CRITICAL: Capture To tag for subsequent requests (ACK, BYE)
            to_header_val = final_headers.get('to')
            to_headers_list: list[str] = []
            if isinstance(to_header_val, list): to_headers_list = [str(h) for h in to_header_val]
            elif isinstance(to_header_val, str): to_headers_list = [to_header_val]

            tag_found = False
            for hdr in to_headers_list:
                # Regex to find 'tag=' parameter, ensuring it's not part of the display name
                match = re.search(r';\s*tag=([\w.-]+)', hdr)
                if match:
                    self.to_tag = match.group(1)
                    tag_found = True
                    break # Found the tag in one of the To headers

            if tag_found:
                logger.info(f"Captured To tag from {final_status} response: {self.to_tag}")
            else:
                logger.error(f"CRITICAL: Received {final_status} success, but could not find 'tag=' parameter in To header(s): {to_header_val}")
                self.dialog_established = False # Cannot establish dialog without tag
                return False # Treat as failure if To tag is missing

            # Parse SDP answer if present (usually in 200 OK)
            if final_status == 200 and final_body:
                logger.info("Parsing SDP answer from 200 OK...")
                self.last_invite_response_sdp_info = parse_sdp_answer(final_body)
                # Check if parsing was successful and if we need media streams
                if not self.last_invite_response_sdp_info and self.config.audio_file:
                     logger.error("CRITICAL: Received 200 OK but failed to parse required media info from SDP answer. Streaming will fail.")
                     self.dialog_established = False # Cannot proceed with streaming
                     return False # Parsing SDP failed, treat invite as failure
                elif self.last_invite_response_sdp_info:
                     for i, info in enumerate(self.last_invite_response_sdp_info):
                         crypto_info = f"Suite={info.crypto_suite}" if info.crypto_suite else "N/A (Plain RTP)"
                         logger.info(f"  Parsed Answer Stream {i+1}: Label='{info.label}', Target={info.connection_ip}:{info.port}, Proto={info.protocol}, Crypto={crypto_info}")
            elif final_status == 200 and not final_body:
                 logger.warning("Received 200 OK for INVITE but no SDP body was present.")
                 if self.config.audio_file:
                      logger.error("Audio file specified, but no SDP answer received. Cannot stream.")
                      self.dialog_established = False
                      return False # Treat as failure if streaming expected

            # If we reached here with a 2xx and got the To tag, the dialog is established
            self.dialog_established = True
            logger.debug("Dialog established state set to True.")
            return True # INVITE was successful

        # Failure Case (>= 300)
        else:
            logger.error(f"INVITE failed with final status: {final_status} {final_headers.get('reason-phrase', '')}")
            if final_body: logger.error(f"Failure Response Body:\n{final_body.decode(errors='ignore')}")
            self.dialog_established = False # Ensure state reflects failure
            return False

    def send_ack(self, invite_cseq_num: int) -> bool:
        """
        Sends an ACK request for a successful INVITE.

        Uses the stored `to_tag` and the `_last_branch` from the INVITE.
        Requires the CSeq number of the original INVITE.

        Args:
            invite_cseq_num: The CSeq number of the INVITE this ACK is for.

        Returns:
            True if ACK was sent successfully, False otherwise.
        """
        if not self.dialog_established:
            logger.error("Cannot send ACK: Dialog not established (INVITE likely failed or To tag missing).")
            return False
        if not self.to_tag:
             logger.error("Cannot send ACK: Missing To tag (internal state error).")
             # Should not happen if dialog_established is True, but check defensively
             return False
        if not self._last_branch:
             logger.error("Cannot send ACK: Missing Via branch from INVITE (internal error).")
             return False

        logger.info(f"Sending ACK for INVITE (CSeq: {invite_cseq_num} ACK)...")

        # ACK headers are constructed based on current dialog state (to_tag, from_tag, call_id)
        # We must provide the correct CSeq number and method ("ACK")
        ack_headers = {
            'CSeq': f"{invite_cseq_num} ACK", # Critical: Use INVITE's CSeq num, method ACK
            'Content-Length': "0" # ACK has no body
            # Via, From, To, Call-ID, Max-Forwards are handled by _send_request
        }

        # Note: _send_request does NOT increment self.cseq for ACK
        ack_sent = self._send_request("ACK", ack_headers, b'')
        if ack_sent:
            logger.info("ACK sent successfully.")
        else:
            logger.error("Failed to send ACK.") # Connection likely closed by _send_request
            # Keep dialog_established as True for now, but connection is likely dead. BYE attempt might fail.
        return ack_sent

    def send_bye(self) -> bool:
        """
        Attempts to send a BYE request to terminate the established dialog.

        This should only be called if `self.dialog_established` is True.
        It's a best-effort attempt. Failure (e.g., if the connection is
        already down) is logged but doesn't prevent cleanup.
        Sets `self.dialog_established = False` after sending or on failure to send.

        Returns:
            True if the BYE request was successfully sent, False otherwise.
            Note: Return value indicates if sending was successful, not if a 200 OK was received.
        """
        if not self.dialog_established:
            logger.debug("Cannot send BYE: Dialog not established.")
            return False
        if not self.ssl_sock:
            logger.error("Cannot send BYE: Not connected.")
            self.dialog_established = False # Mark dialog ended due to connection issue
            return False
        if not self.to_tag:
             logger.error("Cannot send BYE: Missing To tag (internal state error).")
             self.dialog_established = False # Mark dialog ended due to state issue
             return False

        bye_cseq_num = self.cseq # Use the current CSeq number *before* sending BYE
        logger.info(f"Sending BYE to terminate dialog (CSeq: {bye_cseq_num} BYE)...")

        # Construct BYE headers
        bye_headers = {
            'Content-Length': "0" # BYE has no body
            # Via (new branch), From, To, Call-ID, CSeq, Max-Forwards
            # are added by _send_request using the current state.
        }

        # Call _send_request for BYE. This will use the current self.cseq
        # and increment it afterwards if successful.
        bye_sent = self._send_request("BYE", bye_headers, b'')

        # Mark dialog as terminated locally *after* attempting to send BYE
        # regardless of success, as the intention is to end the session.
        self.dialog_established = False
        logger.debug("Dialog established state set to False after BYE attempt.")

        if bye_sent:
            logger.info("BYE request sent successfully.")
            # Optionally, wait briefly for a 200 OK response to the BYE
            logger.debug(f"Waiting up to {BYE_RESPONSE_TIMEOUT_SEC}s for BYE response...")
            status, headers, _, _ = self._receive_response(timeout=BYE_RESPONSE_TIMEOUT_SEC)
            if status == 200:
                logger.info(f"Received 200 OK for BYE (CSeq: {headers.get('cseq', 'N/A')}).")
            elif status is not None:
                logger.warning(f"Received unexpected response to BYE: {status} {headers.get('reason-phrase', '')} (CSeq: {headers.get('cseq', 'N/A')})")
            else:
                logger.debug("No response received for BYE within timeout (this is often normal).")
            return True # Return True because BYE was sent
        else:
            logger.error("Failed to send BYE request (connection likely broken).")
            return False

    def _close_socket(self) -> None:
        """
        Internal helper to close the plain TCP socket gracefully.
        """
        if self.sock:
             sock_fd = -1
             try: sock_fd = self.sock.fileno()
             except Exception: pass # Ignore errors getting fd if already closed
             logger.debug(f"Closing plain socket (fd={sock_fd if sock_fd != -1 else 'N/A'})...")
             try:
                 try:
                     # Attempt graceful shutdown before closing
                     self.sock.shutdown(socket.SHUT_RDWR)
                 except (socket.error, OSError) as shut_err:
                      # Ignore errors if already disconnected or invalid fd
                      if shut_err.errno not in (socket.errno.ENOTCONN, socket.errno.EBADF, 107, socket.errno.EPIPE):
                           logger.warning(f"Error shutting down plain socket {sock_fd}: {shut_err}")
                 # Always attempt close
                 self.sock.close()
                 logger.debug(f"Plain socket (fd={sock_fd}) closed.")
             except (socket.error, OSError) as close_err:
                 logger.warning(f"Error closing plain socket {sock_fd}: {close_err}")
             finally:
                self.sock = None # Ensure socket attribute is cleared

    def close(self) -> None:
        """
        Closes the TLS and underlying socket connection gracefully.

        Attempts TLS shutdown (unwrap) before closing the socket.
        Sets dialog_established to False. Handles potential errors during closure.
        """
        # Mark dialog ended immediately, as connection is being torn down
        self.dialog_established = False
        logger.debug("Dialog established state set to False during close().")

        if self.ssl_sock:
            sock_fd = -1
            try: sock_fd = self.ssl_sock.fileno()
            except Exception: pass
            logger.info(f"Closing TLS connection (socket fd={sock_fd if sock_fd != -1 else 'N/A'})...")
            try:
                # Attempt graceful TLS shutdown (send close_notify)
                # Use a short timeout to prevent hanging if peer doesn't respond
                self.ssl_sock.settimeout(1.0)
                self.ssl_sock.unwrap()
                logger.debug(f"TLS layer unwrapped for socket {sock_fd}.")
            except ssl.SSLError as ssl_err:
                 # Common errors during unwrap on already closed/broken sockets
                 err_str = str(ssl_err).upper()
                 common_unwrap_errors = ("SOCKET_CLOSED", "WRONG_VERSION_NUMBER",
                                        "SHUTDOWN_WHILE_ASYNC", "SSL_ERROR_EOF",
                                        "UNEXPECTED EOF", "TLSV1_ALERT_INTERNAL_ERROR", # Add more known benign errors
                                        "RECEIVED_SHUTDOWN")
                 if any(e in err_str for e in common_unwrap_errors):
                      logger.debug(f"Ignoring expected SSL error during unwrap (socket likely closed): {ssl_err}")
                 else:
                      logger.warning(f"SSL error during unwrap() on socket {sock_fd}: {ssl_err}")
            except (socket.error, OSError) as sock_err:
                 # Ignore common socket errors indicating closure
                 if sock_err.errno not in (socket.errno.ENOTCONN, socket.errno.EBADF, 107, socket.errno.EPIPE):
                      logger.warning(f"Socket error during unwrap() on socket {sock_fd}: {sock_err}")
                 else:
                      logger.debug(f"Socket closed or not connected during unwrap: {sock_err}")
            except socket.timeout:
                 logger.warning(f"Timeout during SSL unwrap() for socket {sock_fd}. Closing abruptly.")
            except Exception as e:
                 logger.warning(f"Unexpected error during unwrap() on socket {sock_fd}: {e}")
            finally:
                 # Always try to close the SSL socket object itself
                 try:
                      self.ssl_sock.close()
                      logger.info(f"TLS connection closed (socket fd={sock_fd}).")
                 except (socket.error, OSError, ssl.SSLError) as close_err:
                      # Log errors during the final close, but continue
                      logger.warning(f"Error closing SSL socket object (fd={sock_fd}): {close_err}")
                 finally:
                      # Clear references
                      self.ssl_sock = None
                      self.sock = None # Underlying socket is closed by ssl_sock.close()
        elif self.sock:
             # If only the plain socket exists (e.g., TLS handshake failed after connect)
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
    srtp_session: pylibsrtp.Session | None, # SRTP session or None for plain RTP
    local_rtp_port: int,
    stop_event: threading.Event,
    max_duration_sec: float | None,
    output_filename: str | None,
) -> None:
    """
    Streams one audio channel from a file over RTP/SRTP.

    Reads audio data for the specified channel, encodes it (using soundfile),
    packetizes it into RTP, encrypts if an SRTP session is provided,
    and sends it to the destination IP/port from the specified local port.

    Optionally saves the original *unencrypted* encoded payload to a WAV file
    if `output_filename` is provided and the codec is compatible (PCMA/PCMU).

    Args:
        channel_index: The audio channel index to read (0-based).
        audio_file_path: Path to the input audio file (e.g., WAV).
        dest_ip: Destination IP address for RTP/SRTP packets.
        dest_port: Destination UDP port for RTP/SRTP packets.
        payload_type: RTP payload type number for the audio codec.
        codec_name: Name of the audio codec (e.g., "PCMA").
        sample_rate: Audio sample rate in Hz (e.g., 8000).
        packet_time_ms: Packet duration in milliseconds (determines samples per packet).
        srtp_session: An initialized pylibsrtp.Session for SRTP encryption, or None for plain RTP.
        local_rtp_port: The local UDP port to send RTP/SRTP from.
        stop_event: A threading.Event to signal when to stop streaming.
        max_duration_sec: Maximum streaming duration in seconds (0 or None for no limit).
        output_filename: Path to save the original encoded payload as WAV, or None.
    """
    thread_name = f"Streamer-Ch{channel_index}" # e.g., Streamer-Ch0
    is_srtp = bool(srtp_session)
    stream_type = "SRTP" if is_srtp else "RTP"
    logger.info(f"[{thread_name}] Starting {stream_type}: Target={dest_ip}:{dest_port}, Local UDP Port={local_rtp_port}, PT={payload_type}, Codec={codec_name}/{sample_rate}, PTime={packet_time_ms}ms")

    # --- Calculate stream parameters ---
    try:
        samples_per_packet = int(sample_rate * packet_time_ms / 1000)
        if samples_per_packet <= 0: raise ValueError("Packet time too small or zero sample rate")
        packet_interval_sec = packet_time_ms / 1000.0
        timestamp_increment = samples_per_packet
    except (ValueError, TypeError) as e:
        logger.error(f"[{thread_name}] Invalid stream parameters (Rate: {sample_rate}, PTime: {packet_time_ms}): {e}. Stopping.")
        stop_event.set()
        return

    # --- Initialize resources ---
    rtp_socket: socket.socket | None = None
    audio_file: sf.SoundFile | None = None
    output_file: io.BufferedWriter | None = None
    wav_format_code: int | None = None
    output_file_opened_successfully = False
    stream_start_time = time.monotonic()
    packets_sent = 0
    bytes_sent = 0 # Network bytes (RTP/SRTP)
    payload_bytes_saved = 0 # Original encoded bytes saved to file

    try:
        # --- Setup WAV output file (if requested and compatible) ---
        if output_filename:
            wav_format_code = AUDIO_ENCODING_TO_WAV_FORMAT_CODE.get(codec_name.upper())
            if wav_format_code is None:
                logger.error(f"[{thread_name}] Cannot save to WAV: Unsupported codec '{codec_name}' for WAV output (requires PCMA/G711A or PCMU/G711U).")
                output_filename = None # Disable saving
            else:
                try:
                    logger.info(f"[{thread_name}] Opening WAV output file: '{output_filename}' (Format Code: {wav_format_code})")
                    output_file = open(output_filename, 'wb')
                    write_wav_header(output_file, sample_rate, wav_format_code)
                    output_file_opened_successfully = True
                except IOError as e:
                    logger.error(f"[{thread_name}] Cannot open WAV output file '{output_filename}': {e}. Disabling saving.")
                    output_file = None
                    output_filename = None
                    output_file_opened_successfully = False
                except Exception as e:
                     logger.exception(f"[{thread_name}] Unexpected error setting up WAV output file '{output_filename}': {e}")
                     output_file = None
                     output_filename = None
                     output_file_opened_successfully = False

        # --- Setup UDP socket ---
        rtp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp_socket.bind(('', local_rtp_port))
        logger.info(f"[{thread_name}] UDP sending socket bound successfully to local port {local_rtp_port}")

        # --- Initialize RTP parameters ---
        ssrc = random.randint(0, 0xFFFFFFFF)
        sequence_number = random.randint(0, 0xFFFF)
        timestamp = random.randint(0, 0xFFFFFFFF)

        # --- Open audio file ---
        logger.info(f"[{thread_name}] Opening audio file: {audio_file_path}")
        audio_file = sf.SoundFile(audio_file_path, 'r')

        if audio_file.channels <= channel_index:
             raise ValueError(f"Audio file '{audio_file_path}' has only {audio_file.channels} channels, cannot stream channel {channel_index}.")
        if audio_file.samplerate != sample_rate:
            logger.warning(f"[{thread_name}] Audio file SR ({audio_file.samplerate}Hz) != negotiated SR ({sample_rate}Hz). Quality/timing may be affected.")

        logger.info(f"[{thread_name}] Audio File Info: Rate={audio_file.samplerate}, Channels={audio_file.channels}, Frames={audio_file.frames or 'Unknown'}")
        logger.info(f"[{thread_name}] {stream_type} Params: SSRC={ssrc:08X}, StartSeq={sequence_number}, StartTS={timestamp}, Samples/Pkt={samples_per_packet}")

        # --- Streaming Loop ---
        last_log_time = time.monotonic()
        for block_num, block in enumerate(audio_file.blocks(blocksize=samples_per_packet, dtype='int16', fill_value=0)):
            loop_start_time = time.monotonic()

            # Check stop conditions
            if stop_event.is_set():
                logger.info(f"[{thread_name}] Stop event received. Halting stream.")
                break
            current_duration = loop_start_time - stream_start_time
            if max_duration_sec and max_duration_sec > 0 and current_duration >= max_duration_sec:
                logger.info(f"[{thread_name}] Max stream duration ({max_duration_sec:.1f}s) reached. Halting.")
                break
            if not block.size: # Check if block is empty (end of file without fill)
                logger.info(f"[{thread_name}] End of audio file reached (empty block).")
                break

            # Extract channel data and ensure correct size
            channel_data = block[:, channel_index]
            if channel_data.shape[0] < samples_per_packet:
                 padding_needed = samples_per_packet - channel_data.shape[0]
                 channel_data = np.pad(channel_data, (0, padding_needed), 'constant')

            # 1. Encode audio segment -> original_payload
            try:
                original_payload = encode_audio_segment(channel_data, codec_name, sample_rate)
            except (ValueError, sf.SoundFileError, TypeError) as enc_err:
                 logger.error(f"[{thread_name}] Failed to encode audio block {block_num}: {enc_err}. Stopping stream.")
                 stop_event.set()
                 break
            except Exception as enc_exc:
                logger.exception(f"[{thread_name}] Unexpected error encoding block {block_num}: {enc_exc}. Stopping.")
                stop_event.set()
                break

            # 2. Construct plain RTP packet (header + original_payload)
            version = 2; padding = 0; extension = 0; csrc_count = 0; marker = 0
            header_byte1 = (version << 6) | (padding << 5) | (extension << 4) | csrc_count
            header_byte2 = (marker << 7) | payload_type
            rtp_header = struct.pack('!BBHLL', header_byte1, header_byte2,
                                      sequence_number & 0xFFFF,
                                      timestamp & 0xFFFFFFFF,
                                      ssrc)
            rtp_packet = rtp_header + original_payload

            # 3. Encrypt if SRTP, otherwise use plain RTP packet
            packet_to_send: bytes
            log_pkt_type: str
            if srtp_session: # Check if session object exists (implies SRTP)
                try:
                    packet_to_send = srtp_session.protect(rtp_packet)
                    log_pkt_type = "SRTP"
                except pylibsrtp.Error as srtp_err:
                    logger.error(f"[{thread_name}] SRTP protection failed (Seq={sequence_number}): {srtp_err}. Stopping.")
                    stop_event.set()
                    break
                except Exception as protect_err:
                    logger.exception(f"[{thread_name}] Unexpected SRTP protect error (Seq={sequence_number}): {protect_err}. Stopping.")
                    stop_event.set()
                    break
            else:
                packet_to_send = rtp_packet
                log_pkt_type = "RTP"

            # 4. Save original payload to WAV file (if enabled and open)
            if output_file and output_file_opened_successfully:
                try:
                    output_file.write(original_payload)
                    payload_bytes_saved += len(original_payload)
                    # Log saving periodically
                    if packets_sent % 250 == 0: # Log every ~5 seconds for 20ms packets
                         logger.info(f"[{thread_name}] Saved {payload_bytes_saved} payload bytes to '{output_filename}'")
                except IOError as e:
                    logger.warning(f"[{thread_name}] Error writing to WAV file '{output_filename}': {e}. Disabling saving.")
                    try: output_file.close()
                    except Exception: pass
                    output_file = None
                    output_file_opened_successfully = False
                    output_filename = None # Prevent header update attempt later

            # 5. Send the network packet
            try:
                bytes_sent_this_packet = rtp_socket.sendto(packet_to_send, (dest_ip, dest_port))
                bytes_sent += bytes_sent_this_packet
                packets_sent += 1
                # Log sent packet periodically
                current_time = time.monotonic()
                if current_time - last_log_time > 5.0: # Log approx every 5 seconds
                    logger.debug(f"[{thread_name}] Sent {log_pkt_type} packet: Seq={sequence_number}, TS={timestamp}, NetSize={bytes_sent_this_packet} (Total sent: {packets_sent})")
                    last_log_time = current_time
            except socket.error as send_err:
                logger.error(f"[{thread_name}] Socket error sending {log_pkt_type} (Seq={sequence_number}): {send_err}. Stopping.")
                stop_event.set()
                break
            except Exception as send_exc:
                logger.exception(f"[{thread_name}] Unexpected error sending {log_pkt_type} (Seq={sequence_number}): {send_exc}. Stopping.")
                stop_event.set()
                break

            # 6. Update RTP sequence number and timestamp
            sequence_number = (sequence_number + 1) & 0xFFFF
            timestamp = (timestamp + timestamp_increment) & 0xFFFFFFFF

            # 7. Wait for the next packet interval
            elapsed_processing_time = time.monotonic() - loop_start_time
            sleep_time = packet_interval_sec - elapsed_processing_time
            if sleep_time > 0:
                time.sleep(sleep_time)
            elif packets_sent > 10: # Avoid warning on initial packets
                 logger.warning(f"[{thread_name}] Loop processing time ({elapsed_processing_time:.4f}s) exceeded interval ({packet_interval_sec:.4f}s). Falling behind.")

        # --- Loop finished ---
        logger.info(f"[{thread_name}] Streaming loop finished. Packets sent: {packets_sent}, Network bytes sent: {bytes_sent} ({stream_type})")
        if output_filename and output_file_opened_successfully:
            logger.info(f"[{thread_name}] Total original payload bytes saved to intermediate WAV '{output_filename}': {payload_bytes_saved}.")

    # --- Handle exceptions during setup or loop ---
    except (sf.SoundFileError, ValueError, pylibsrtp.Error, OSError) as e:
        # Catch specific, potentially recoverable errors or config issues
        logger.error(f"[{thread_name}] Error during streaming: {e}")
        stop_event.set() # Signal main thread about the error
    except Exception as e:
        # Catch unexpected errors
        logger.exception(f"[{thread_name}] Unexpected critical error during streaming: {e}")
        stop_event.set() # Signal main thread
    finally:
        # --- Cleanup resources for this thread ---
        logger.debug(f"[{thread_name}] Cleaning up resources...")
        if audio_file:
            try: audio_file.close()
            except Exception as close_err: logger.warning(f"[{thread_name}] Error closing audio file: {close_err}")
        if rtp_socket:
            try: rtp_socket.close()
            except Exception as close_err: logger.warning(f"[{thread_name}] Error closing RTP socket: {close_err}")

        # --- Finalize WAV file (Update header size) ---
        if output_file and output_file_opened_successfully:
            logger.info(f"[{thread_name}] Finalizing WAV file: '{output_filename}'")
            try:
                update_wav_header(output_file, WAV_HEADER_SIZE, payload_bytes_saved)
                logger.info(f"[{thread_name}] Successfully updated WAV header for '{output_filename}'.")
            except Exception as update_err:
                logger.error(f"[{thread_name}] Failed to update WAV header for '{output_filename}': {update_err}")
            finally:
                 # Always try to close the file descriptor
                try:
                    output_file.close()
                    logger.info(f"[{thread_name}] Closed WAV output file '{output_filename}'.")
                except Exception as close_err:
                    logger.warning(f"[{thread_name}] Error closing WAV output file '{output_filename}': {close_err}")
        elif output_filename and not output_file_opened_successfully:
             # Case where file opening failed initially
             logger.debug(f"[{thread_name}] WAV file '{output_filename}' was not opened successfully, skipping finalization.")

        logger.info(f"[{thread_name}] Streaming thread terminated.")


# --- Helper Functions for main() ---

def _validate_args(args: argparse.Namespace) -> bool:
    """Performs basic validation on parsed command-line arguments."""
    valid = True
    # Check required file existence
    try:
         required_files = {'cert-file': args.cert_file, 'key-file': args.key_file}
         if args.ca_file: required_files['ca-file'] = args.ca_file
         if args.audio_file: required_files['audio-file'] = args.audio_file
         for name, path in required_files.items():
              if path and not os.path.isfile(path):
                   raise FileNotFoundError(f"Required file --{name} not found: {path}")
    except FileNotFoundError as fnf_error:
         logger.error(f"Error: {fnf_error}")
         valid = False

    # Ensure source number looks like an AOR
    if '@' not in args.src_number:
        logger.warning(f"Source number '{args.src_number}' doesn't contain '@'. Appending '@{args.src_host}'.")
        args.src_number = f"{args.src_number}@{args.src_host}" # Modify in place

    # Validate audio encoding format
    is_wav_compatible = False
    try:
        parts = args.audio_encoding.split('/')
        if len(parts) == 2 and parts[1].isdigit():
            encoding_name = parts[0].strip().upper()
            if encoding_name in AUDIO_ENCODING_TO_PAYLOAD_TYPE:
                # Check if soundfile can encode it (best effort check)
                 subtype = "ALAW" if encoding_name in ("PCMA", "G711A") else \
                           "ULAW" if encoding_name in ("PCMU", "G711U") else None
                 if subtype and sf.check_format("RAW", subtype):
                      if encoding_name in AUDIO_ENCODING_TO_WAV_FORMAT_CODE:
                           is_wav_compatible = True
                 else:
                      logger.warning(f"Soundfile may not support RAW encoding for '{encoding_name}'. Check libsndfile.")
            else:
                 logger.warning(f"Audio encoding '{encoding_name}' not explicitly mapped. Ensure server supports it.")
        else: raise ValueError("Invalid format")
    except ValueError:
        logger.warning(f"--audio-encoding '{args.audio_encoding}' invalid/unsupported. Using default '{DEFAULT_AUDIO_ENCODING}'.")
        args.audio_encoding = DEFAULT_AUDIO_ENCODING # Modify in place
        is_wav_compatible = True # Default is WAV compatible

    # Validate WAV saving requirements
    if (args.save_stream1_file or args.save_stream2_file):
        if not args.audio_file:
            logger.warning("--save-stream*-file requested, but no --audio-file provided. Saving skipped.")
            args.save_stream1_file = None # Disable
            args.save_stream2_file = None
        elif not is_wav_compatible:
             logger.error(f"--save-stream*-file requested, but encoding '{args.audio_encoding.split('/')[0]}' is not PCMA/PCMU. Saving disabled.")
             args.save_stream1_file = None # Disable
             args.save_stream2_file = None
        else:
             logger.info(f"Will save streams as WAV (Encoding: {args.audio_encoding.split('/')[0]}) based on SDP labels '{CLIENT_OFFERED_LABEL_1}', '{CLIENT_OFFERED_LABEL_2}'.")
             for fname in [args.save_stream1_file, args.save_stream2_file]:
                  if fname and not fname.lower().endswith('.wav'):
                       logger.warning(f"Output filename '{fname}' doesn't end with '.wav', but a WAV file will be created.")

    # Validate SRTP choice
    if args.srtp_encryption.upper() != "NONE" and args.srtp_encryption not in SUPPORTED_SRTP_CIPHERS_SDES:
         logger.error(f"Invalid --srtp-encryption choice '{args.srtp_encryption}'. Must be one of {SRTP_ENCRYPTION_CHOICES}")
         valid = False

    return valid

def _setup_tshark(args: argparse.Namespace, ssl_key_log_file_path: str | None) -> subprocess.Popen | None:
    """Starts the tshark packet capture process if requested and possible."""
    if not args.pcap_file:
        return None # Not requested

    tshark_path = shutil.which("tshark")
    if not tshark_path:
         logger.error("'tshark' not found in PATH. Skipping packet capture.")
         return None

    logger.info("Packet capture requested. Constructing tshark command...")
    try:
         sip_target = args.capture_sip_range
         sip_keyword = "net" if '/' in sip_target else "host"
         sip_condition = f"({sip_keyword} {sip_target} and tcp port {args.capture_sip_port})"

         media_target = args.capture_media_range
         media_keyword = "net" if '/' in media_target else "host"
         media_condition = f"({media_keyword} {media_target} and udp)" # Capture all UDP to/from media range

         bpf_filter = f"{sip_condition} or {media_condition}"
         logger.info(f"Using tshark BPF filter: {bpf_filter}")

         # Log decryption possibilities
         can_decrypt = ssl_key_log_file_path and os.path.exists(ssl_key_log_file_path)
         if args.srtp_encryption.upper() != "NONE":
             if can_decrypt:
                 logger.info("SSLKEYLOGFILE set and exists. Decryption of TLS SIP will be attempted after capture.")
             elif ssl_key_log_file_path: # Set but doesn't exist
                 logger.warning(f"SSLKEYLOGFILE is set ('{ssl_key_log_file_path}') but file not found. Pcap won't be automatically decrypted.")
             else: # Not set
                 logger.warning("SSLKEYLOGFILE not set. Captured TLS SIP traffic will not be automatically decrypted.")
         else: # Plain RTP
             logger.info("Plain RTP selected. Media packets will not be encrypted. TLS SIP decryption depends on SSLKEYLOGFILE.")
             if can_decrypt: logger.info("SSLKEYLOGFILE set for potential TLS SIP decryption.")


         tshark_cmd = [tshark_path, "-i", args.capture_interface, "-f", bpf_filter, "-w", args.pcap_file]
         logger.info(f"Starting tshark: {' '.join(tshark_cmd)}")
         if args.capture_interface == 'any': logger.info("Note: Interface 'any' usually requires root/administrator privileges.")

         # Start process, capturing stderr
         process = subprocess.Popen(
             tshark_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
             text=True, encoding='utf-8', errors='replace'
         )
         time.sleep(TSHARK_STARTUP_WAIT_SEC) # Allow time for startup errors

         if process.poll() is not None: # Check if process terminated quickly
             stderr_output = process.stderr.read() if process.stderr else ""
             logger.error(f"tshark process terminated unexpectedly (exit code: {process.returncode}). Check permissions, interface, filter.")
             if stderr_output: logger.error(f"tshark stderr: {stderr_output.strip()}")
             return None # Failed to start
         else:
             logger.info("tshark process started successfully.")
             return process

    except Exception as e:
         logger.error(f"Failed to start tshark: {e}", exc_info=logger.level <= logging.DEBUG)
         return None

def _run_editcap(pcap_base_file: str, ssl_key_log_file: str, pcap_decrypted_file: str) -> bool:
    """Runs editcap to inject TLS keys into the captured pcap file."""
    editcap_path = shutil.which("editcap")
    if not editcap_path:
        logger.error("'editcap' not found in PATH. Cannot inject TLS keys.")
        return False
    if not os.path.exists(pcap_base_file):
         logger.error(f"Cannot inject keys: Raw pcap file '{pcap_base_file}' not found.")
         return False
    if os.path.getsize(pcap_base_file) == 0:
         logger.warning(f"Raw pcap file '{pcap_base_file}' is empty. Skipping key injection.")
         # Consider this success, as there's nothing to inject into
         return True

    cmd = [editcap_path, "--inject-secrets", f"tls,{ssl_key_log_file}", pcap_base_file, pcap_decrypted_file]
    logger.info(f"Running editcap to inject keys: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=30)
        logger.info(f"Successfully injected keys into '{pcap_decrypted_file}'")
        if result.stdout: logger.debug(f"editcap stdout:\n{result.stdout.strip()}")
        if result.stderr: logger.debug(f"editcap stderr:\n{result.stderr.strip()}")
        return True
    except FileNotFoundError:
        logger.error(f"Error running editcap: Command not found at '{editcap_path}'.")
    except subprocess.CalledProcessError as e:
        logger.error(f"editcap failed (exit code {e.returncode}):")
        if e.stdout: logger.error(f"  stdout: {e.stdout.strip()}")
        if e.stderr: logger.error(f"  stderr: {e.stderr.strip()}")
    except subprocess.TimeoutExpired:
        logger.error("editcap command timed out.")
    except Exception as e:
        logger.error(f"Unexpected error running editcap: {e}", exc_info=logger.level <= logging.DEBUG)
    return False

# --- Main Execution ---

def main() -> None:
    """
    Main function: Parses arguments, runs SIP client, handles streaming,
    manages packet capture, performs cleanup, and exits.
    """
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description=f"Python SIPREC Test Client with SRTP/RTP Streaming (v{USER_AGENT.split('/')[1]})",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="Requires pylibsrtp, soundfile, numpy. Sends BYE on exit if INVITE succeeded.\n"
               f"Default packet capture filters match Google Telephony ranges:\n"
               f"  SIP: TCP to/from {DEFAULT_CAPTURE_SIP_RANGE} port {DEFAULT_CAPTURE_SIP_PORT}\n"
               f"  Media: UDP to/from {DEFAULT_CAPTURE_MEDIA_RANGE}\n"
               "Use --capture-* arguments to override.\n"
               f"Stream saving creates WAV files for PCMA/PCMU, mapping based on SDP labels matching client offer ('{CLIENT_OFFERED_LABEL_1}', '{CLIENT_OFFERED_LABEL_2}')."
    )
    # Destination
    parser.add_argument("dest_number", help="Destination user/number part for Request-URI")
    parser.add_argument("dest_host", help="Destination SIP server hostname or IP address")
    parser.add_argument("-p", "--dest-port", type=int, default=DEFAULT_SIPS_PORT, help="Destination SIP server port (SIPS/TLS)")
    # Source
    parser.add_argument("-s", "--src-number", required=True, help="Source AOR (e.g., 'client@example.com')")
    parser.add_argument("--src-host", required=True, help="Source host FQDN or public IP (must be resolvable)")
    parser.add_argument("--src-display-name", default="PythonSIPRECClient", help="Source display name")
    # Local Network
    parser.add_argument("--local-port", type=int, default=0, help="Local TCP port for SIP (0=OS default)")
    # TLS
    parser.add_argument("--cert-file", required=True, help="Path to client TLS certificate file (PEM)")
    parser.add_argument("--key-file", required=True, help="Path to client TLS private key file (PEM, unencrypted)")
    parser.add_argument("--ca-file", help="Path to CA certificate file for server verification (PEM). Omit=INSECURE.")
    # SIP/SDP/Media
    parser.add_argument("--audio-encoding", default=DEFAULT_AUDIO_ENCODING,
                        help=f"Audio encoding ('NAME/Rate'). Supported: {list(AUDIO_ENCODING_TO_PAYLOAD_TYPE.keys())}. PCMA/PCMU for WAV saving.")
    parser.add_argument("--options-ping-count", type=int, default=0, help="Number of OPTIONS pings before INVITE.")
    parser.add_argument("--options-target-uri", help="Optional Request-URI for OPTIONS.")
    parser.add_argument("--call-info-url", help="URL for Call-Info header (e.g., CCAI conversation URL)")
    parser.add_argument("--srtp-encryption", default=DEFAULT_SRTP_ENCRYPTION, choices=SRTP_ENCRYPTION_CHOICES,
                        help="SRTP encryption profile to offer, or 'NONE' for plain RTP.")
    parser.add_argument("--audio-file", help="Path to 2-channel audio file (e.g., WAV) for streaming.")
    parser.add_argument("--packet-time", type=int, default=DEFAULT_PACKET_TIME_MS, help="RTP packet duration (ms)")
    parser.add_argument("--stream-duration", type=float, default=0, help="Max stream duration (sec, 0=until file end/Ctrl+C)")
    # Output/Saving
    parser.add_argument("--save-stream1-file", help=f"Save payload for label '{CLIENT_OFFERED_LABEL_1}' to this WAV file (PCMA/PCMU only).")
    parser.add_argument("--save-stream2-file", help=f"Save payload for label '{CLIENT_OFFERED_LABEL_2}' to this WAV file (PCMA/PCMU only).")
    # Tooling/Debug
    parser.add_argument("-d", "--debug", action="store_true", help="Enable DEBUG level logging.")
    # Packet Capture
    parser.add_argument("--pcap-file", help="Output file path for packet capture (requires tshark/editcap).")
    parser.add_argument("--capture-interface", default="any", help="Network interface for tshark ('any' needs root/admin).")
    parser.add_argument("--capture-sip-range", default=DEFAULT_CAPTURE_SIP_RANGE, help="IP/CIDR for SIP signaling capture.")
    parser.add_argument("--capture-sip-port", type=int, default=DEFAULT_CAPTURE_SIP_PORT, help="TCP port for SIP signaling capture.")
    parser.add_argument("--capture-media-range", default=DEFAULT_CAPTURE_MEDIA_RANGE, help="IP/CIDR for RTP/media capture (UDP).")

    args = parser.parse_args()

    # --- Logging Setup ---
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.getLogger().setLevel(log_level) # Root logger
    logger.setLevel(log_level) # Module logger
    encoder_logger.setLevel(log_level) # Encoder logger
    if log_level == logging.DEBUG: logger.debug("Debug logging enabled.")
    logger.info(f"SIPREC Client v{USER_AGENT.split('/')[1]} starting...")
    logger.info(f"Selected SRTP encryption offer: {args.srtp_encryption}")

    # Check SSLKEYLOGFILE
    ssl_key_log_file_path = os.environ.get('SSLKEYLOGFILE')
    if ssl_key_log_file_path: logger.info(f"SSLKEYLOGFILE detected: {ssl_key_log_file_path}")
    else: logger.info("SSLKEYLOGFILE environment variable not set. Set it to log TLS keys for decryption.")

    # --- Argument Validation ---
    if not _validate_args(args):
        sys.exit(1)

    # --- Initialize State ---
    client: SiprecTester | None = None
    stream_threads: list[threading.Thread] = []
    stop_stream_event = threading.Event()
    tshark_process: subprocess.Popen | None = None
    pcap_decrypted_file: str | None = None
    exit_code: int = 0 # Default exit code (success)

    try:
        # --- Start Packet Capture (if requested) ---
        tshark_process = _setup_tshark(args, ssl_key_log_file_path)
        if args.pcap_file and tshark_process is None:
            # _setup_tshark already logged the error
            raise RuntimeError("Packet capture (tshark) failed to start. Aborting.")

        # --- Connect SIP Client ---
        client = SiprecTester(args)
        client.connect() # Can raise ConnectionError, ValueError, OSError

        # --- Optional OPTIONS Pings ---
        if args.options_ping_count > 0:
            logger.info(f"Sending {args.options_ping_count} OPTIONS ping(s)...")
            ping_success_count = 0
            for i in range(args.options_ping_count):
                 if i > 0: time.sleep(OPTIONS_PING_DELAY_SEC)
                 if not client or not client.ssl_sock: # Check connection before each ping
                      logger.error(f"Connection lost before OPTIONS ping {i+1}. Aborting pings.")
                      raise ConnectionError("Connection lost during OPTIONS pings.")
                 if client.send_options(): ping_success_count += 1
            logger.info(f"OPTIONS ping sequence finished ({ping_success_count}/{args.options_ping_count} successful).")
            # Decide if failure is critical? For now, continue even if pings failed.

        # --- Send INVITE ---
        if not client or not client.ssl_sock: raise ConnectionError("Connection lost before INVITE.")
        logger.info("Proceeding to send INVITE...")
        invite_successful = client.send_invite() # Handles responses, sets dialog_established
        invite_cseq = client.cseq - 1 # CSeq number used for the INVITE (already incremented)

        # --- If INVITE Succeeded (2xx), Send ACK and Start Streaming ---
        if invite_successful:
            logger.info("INVITE successful (received 2xx), sending ACK.")
            if not client.send_ack(invite_cseq):
                # ACK sending failure usually means connection died. Logged by send_ack.
                logger.error("Failed to send ACK after successful INVITE. Session likely dead.")
                # Allow cleanup and potential BYE attempt (though it will likely fail)
                exit_code = 1

            # --- Setup and Start Media Streaming (if audio file provided) ---
            if args.audio_file and exit_code == 0: # Proceed only if ACK likely succeeded
                logger.info(f"Audio file specified ({args.audio_file}). Preparing media streaming...")
                sdp_answer_streams = client.last_invite_response_sdp_info

                if not sdp_answer_streams:
                    logger.error("No usable media descriptions found in SDP answer. Cannot stream.")
                    exit_code = 1
                else:
                    # Find streams matching the client's offered labels
                    logger.info(f"Mapping SDP answer streams to offered labels '{CLIENT_OFFERED_LABEL_1}' and '{CLIENT_OFFERED_LABEL_2}'...")
                    stream_info_1 = next((s for s in sdp_answer_streams if s.label == CLIENT_OFFERED_LABEL_1), None)
                    stream_info_2 = next((s for s in sdp_answer_streams if s.label == CLIENT_OFFERED_LABEL_2), None)

                    if not stream_info_1: logger.error(f"SDP answer missing stream for label '{CLIENT_OFFERED_LABEL_1}'.")
                    if not stream_info_2: logger.error(f"SDP answer missing stream for label '{CLIENT_OFFERED_LABEL_2}'.")

                    if stream_info_1 and stream_info_2:
                        logger.info("Found matching SDP streams for both labels.")
                        # --- Initialize SRTP Sessions (if needed) based on parsed answer ---
                        srtp_session_1: pylibsrtp.Session | None = None
                        srtp_session_2: pylibsrtp.Session | None = None
                        try:
                            # Validate essential info (IP/Port) before proceeding
                            if not stream_info_1.connection_ip or stream_info_1.port <= 0 or \
                               not stream_info_2.connection_ip or stream_info_2.port <= 0:
                                 raise ValueError("Missing required IP/Port in mapped SDP streams.")

                            # Setup SRTP for stream 1 if negotiated
                            if stream_info_1.protocol == "RTP/SAVP":
                                if stream_info_1.crypto_suite and stream_info_1.crypto_key_material:
                                    profile = SDP_SUITE_TO_PYLIBSRTP_PROFILE.get(stream_info_1.crypto_suite)
                                    if profile is None: raise ValueError(f"Unsupported SRTP suite '{stream_info_1.crypto_suite}' for label {CLIENT_OFFERED_LABEL_1}")
                                    policy = pylibsrtp.Policy(key=stream_info_1.crypto_key_material, ssrc_type=pylibsrtp.Policy.SSRC_ANY_OUTBOUND, srtp_profile=profile)
                                    srtp_session_1 = pylibsrtp.Session(policy=policy)
                                    logger.info(f"Using SRTP for Stream 1 (Label {CLIENT_OFFERED_LABEL_1}, Suite: {stream_info_1.crypto_suite})")
                                else: raise ValueError(f"SAVP negotiated for label {CLIENT_OFFERED_LABEL_1} but missing crypto details.")
                            else: logger.info(f"Using plain RTP for Stream 1 (Label {CLIENT_OFFERED_LABEL_1})")

                            # Setup SRTP for stream 2 if negotiated
                            if stream_info_2.protocol == "RTP/SAVP":
                                if stream_info_2.crypto_suite and stream_info_2.crypto_key_material:
                                     profile = SDP_SUITE_TO_PYLIBSRTP_PROFILE.get(stream_info_2.crypto_suite)
                                     if profile is None: raise ValueError(f"Unsupported SRTP suite '{stream_info_2.crypto_suite}' for label {CLIENT_OFFERED_LABEL_2}")
                                     policy = pylibsrtp.Policy(key=stream_info_2.crypto_key_material, ssrc_type=pylibsrtp.Policy.SSRC_ANY_OUTBOUND, srtp_profile=profile)
                                     srtp_session_2 = pylibsrtp.Session(policy=policy)
                                     logger.info(f"Using SRTP for Stream 2 (Label {CLIENT_OFFERED_LABEL_2}, Suite: {stream_info_2.crypto_suite})")
                                else: raise ValueError(f"SAVP negotiated for label {CLIENT_OFFERED_LABEL_2} but missing crypto details.")
                            else: logger.info(f"Using plain RTP for Stream 2 (Label {CLIENT_OFFERED_LABEL_2})")

                            # Common stream parameters from config/validation
                            codec_name, rate_str = args.audio_encoding.split('/')
                            sample_rate = int(rate_str)
                            payload_type = AUDIO_ENCODING_TO_PAYLOAD_TYPE[codec_name.upper()]
                            local_rtp_port1 = DEFAULT_SDP_AUDIO_PORT_BASE # Port offered for label 1
                            local_rtp_port2 = DEFAULT_SDP_AUDIO_PORT_BASE + 2 # Port offered for label 2

                            # Create and start streaming threads
                            thread1 = threading.Thread(target=stream_channel, daemon=True, name=f"Streamer-L{CLIENT_OFFERED_LABEL_1}-Ch0",
                                                       args=(0, args.audio_file, stream_info_1.connection_ip, stream_info_1.port,
                                                             payload_type, codec_name, sample_rate, args.packet_time,
                                                             srtp_session_1, local_rtp_port1, stop_stream_event,
                                                             args.stream_duration, args.save_stream1_file))
                            thread2 = threading.Thread(target=stream_channel, daemon=True, name=f"Streamer-L{CLIENT_OFFERED_LABEL_2}-Ch1",
                                                       args=(1, args.audio_file, stream_info_2.connection_ip, stream_info_2.port,
                                                             payload_type, codec_name, sample_rate, args.packet_time,
                                                             srtp_session_2, local_rtp_port2, stop_stream_event,
                                                             args.stream_duration, args.save_stream2_file))
                            stream_threads.extend([thread1, thread2])

                            logger.info("Starting media streaming threads...")
                            thread1.start()
                            thread2.start()

                            # Wait for threads to finish or Ctrl+C / Duration Limit / Error
                            logger.info("Streaming in progress. Press Ctrl+C to stop early.")
                            start_wait = time.monotonic()
                            while any(t.is_alive() for t in stream_threads):
                                 if stop_stream_event.is_set():
                                      logger.warning("Stop event detected during wait, likely due to thread error.")
                                      exit_code = 1 # Mark error if a thread signaled stop
                                      break
                                 if args.stream_duration and args.stream_duration > 0 and (time.monotonic() - start_wait > args.stream_duration + 1.0): # Add small grace period
                                      logger.info(f"Maximum stream duration ({args.stream_duration}s) reached. Signaling threads.")
                                      stop_stream_event.set()
                                      break
                                 time.sleep(0.2) # Check periodically

                            logger.info("Streaming wait loop finished.")
                            if not stop_stream_event.is_set() and not any(t.is_alive() for t in stream_threads):
                                 logger.info("Streaming threads appear to have completed normally.")

                        except (ValueError, pylibsrtp.Error) as stream_setup_err:
                            logger.error(f"Failed to setup media streaming: {stream_setup_err}", exc_info=args.debug)
                            exit_code = 1
                            stop_stream_event.set() # Ensure any partially started threads stop

                    else: # One or both labels not found
                        logger.error("Aborting streaming setup: Required media stream labels not found in SDP answer.")
                        exit_code = 1

            elif not args.audio_file and exit_code == 0:
                # INVITE OK, ACK OK, but no streaming requested
                logger.info("No audio file specified, skipping media streaming.")
                if args.save_stream1_file or args.save_stream2_file:
                     logger.info("Skipping saving streams (no audio file provided).")
                wait_time = 5
                logger.info(f"Holding SIP dialog open for {wait_time} seconds before sending BYE...")
                time.sleep(wait_time)

        # Handle INVITE failure (non-2xx response or critical error during processing)
        else:
             logger.error(f"INVITE failed or did not establish a usable dialog (Last Status: {client.last_invite_response_status if client else 'N/A'}). ACK/Streaming/BYE skipped.")
             exit_code = 1
             # No BYE should be sent here

    # --- Handle runtime exceptions ---
    except (ConnectionError, socket.gaierror, socket.timeout, ssl.SSLError, OSError, RuntimeError, ValueError) as e:
         logger.error(f"Execution Error: {e}", exc_info=args.debug)
         exit_code = 1
         stop_stream_event.set() # Signal threads to stop on error
    except KeyboardInterrupt:
         logger.info("Keyboard interrupt detected. Signaling stop and cleaning up...")
         exit_code = 2 # Specific exit code for Ctrl+C
         stop_stream_event.set()
    except Exception as e:
        logger.exception(f"An unexpected critical error occurred: {e}")
        exit_code = 1
        stop_stream_event.set()
    finally:
        # --- Unified Cleanup ---
        logger.info("Initiating cleanup...")

        # 1. Signal and wait briefly for streaming threads (if any started)
        if not stop_stream_event.is_set():
            logger.debug("Signaling potentially running stream threads to stop.")
            stop_stream_event.set()
        if stream_threads:
            logger.info("Waiting briefly for streaming threads to finish...")
            join_timeout = 1.5 # Slightly longer timeout
            start_join = time.monotonic()
            for t in stream_threads:
                try:
                    remaining_time = max(0.1, join_timeout - (time.monotonic() - start_join))
                    t.join(timeout=remaining_time)
                except Exception as join_err:
                    logger.warning(f"Error joining thread {t.name}: {join_err}")
            alive_threads = [t.name for t in stream_threads if t.is_alive()]
            if alive_threads: logger.warning(f"Threads still alive after cleanup wait: {alive_threads}")
            else: logger.info("Streaming threads finished.")

        # 2. Attempt to send BYE if dialog was established
        # client.dialog_established is updated by send_bye() or close()
        if client and client.dialog_established:
            logger.info("Attempting to send BYE to terminate session...")
            try:
                client.send_bye() # Logs success/failure internally
            except Exception as bye_err:
                 logger.error(f"Unexpected error during send_bye() call: {bye_err}", exc_info=args.debug)
        elif client: # Client exists but dialog not established/already terminated
             logger.debug("Skipping BYE attempt (dialog not established or already ended).")

        # 3. Close SIP connection
        if client:
            logger.info("Closing client SIP connection...")
            client.close() # Handles TLS unwrap and socket closure

        # 4. Stop packet capture process
        if tshark_process and tshark_process.poll() is None:
            logger.info(f"Stopping tshark process (PID: {tshark_process.pid})...")
            try:
                tshark_process.terminate()
                tshark_process.wait(timeout=TSHARK_TERMINATE_TIMEOUT_SEC)
                logger.info(f"tshark terminated (exit code: {tshark_process.returncode}).")
            except subprocess.TimeoutExpired:
                logger.warning(f"tshark didn't terminate gracefully, sending KILL.")
                tshark_process.kill()
                try: tshark_process.wait(timeout=2.0)
                except subprocess.TimeoutExpired: logger.error("tshark ignored KILL signal.")
            except Exception as e:
                logger.error(f"Error stopping tshark: {e}")
            finally:
                 time.sleep(0.5) # Allow filesystem flush
                 if os.path.exists(args.pcap_file): logger.info(f"Raw packet capture in '{args.pcap_file}'")
                 else: logger.warning(f"Pcap file '{args.pcap_file}' not found after capture.")
        elif tshark_process: # Process existed but already terminated
            logger.warning(f"tshark process (PID: {tshark_process.pid}) already terminated before cleanup (exit code: {tshark_process.returncode}). Capture might be incomplete.")

        # 5. Attempt to inject TLS keys into pcap using editcap
        if args.pcap_file and tshark_process is not None and ssl_key_log_file_path:
             # Generate decrypted filename only if needed
             base, ext = os.path.splitext(args.pcap_file)
             pcap_decrypted_file = f"{base}-decrypted{ext or '.pcapng'}"
             if os.path.exists(ssl_key_log_file_path):
                 _run_editcap(args.pcap_file, ssl_key_log_file_path, pcap_decrypted_file)
             else:
                 logger.warning(f"SSLKEYLOGFILE '{ssl_key_log_file_path}' not found. Skipping key injection.")
        elif args.pcap_file and args.srtp_encryption != "NONE" and not ssl_key_log_file_path:
             logger.info("SRTP used but SSLKEYLOGFILE not set, skipping key injection.")

        logger.info(f"SIPREC client finished with exit code {exit_code}.")
        sys.exit(exit_code)


if __name__ == "__main__":
    # Enforce Python version >= 3.8 (required for pylibsrtp and type hints)
    if sys.version_info < (3, 8):
         print("Error: This script requires Python 3.8 or later.", file=sys.stderr)
         sys.exit(1)
    main()