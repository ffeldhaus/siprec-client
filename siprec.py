#!/usr/env/bin python3
# -*- coding: utf-8 -*-

"""
A basic Python command-line client for testing SIPREC (RFC 7865) servers using TLS.
(Manual multipart body construction, no email library for INVITE body)

This script establishes a TLS connection to a SIPREC Session Recording Server (SRS),
optionally sends a configurable number of OPTIONS pings, sends a SIP INVITE request
containing SDP and SIPREC metadata, handles the response, sends an ACK, and then
closes the connection.

It requires client-side TLS certificates for authentication.

Optionally captures traffic to a temporary pcap file using tshark directly
if --pcap-file is provided. Requires tshark (from Wireshark suite) in PATH.
After capture, if SSLKEYLOGFILE is set and exists, it attempts to use 'editcap'
(also from Wireshark suite) to inject the TLS keys into a final pcapng file
(e.g., output.pcapng -> output-decrypted.pcapng).

Example Usage:
  # Basic usage with default PCMA/8000
  export SSLKEYLOGFILE=/path/to/keylog.txt # For Wireshark decryption (required for pcap)
  python siprec_client_manual_multipart.py \\
      +15551234567 srs.example.com \\
      --src-number siprec-client@example.com \\
      --src-host my.public.ip.address \\
      --cert-file /path/to/client.crt \\
      --key-file /path/to/client.key \\
      --ca-file /path/to/ca.crt \\
      --call-info-url "http://example.com/calls/unique-call-id" \\
      --options-ping-count 3

  # Usage specifying PCMU/8000
  python siprec_client_manual_multipart.py \\
      rec-target@domain srs.domain.tld \\
      --src-number client@client.domain.tld \\
      --src-host 1.2.3.4 \\
      --cert-file client.crt \\
      --key-file client.key \\
      --ca-file ca.crt \\
      --audio-encoding PCMU/8000

  # Usage with packet capture and key injection (using tshark directly)
  export SSLKEYLOGFILE=/tmp/sslkeys.log
  # Run with sudo if capturing on standard interfaces or using 'any'
  sudo python siprec_client_manual_multipart.py \\
      rec-target@domain srs.domain.tld \\
      --src-number client@client.domain.tld \\
      --src-host 1.2.3.4 \\
      --cert-file client.crt \\
      --key-file client.key \\
      --ca-file ca.crt \\
      --pcap-file /tmp/siprec_capture.pcapng # Request pcap capture
      --audio-encoding PCMA/8000 # Explicitly specify PCMA

  # After running, look for /tmp/siprec_capture-decrypted.pcapng
"""

import argparse
import logging
import os
import re
import select # Needed for improved _receive_response
import shutil # Needed for tshark/editcap path check
import socket
import ssl
import subprocess # Needed for tshark and editcap
import sys
import time
import uuid
from typing import Optional, Any, TypeAlias

# --- Type Aliases (for clarity) ---
SipHeaders: TypeAlias = dict[str, str | list[str]]
SipResponseParsed: TypeAlias = tuple[Optional[int], SipHeaders, bytes]
SipResponseRaw: TypeAlias = tuple[Optional[int], SipHeaders, bytes, bytes]

# --- Constants ---
LOG_FORMAT: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
SIP_VERSION: str = "SIP/2.0"
DEFAULT_SIPS_PORT: int = 5061
DEFAULT_MAX_FORWARDS: int = 70
VIA_BRANCH_PREFIX: str = "z9hG4bK"
USER_AGENT: str = "PythonSIPRECClient/1.6" # Version number updated
DEFAULT_SDP_AUDIO_PORT_BASE: int = 16000
EXAMPLE_CRYPTO_LINE: str = "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:j2br8Ob5L7fRd+1xyapRVhL+gG+ooQcenOpJl0gW"
CRLF: str = "\r\n"
CRLF_BYTES: bytes = b"\r\n"
DTMF_PAYLOAD_TYPE: int = 100 # Common payload type for telephone-event
DEFAULT_AUDIO_ENCODING: str = "PCMA/8000" # Default if not specified or invalid
TSHARK_STARTUP_WAIT_SEC: float = 2.0 # Time to wait after starting tshark to check for errors
TSHARK_TERMINATE_TIMEOUT_SEC: float = 5.0 # Time to wait for graceful tshark termination

# Mapping from common audio encoding names (uppercase) to RTP payload types
# Reference: https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml
AUDIO_ENCODING_TO_PAYLOAD_TYPE: dict[str, int] = {
    "PCMU": 0,  # G.711 PCMU (µ-law)
    "PCMA": 8,  # G.711 PCMA (A-law)
    "G722": 9,  # G.722
    "G729": 18, # G.729 Annex A
    # Add more mappings as needed (e.g., OPUS, G726 variants)
}


# Configure logging
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("siprec_client")
logger.setLevel(logging.INFO) # Default level, can be overridden by --debug


# --- Helper Functions ---

def generate_branch() -> str:
    """Generates a unique Via branch parameter (z9hG4bK...)."""
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
    Prefers IPv4. Raises error if lookup fails.
    """
    try:
        # Try IPv4 first
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        if addr_info:
            ip_address = addr_info[0][4][0]
            logger.debug(f"Resolved {hostname} to IPv4 {ip_address}")
            return ip_address
        else:
            # Try IPv6 if IPv4 fails (less common for SIP endpoints perhaps)
             logger.debug(f"No IPv4 found for {hostname}, trying IPv6...")
             addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM)
             if addr_info:
                  ip_address = addr_info[0][4][0]
                  logger.warning(f"Resolved {hostname} to IPv6 {ip_address}. Using IPv6.")
                  # Note: This script primarily assumes IPv4 elsewhere (e.g., SDP c= line)
                  # Full IPv6 support would require more changes.
                  return ip_address
             else:
                  raise socket.gaierror(f"No IPv4 or IPv6 address found for {hostname}")

    except socket.gaierror as e:
        logger.error(f"Could not resolve hostname '{hostname}': {e}")
        raise ValueError(f"Failed to resolve hostname {hostname}") from e
    except Exception as e:
        logger.error(f"Unexpected error resolving hostname '{hostname}': {e}")
        raise ValueError(f"Unexpected error resolving {hostname}") from e

def create_sdp(local_ip: str, local_port_base: int, audio_encoding_str: str) -> str:
    """Creates a sample SDP body using the specified audio encoding (ensures CRLF line endings)."""

    # --- Parse Audio Encoding ---
    encoding_name = ""
    sample_rate = 0
    payload_type = None

    try:
        parts = audio_encoding_str.split('/')
        if len(parts) == 2:
            encoding_name = parts[0].strip().upper() # Use upper case for dictionary lookup
            sample_rate = int(parts[1].strip())
            payload_type = AUDIO_ENCODING_TO_PAYLOAD_TYPE.get(encoding_name)
        else:
             raise ValueError("Invalid format") # Trigger fallback

    except (ValueError, IndexError, TypeError):
        logger.warning(f"Invalid or unsupported audio encoding format '{audio_encoding_str}'. "
                       f"Falling back to default '{DEFAULT_AUDIO_ENCODING}'.")
        audio_encoding_str = DEFAULT_AUDIO_ENCODING # Use default
        encoding_name = audio_encoding_str.split('/')[0].upper()
        sample_rate = int(audio_encoding_str.split('/')[1])
        payload_type = AUDIO_ENCODING_TO_PAYLOAD_TYPE.get(encoding_name)

    if payload_type is None:
        # This should only happen if DEFAULT_AUDIO_ENCODING is somehow not in the map
        logger.error(f"CRITICAL: Default encoding '{DEFAULT_AUDIO_ENCODING}' payload type not found in map! Using 8 (PCMA) as hard fallback.")
        payload_type = 8 # Hard fallback to PCMA
        encoding_name = "PCMA"
        sample_rate = 8000

    logger.info(f"Using audio encoding: {encoding_name}/{sample_rate} (Payload Type: {payload_type})")

    # --- Construct SDP ---
    # Note: Both m-lines will use the *same* negotiated audio codec from the argument
    sdp = f"""v=0
o=PythonSIPClient {int(time.time())} {int(time.time())+1} IN IP4 {local_ip}
s=SIPREC Test Call
t=0 0
m=audio {local_port_base} RTP/SAVP {payload_type} {DTMF_PAYLOAD_TYPE}
c=IN IP4 {local_ip}
a=label:1
{EXAMPLE_CRYPTO_LINE}
a=rtpmap:{payload_type} {encoding_name}/{sample_rate}
a=rtpmap:{DTMF_PAYLOAD_TYPE} telephone-event/8000
a=fmtp:{DTMF_PAYLOAD_TYPE} 0-15
a=sendonly
a=maxptime:20
m=audio {local_port_base+2} RTP/SAVP {payload_type} {DTMF_PAYLOAD_TYPE}
c=IN IP4 {local_ip}
a=label:2
{EXAMPLE_CRYPTO_LINE}
a=rtpmap:{payload_type} {encoding_name}/{sample_rate}
a=rtpmap:{DTMF_PAYLOAD_TYPE} telephone-event/8000
a=fmtp:{DTMF_PAYLOAD_TYPE} 0-15
a=sendonly
a=maxptime:20
"""
    # Ensure consistent CRLF endings
    return sdp.replace('\r\n', '\n').replace('\n', CRLF)


def create_siprec_metadata(
    config: argparse.Namespace,
    dest_number: str,
    dest_host: str
) -> str:
    """Creates sample SIPREC metadata XML (ensures CRLF line endings)."""
    timestamp: str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    session_id: str = generate_call_id() # SIPREC session ID, can differ from Call-ID

    conversation_id: str = "PY_TEST_CONV_" + uuid.uuid4().hex[:8]
    project_id: str = "unknown-project"
    if config.call_info_url:
        # Attempt to parse Google CCAI style URL
        try:
            url_to_parse = config.call_info_url
            # Handle potential unexpanded shell variables defensively
            if 'CID-$(' in url_to_parse:
                logger.warning("Call-Info URL seems to contain unexpanded shell command '$(uuidgen)'. Using placeholder.")
                url_to_parse = url_to_parse.split('CID-$(',1)[0] + "CID-GENERATED-" + uuid.uuid4().hex[:8]

            # Extract conversation ID (last path component)
            if '/' in url_to_parse.rstrip('/'):
                conversation_id = url_to_parse.rstrip('/').split('/')[-1]
            # Extract project ID
            if 'projects/' in url_to_parse:
                project_id = url_to_parse.split('projects/')[1].split('/')[0]
            logger.debug(f"Parsed from Call-Info URL: Project='{project_id}', Conversation='{conversation_id}'")
        except IndexError:
            logger.warning(f"Could not parse project/conversation ID from Call-Info URL: {config.call_info_url}")
        except Exception as e:
             logger.warning(f"Error parsing Call-Info URL ({config.call_info_url}): {e}")


    metadata = f"""<?xml version="1.0" encoding="UTF-8"?>
<recording xmlns="urn:ietf:params:xml:ns:recording:1">
  <session session_id="{session_id}">
    <associate-time>{timestamp}</associate-time>
  </session>
  <participant participant_id="src_participant_{generate_tag()}">
     <associate-time>{timestamp}</associate-time>
     <nameID aor="sip:{config.src_number}"/>
     <!-- Add more participant details as needed, e.g., <send>true</send> -->
  </participant>
    <participant participant_id="dest_participant_{generate_tag()}">
     <associate-time>{timestamp}</associate-time>
     <nameID aor="sip:{dest_number}@{dest_host}"/>
     <!-- Add more participant details as needed -->
  </participant>
  <stream stream_id="stream_label_1_{generate_tag()}" media_label="1">
      <associate-time>{timestamp}</associate-time>
      <label>Caller_Stream</label>
      <!-- <direction>sendonly</direction> -->
  </stream>
    <stream stream_id="stream_label_2_{generate_tag()}" media_label="2">
      <associate-time>{timestamp}</associate-time>
      <label>Callee_Stream</label>
      <!-- <direction>sendonly</direction> -->
  </stream>
  <extensiondata xmlns:google="http://google.com/siprec">
     <google:call id="{conversation_id}" project="{project_id}"/>
  </extensiondata>
</recording>
"""
    # Ensure consistent CRLF endings
    return metadata.replace('\r\n', '\n').replace('\n', CRLF)


def parse_sip_response(data: bytes) -> SipResponseParsed:
    """
    Parses a SIP response buffer into status code, headers, and body.
    Handles multi-line headers and case-insensitivity.
    """
    headers: SipHeaders = {}
    status_code: Optional[int] = None
    reason_phrase: str = ""
    body: bytes = b''

    try:
        header_part, body = data.split(CRLF_BYTES * 2, 1)
    except ValueError:
        # No double CRLF found, assume entire data is headers (or malformed)
        header_part = data
        body = b''
        logger.debug("No body found in response (no CRLFCRLF separator)")

    lines: list[bytes] = header_part.split(CRLF_BYTES)
    if not lines:
        logger.error("Received empty or malformed response data (no lines).")
        return None, {}, b''

    # Parse Status Line
    status_line: bytes = lines[0]
    match = re.match(rb'SIP/2.0\s+(\d{3})\s+(.*)', status_line, re.IGNORECASE) # Match SIP/2.0 case-insensitively
    if not match:
        logger.error(f"Could not parse status line: {status_line.decode(errors='ignore')}")
        # Try to return raw data if parsing fails completely
        return None, {}, body

    try:
        status_code = int(match.group(1))
        reason_phrase = match.group(2).decode(errors='ignore').strip()
        # Store reason phrase in headers dict for convenience? Or return separately? Let's put in headers.
        headers['reason-phrase'] = reason_phrase
    except (ValueError, IndexError):
         logger.error(f"Error parsing status code/reason from status line: {status_line.decode(errors='ignore')}")
         return None, {}, body # Return body even if status line parsing fails

    # Parse Headers
    current_key: Optional[str] = None
    for line in lines[1:]:
        line = line.strip() # Remove leading/trailing whitespace from the line itself
        if not line: # Skip empty lines between headers if any
            continue

        # Handle header continuation lines (starting with space or tab)
        if line.startswith(b' ') or line.startswith(b'\t'):
            if current_key and current_key in headers:
                value_to_append_bytes = b' ' + line.strip()
                try:
                    value_to_append_str = value_to_append_bytes.decode(errors='ignore')
                    current_value = headers[current_key]
                    if isinstance(current_value, list):
                        # Append to the last element of the list
                        headers[current_key][-1] += value_to_append_str
                    elif isinstance(current_value, str):
                        # Convert to list if it's the first continuation
                        headers[current_key] = [current_value + value_to_append_str]
                    # If headers[current_key] is somehow not str/list, log warning?
                except (IndexError, AttributeError, KeyError):
                     logger.warning(f"Error appending continuation line to header '{current_key}'")
                except Exception as e:
                     logger.warning(f"Unexpected error appending continuation line: {e}")
            else:
                logger.warning(f"Ignoring continuation line with no preceding header: {line.decode(errors='ignore')}")
            continue

        # Handle regular header lines (Key: Value)
        try:
            key_bytes, value_bytes = line.split(b':', 1)
            # Normalize key to lower case for consistent access
            key = key_bytes.strip().lower().decode(errors='ignore')
            value = value_bytes.strip().decode(errors='ignore')
            current_key = key # Store for potential continuation lines

            # Store headers that can appear multiple times as a list (e.g., Via, Route, Record-Route)
            # Simple approach: if key exists, convert to/append to list.
            if key in headers:
                existing_value = headers[key]
                if isinstance(existing_value, list):
                    existing_value.append(value)
                else:
                    # Convert existing single value to a list and add the new one
                    headers[key] = [existing_value, value]
            else:
                # First time seeing this header, store as string
                headers[key] = value
        except ValueError:
            # Line doesn't contain a colon, maybe malformed? Log it.
            logger.warning(f"Malformed header line (no colon?): {line.decode(errors='ignore')}")
            current_key = None # Reset current key as this line was invalid
        except Exception as e:
            logger.warning(f"Error processing header line '{line.decode(errors='ignore')}': {e}")
            current_key = None


    # Convert single-element lists back to strings for simplicity? Optional.
    # for key, value in headers.items():
    #     if isinstance(value, list) and len(value) == 1:
    #         headers[key] = value[0]

    return status_code, headers, body


# --- Main SIP Client Class ---
class SiprecTester:
    """
    Manages the SIPREC test session, including TLS connection and SIP messaging.
    (Uses manual multipart body construction)
    """
    def __init__(self, config: argparse.Namespace):
        """Initializes the SiprecTester."""
        self.config: argparse.Namespace = config # Store the config
        self.local_ip: str = get_ip_by_name(config.src_host)
        # Allow specifying local port 0 to let OS choose
        self.local_port: int = int(config.local_port) if config.local_port else 0

        self.call_id: str = generate_call_id()
        self.from_tag: str = generate_tag()
        self.to_tag: Optional[str] = None # Captured from 2xx response to INVITE
        self.cseq: int = 1 # Initial sequence number

        self.sock: Optional[socket.socket] = None
        self.ssl_sock: Optional[ssl.SSLSocket] = None
        self._last_branch: str = "" # Stores Via branch of last non-ACK request (for ACK Via)

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Creates an SSL context for TLS with client authentication."""
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        # Require TLS 1.2 or higher by default
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # --- Certificate Validation ---
        if not self.config.cert_file or not self.config.key_file:
            raise ValueError("Certificate file (--cert-file) and Key file (--key-file) must be specified for TLS")
        if not os.path.exists(self.config.cert_file):
             raise FileNotFoundError(f"Certificate file not found: {self.config.cert_file}")
        if not os.path.exists(self.config.key_file):
             raise FileNotFoundError(f"Key file not found: {self.config.key_file}")

        logger.info(f"Loading client cert: {self.config.cert_file}, key: {self.config.key_file}")
        try:
            context.load_cert_chain(certfile=self.config.cert_file, keyfile=self.config.key_file)
        except ssl.SSLError as e:
            logger.error(f"SSL Error loading client certificate/key: {e}")
            # Provide hints for common issues
            if "key values mismatch" in str(e):
                logger.error(f"Hint: Ensure certificate '{self.config.cert_file}' and private key '{self.config.key_file}' correspond to each other.")
            if "bad decrypt" in str(e) or "wrong password" in str(e):
                 logger.error(f"Hint: Ensure the private key '{self.config.key_file}' is not password-protected, or decrypt it first.")
            raise
        except Exception as e:
            logger.error(f"Unexpected error loading client certificate/key: {e}")
            raise

        # --- Server Verification ---
        if self.config.ca_file:
            if not os.path.exists(self.config.ca_file):
                 raise FileNotFoundError(f"CA file not found: {self.config.ca_file}")
            logger.info(f"Loading CA file for server verification: {self.config.ca_file}")
            try:
                context.load_verify_locations(cafile=self.config.ca_file)
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True # Verify server hostname against certificate SAN/CN
                logger.info("Server certificate verification enabled.")
            except ssl.SSLError as e:
                 logger.error(f"SSL Error loading CA file '{self.config.ca_file}': {e}")
                 raise
            except Exception as e:
                logger.error(f"Failed to load CA file '{self.config.ca_file}': {e}")
                raise
        else:
            # INSECURE: Disable server verification if no CA file provided
            logger.warning("*******************************************************")
            logger.warning("! WARNING: CA file (--ca-file) not provided.")
            logger.warning("! Disabling server certificate verification (INSECURE!).")
            logger.warning("! Connection is vulnerable to Man-in-the-Middle attacks.")
            logger.warning("*******************************************************")
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        # Log if SSLKEYLOGFILE is set for decryption purposes
        if os.environ.get('SSLKEYLOGFILE'):
             logger.info(f"SSLKEYLOGFILE detected ({os.environ['SSLKEYLOGFILE']}), TLS session keys will be logged by the SSL library.")
        else:
             logger.debug("SSLKEYLOGFILE environment variable not set.")

        return context

    def connect(self) -> None:
        """Establishes the TCP and TLS connection to the destination server."""
        context: ssl.SSLContext = self._create_ssl_context()
        # Bind to all interfaces ('') on the specified or ephemeral local port
        bind_addr: tuple[str, int] = ('', self.local_port)
        dest_addr: tuple[str, int] = (self.config.dest_host, self.config.dest_port)

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set socket options: timeout, reuse address (optional but often useful)
            self.sock.settimeout(10.0) # Connection timeout
            # Allow reusing the address quickly after script exits/crashes
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            if self.local_port != 0:
                 logger.info(f"Attempting to bind to local address {bind_addr[0]}:{bind_addr[1]}")
            self.sock.bind(bind_addr)
            # Get the actual IP and port we bound to
            actual_bound_ip, self.local_port = self.sock.getsockname()
            # Note: actual_bound_ip might be 0.0.0.0 if bound to '', use self.local_ip (resolved from src_host) for SIP headers.
            logger.info(f"Socket bound to {actual_bound_ip}:{self.local_port} (using address '{self.local_ip}' for SIP messages)")

            logger.info(f"Connecting to {self.config.dest_host}:{self.config.dest_port}...")
            self.sock.connect(dest_addr)
            logger.info("TCP connection established.")

            # Wrap socket for TLS
            # server_hostname is crucial for SNI and hostname verification if enabled
            self.ssl_sock = context.wrap_socket(self.sock, server_hostname=self.config.dest_host)
            logger.info(f"TLS handshake successful. Protocol: {self.ssl_sock.version()}, Cipher: {self.ssl_sock.cipher()}")
            try:
                peer_cert = self.ssl_sock.getpeercert()
                logger.debug(f"Peer certificate details: {peer_cert}")
            except ssl.SSLError:
                # This might happen if verification was disabled
                logger.warning("Could not get peer certificate details (verification might be disabled or cert missing).")

        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for destination host '{self.config.dest_host}': {e}")
            self._close_socket() # Ensure socket is closed on failure
            raise ConnectionError(f"DNS lookup failed for {self.config.dest_host}") from e
        except socket.timeout:
            logger.error(f"Timeout connecting to {dest_addr}")
            self._close_socket()
            raise ConnectionError(f"Timeout connecting to {dest_addr}") from socket.timeout
        except ssl.SSLCertVerificationError as e:
             # This error specifically happens if verify_mode=CERT_REQUIRED and validation fails
             logger.error(f"SSL Certificate Verification Error: {e}")
             if not self.config.ca_file:
                 logger.error("Hint: Server certificate verification failed. Provide the correct CA certificate using --ca-file.")
             else:
                 logger.error(f"Hint: Ensure '{self.config.ca_file}' contains the correct CA chain for the server '{self.config.dest_host}'.")
                 logger.error("Hint: Check if the server hostname matches the certificate's Common Name (CN) or Subject Alternative Name (SAN).")
             self._close_socket()
             # Re-raise as a generic SSLError or a more specific custom error? SSLError is fine.
             raise ssl.SSLError(f"Certificate verification failed: {e}") from e
        except ssl.SSLError as e:
             # Catches other SSL errors during handshake (wrong version, cipher mismatch, cert issues if verification off etc.)
             logger.error(f"SSL Error during handshake: {e}")
             if "CERTIFICATE_VERIFY_FAILED" in str(e) and not self.config.ca_file:
                 logger.error("Hint: Server certificate verification failed (or was disabled, but server requires valid client cert?). Provide a CA file using --ca-file if needed.")
             elif "WRONG_VERSION_NUMBER" in str(e):
                  logger.error("Hint: The server might not be speaking TLS on this port, or requires a different TLS/SSL version.")
             elif "HANDSHAKE_FAILURE" in str(e):
                  logger.error("Hint: Handshake failed. Check ciphers, TLS versions, or server/client certificate requirements.")
             self._close_socket()
             raise # Re-raise the original SSLError
        except OSError as e:
             # Catches OS-level errors like "Address already in use" during bind or "Network is unreachable" during connect
             logger.error(f"OS Error during connect/bind to {dest_addr} from port {self.local_port}: {e}")
             self._close_socket()
             raise ConnectionError(f"OS error during connection setup: {e}") from e
        except Exception as e:
            # Catchall for unexpected errors during connection setup
            logger.error(f"Unexpected error during connection: {e}")
            self._close_socket()
            raise ConnectionError(f"Unexpected error during connection: {e}") from e


    def _send_request(self, method: str, headers: dict[str, Any], body: bytes = b'') -> bool:
        """
        Constructs and sends a SIP request over the TLS connection.
        Calculates Content-Length based on the provided body. Handles CSeq incrementing.
        """
        if not self.ssl_sock:
            logger.error("Cannot send request: Not connected.")
            return False

        # --- Determine Request URI ---
        if method == "OPTIONS" and self.config.options_target_uri:
            request_uri: str = self.config.options_target_uri
        else:
            # Default Request-URI is sip:dest_number@dest_host:dest_port
            # Include port only if it's not the default SIPS port (5061)
            port_suffix = f":{self.config.dest_port}" if self.config.dest_port != DEFAULT_SIPS_PORT else ""
            request_uri = f"sip:{self.config.dest_number}@{self.config.dest_host}{port_suffix}"

        req_line: str = f"{method} {request_uri} {SIP_VERSION}"

        # --- CSeq Handling ---
        cseq_method = method # Method part of the CSeq header
        current_cseq_num: int
        if method == "ACK":
            # ACK uses the CSeq *number* from the INVITE it acknowledges.
            # It should be provided in the 'headers' dict passed to this function.
            try:
                cseq_header_val = str(headers.get('CSeq', '')) # Get CSeq from input headers
                current_cseq_num = int(cseq_header_val.split(maxsplit=1)[0])
                # Ensure the method part in the header is ACK
                headers['CSeq'] = f"{current_cseq_num} ACK"
            except (ValueError, IndexError, TypeError):
                 # Fallback: Assume INVITE was the last message sent before this ACK
                 invite_cseq_num = self.cseq - 1 if self.cseq > 1 else 1
                 logger.warning(f"Could not parse CSeq number for ACK from provided header: '{headers.get('CSeq')}'. Using previous CSeq number {invite_cseq_num}.")
                 current_cseq_num = invite_cseq_num
                 headers['CSeq'] = f"{current_cseq_num} ACK" # Correct the header
        else:
            # For other methods, use the current CSeq counter
            current_cseq_num = self.cseq

        # --- Via Header ---
        # Generate a new branch for non-ACK requests. ACK reuses INVITE's branch.
        branch: str = generate_branch()
        via_branch_to_use = self._last_branch if method == "ACK" else branch
        if method != "ACK":
             self._last_branch = branch # Store branch for potential future ACK

        via_header: str = f"{SIP_VERSION}/TLS {self.local_ip}:{self.local_port};branch={via_branch_to_use}"

        # --- From Header ---
        # Use the full source AOR (user@host) provided by user
        from_header: str = f"\"{self.config.src_display_name}\" <sip:{self.config.src_number}>;tag={self.from_tag}"

        # --- To Header ---
        # To header URI usually matches Request-URI target for initial requests.
        # For requests within a dialog (ACK, BYE), it must match the To from the initial response.
        to_port_suffix = f":{self.config.dest_port}" if self.config.dest_port != DEFAULT_SIPS_PORT else ""
        to_uri_part = f"sip:{self.config.dest_number}@{self.config.dest_host}{to_port_suffix}"
        to_header: str = f"\"SIPREC-SRS\" <{to_uri_part}>" # Display name is arbitrary
        # Add the To tag if we have one (i.e., we are in a dialog) AND it's not the initial INVITE
        # ACK *must* have the to_tag.
        if self.to_tag and (method != "INVITE" or method == "ACK"):
             # Check added for ACK specifically, as it might be passed in headers already
             if method == "ACK" and ";tag=" in headers.get("To",""):
                 logger.debug("Using To header passed explicitly for ACK.")
                 to_header = headers["To"] # Use the one passed in
             elif self.to_tag:
                 to_header += f";tag={self.to_tag}"

        # --- Contact Header ---
        # Provides the address where this client can be reached for future requests in this dialog
        contact_header: str = f"\"{self.config.src_display_name}\" <sip:{self.config.src_number.split('@')[0]}@{self.local_ip}:{self.local_port};transport=tls>"


        # --- Default Headers ---
        # These are standard headers included in most requests.
        default_hdrs: dict[str, Any] = {
            'Via': via_header,
            'From': from_header,
            'To': to_header,
            'Call-ID': self.call_id,
            'CSeq': f"{current_cseq_num} {cseq_method}", # Use the determined CSeq num and method
            'Max-Forwards': str(DEFAULT_MAX_FORWARDS),
            'Contact': contact_header,
            'User-Agent': USER_AGENT,
            'Content-Length': str(len(body)) # Calculated based on the final body
        }

        # --- Final Headers ---
        # Merge default headers with custom headers provided. Custom headers overwrite defaults.
        final_hdrs: dict[str, Any] = {**default_hdrs, **headers}
        # Ensure Content-Length is correct based on the actual body, even if passed in headers
        final_hdrs['Content-Length'] = str(len(body))

        # --- Construct Message ---
        message_lines: list[str] = [req_line]
        for key, value in final_hdrs.items():
            # Handle multi-value headers (like Via, if needed, though usually only one Via is added per hop)
            if isinstance(value, list):
                for v_item in value:
                    # Ensure keys are properly capitalized (Canonical form) - optional but good practice
                    canonical_key = '-'.join(word.capitalize() for word in key.split('-'))
                    message_lines.append(f"{canonical_key}: {v_item}")
            elif value is not None: # Skip headers explicitly set to None
                canonical_key = '-'.join(word.capitalize() for word in key.split('-'))
                message_lines.append(f"{canonical_key}: {value}")

        # Join lines with CRLF, add extra CRLF between headers and body
        full_message_str: str = CRLF.join(message_lines) + CRLF * 2
        # Combine headers string (encoded) with the body bytes
        full_message_bytes: bytes = full_message_str.encode('utf-8') + body

        # --- Logging ---
        logger.debug(f"--- Sending {method} (CSeq: {final_hdrs['CSeq']}) --->")
        # Log headers and body separately for potentially better readability
        logger.debug(full_message_str.strip()) # Log headers part
        if body:
             try:
                  # Try decoding body as UTF-8 for logging, replace errors
                  log_body = body.decode('utf-8', errors='replace')
                  logger.debug(CRLF + log_body.strip()) # Add separator for clarity
             except Exception:
                 # Fallback if decoding fails (e.g., unexpected binary data)
                 logger.debug(CRLF + f"<Body: {len(body)} bytes (undecodable as UTF-8)>")
        else:
            # Log explicitly if there's no body
            logger.debug(CRLF + "<No Body>")
        logger.debug("--- End Message --->")

        # --- Send Data ---
        try:
            self.ssl_sock.sendall(full_message_bytes)
            # Increment CSeq counter *after* successfully sending, but *not* for ACK
            if method != "ACK":
                 self.cseq += 1
            return True
        except socket.error as e:
            logger.error(f"Socket error sending {method}: {e}")
            # Assume connection is broken, trigger close
            self.close()
            return False
        except Exception as e:
             logger.error(f"Unexpected error sending {method}: {e}")
             self.close()
             return False

    def _receive_response(self, timeout: float = 10.0) -> SipResponseRaw:
        """
        Receives a SIP response from the TLS connection using select for timeout.
        Parses the response and returns status, headers, body, and raw data.
        """
        if not self.ssl_sock:
            logger.error("Cannot receive response: Not connected.")
            return None, {}, b'', b''

        # Use a bytearray buffer for efficient appending
        buffer: bytearray = bytearray()
        raw_buffer_log: bytearray = bytearray() # Separate log for all raw bytes received
        headers_parsed: bool = False
        content_length: Optional[int] = None
        expected_total_len: Optional[int] = None
        header_len: int = 0
        start_time = time.monotonic()

        try:
            while True:
                # Calculate remaining time for select
                elapsed_time = time.monotonic() - start_time
                if elapsed_time >= timeout:
                     logger.warning(f"Timeout ({timeout:.1f}s) waiting for response data.")
                     # Check if we received anything at all
                     if not raw_buffer_log:
                          logger.error("No data received before timeout.")
                     break # Exit loop on timeout

                # Wait for socket to become readable, with remaining timeout
                remaining_timeout = max(0.01, timeout - elapsed_time) # Ensure small positive timeout
                try:
                    # select() waits until the socket is readable or timeout occurs
                    readable, _, exceptional = select.select([self.ssl_sock], [], [self.ssl_sock], remaining_timeout)
                except ValueError:
                    # Can happen if socket is closed between loop iterations
                     logger.warning("Socket closed unexpectedly while waiting in select().")
                     break
                except Exception as sel_err:
                     logger.error(f"Error during select(): {sel_err}")
                     break # Exit loop on unexpected select error

                if exceptional:
                     logger.error("Socket reported exceptional condition during select().")
                     break
                if not readable:
                     # select timed out, means overall timeout is reached
                     if time.monotonic() - start_time >= timeout:
                          if not raw_buffer_log: logger.error("No data received before select() timeout.")
                          # else: Timeout occurred, but we might have partial data logged
                     # else: Spurious wakeup? Loop again, timeout check at top will handle it.
                     break # Exit loop on timeout

                # Socket is readable, attempt to receive data
                try:
                    # Read up to 4KB, non-blocking call shouldn't block long after select
                    chunk: bytes = self.ssl_sock.recv(4096)
                except (socket.timeout, ssl.SSLWantReadError):
                     # Should ideally not happen often after select, but handle defensively
                     logger.debug("Socket recv timed out or SSLWantReadError after select, retrying loop.")
                     time.sleep(0.01) # Small sleep before retrying select
                     continue
                except ssl.SSLError as ssl_err:
                     logger.error(f"SSL error during recv: {ssl_err}")
                     break # Assume connection error
                except socket.error as sock_err:
                    logger.error(f"Socket error receiving data: {sock_err}")
                    break # Assume connection error

                # Handle connection closed by peer
                if not chunk:
                    logger.warning("Connection closed by peer while receiving.")
                    # If headers were parsed and we expected more data, log it
                    if headers_parsed and content_length is not None and len(buffer) < expected_total_len:
                        logger.warning(f"Received only {len(buffer)} bytes, expected {expected_total_len} before close.")
                    elif not headers_parsed and buffer:
                         logger.warning("Connection closed before headers fully received or parsed.")
                    break # Exit loop if connection closed

                # Append received chunk to buffers
                raw_buffer_log.extend(chunk)
                buffer.extend(chunk)

                # --- Try parsing headers and determining body length ---
                # Only try parsing headers if not already done
                if not headers_parsed and CRLF_BYTES * 2 in buffer:
                    try:
                        header_part_bytes, body_part_bytes = buffer.split(CRLF_BYTES * 2, 1)
                        header_len = len(header_part_bytes) + len(CRLF_BYTES * 2)

                        # Use robust regex for Content-Length (case-insensitive)
                        cl_match = re.search(rb'^[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ll][Ee][Nn][Gg][Tt][Hh]\s*:\s*(\d+)\s*$', header_part_bytes, re.MULTILINE)
                        if cl_match:
                            content_length = int(cl_match.group(1))
                            expected_total_len = header_len + content_length
                            logger.debug(f"Found Content-Length: {content_length}. Expecting total {expected_total_len} bytes.")
                        else:
                            logger.debug("No Content-Length header found in response.")
                            # If no C-L, we have to rely on timeout or connection close to delimit message.
                            # This is handled by the loop's timeout/close checks.
                            # We cannot reliably determine 'expected_total_len' here.
                            pass # No C-L, keep reading until socket event

                        headers_parsed = True # Mark headers as processed

                    except ValueError:
                        # Split failed unexpectedly, should not happen if CRLFCRLF is present
                        logger.warning("Error splitting headers/body despite finding separator.")
                        # Proceed as if headers parsing failed for safety
                        headers_parsed = False
                    except Exception as parse_err:
                        logger.warning(f"Error parsing headers for Content-Length: {parse_err}.")
                        # Treat as if C-L was not found, but mark headers as 'parsed' conceptually
                        headers_parsed = True
                        content_length = None

                # --- Check if we have received the complete message (if C-L exists) ---
                if headers_parsed and content_length is not None:
                    if len(buffer) >= expected_total_len:
                        logger.debug(f"Received {len(buffer)} bytes, meet/exceed expected {expected_total_len}. Assuming complete message.")
                        # Trim any excess data read beyond Content-Length
                        if len(buffer) > expected_total_len:
                             logger.warning(f"Read {len(buffer) - expected_total_len} extra bytes past Content-Length.")
                             buffer = buffer[:expected_total_len]
                        break # Exit loop, message complete based on C-L
                    else:
                        # Need more data, continue reading
                        logger.debug(f"Received {len(buffer)} bytes, expecting {expected_total_len}. Reading more...")
                        pass # Continue loop

                # Safeguard against excessively large buffers if headers haven't been parsed yet
                # This prevents runaway memory usage if CRLFCRLF is never received.
                elif not headers_parsed and len(buffer) > 16384: # 16KB limit for headers part
                     logger.warning("Buffer exceeds 16KB without finding header end (CRLFCRLF). Treating received data as potentially incomplete/malformed response.")
                     break # Give up waiting for header end

                # If headers parsed but no C-L, the loop continues until timeout or close.

        except Exception as e:
             # Catch unexpected errors during the receive loop itself
             logger.exception(f"Unexpected error during receive loop: {e}")
             # Fall through to return whatever data we managed to collect

        # --- Process the final buffer ---
        # Log all raw data received during the operation
        if raw_buffer_log:
            logger.debug(f"--- Received Raw Response ({len(raw_buffer_log)} bytes total) ---")
            try:
                 # Decode using utf-8, replacing errors for logging purposes
                 logger.debug(bytes(raw_buffer_log).decode('utf-8', errors='replace'))
            except Exception as decode_err:
                 logger.debug(f"<Unable to decode raw buffer as UTF-8: {decode_err}>")
            logger.debug("--- End Raw Response ---")
        else:
            # This case happens if timeout occurred before *any* data was read
            logger.debug("No raw data was received.")
            # Ensure we return consistent empty values if buffer is also empty
            if not buffer: return None, {}, b'', b''

        # Parse the buffer we determined to be the message
        # (This might be incomplete if timeout/close happened without C-L)
        status, headers, body = parse_sip_response(bytes(buffer))

        if status is None and buffer: # Parsing failed, but we had some data
             logger.error("Failed to parse the received SIP response buffer.")
             # Return the raw buffer in body field for inspection, along with raw log
             return None, {}, bytes(buffer), bytes(raw_buffer_log)

        # Return parsed data and the full raw log
        return status, headers, body, bytes(raw_buffer_log)

    def send_options(self) -> bool:
        """Sends a SIP OPTIONS request to check server liveness/capabilities."""
        # Use the CSeq counter *before* this request is sent
        options_cseq = self.cseq
        logger.info(f"Sending OPTIONS ping (CSeq: {options_cseq})...")
        headers: dict[str, str] = {
            # Indicate what content types this client understands
            'Accept': 'application/sdp, application/vnd.google.siprec.metadata+xml, application/rs-metadata+xml',
        }
        # _send_request will increment self.cseq if successful
        if not self._send_request("OPTIONS", headers, b''):
             logger.error("Failed to send OPTIONS request.")
             return False

        # Use a shorter timeout for OPTIONS response
        status, headers_resp, body_resp, raw_resp = self._receive_response(timeout=5.0)

        if status is None:
             logger.error("No response received for OPTIONS request.")
             return False
        elif 200 <= status < 300:
            cseq_resp_str = headers_resp.get('cseq', 'N/A')
            logger.info(f"Received {status} {headers_resp.get('reason-phrase', '')} for OPTIONS (CSeq: {cseq_resp_str}). Connection alive.")
            # Log server capabilities if provided
            logger.debug(f"OPTIONS Response Headers: {headers_resp}")
            if body_resp:
                 logger.debug(f"OPTIONS Response Body:\n{body_resp.decode(errors='ignore')}")
            return True
        else:
            # Received an error response to OPTIONS
            cseq_resp_str = headers_resp.get('cseq', 'N/A')
            logger.error(f"Received non-2xx status for OPTIONS: {status} {headers_resp.get('reason-phrase', '')} (CSeq: {cseq_resp_str})")
            # Log the raw response for debugging error conditions
            logger.debug(f"Raw OPTIONS response:\n{raw_resp.decode(errors='ignore')}")
            return False

    def send_invite(
        self,
        custom_headers: Optional[dict[str, Any]] = None,
        custom_sdp: Optional[str] = None,
        custom_metadata: Optional[str] = None
    ) -> tuple[bool, int]:
        """
        Sends a SIPREC INVITE request with manually constructed multipart body.
        Uses the audio encoding specified in the configuration.
        Returns (success_boolean, invite_cseq_number).
        """
        invite_cseq_num: int = self.cseq # Capture CSeq number *before* sending INVITE
        logger.info(f"Sending SIPREC INVITE (CSeq: {invite_cseq_num})...")

        # --- Generate Content ---
        # Use configured audio encoding unless custom SDP is provided
        if custom_sdp:
             sdp_body_str = custom_sdp
        else:
             sdp_body_str = create_sdp(
                 self.local_ip,
                 DEFAULT_SDP_AUDIO_PORT_BASE,
                 self.config.audio_encoding # Use the configured encoding
             )
        sdp_bytes = sdp_body_str.encode('utf-8')

        metadata_body_str: str = custom_metadata if custom_metadata else create_siprec_metadata(
            self.config, self.config.dest_number, self.config.dest_host
        )
        metadata_bytes = metadata_body_str.encode('utf-8')

        # --- Manually Construct Multipart Body ---
        boundary: str = f"boundary-{uuid.uuid4().hex}"
        boundary_bytes = boundary.encode('utf-8')
        # Boundary line starts with "--"
        boundary_line = b'--' + boundary_bytes
        # Closing boundary line has "--" at the end as well
        closing_boundary_line = b'--' + boundary_bytes + b'--'

        parts = [] # List to hold byte strings of each part

        # Part 1: SDP
        parts.append(boundary_line)
        parts.append(b'Content-Type: application/sdp')
        parts.append(b'Content-Disposition: session; handling=required')
        # Content-Transfer-Encoding: 8bit is implied for text types usually, can be omitted
        # parts.append(b'Content-Transfer-Encoding: 8bit')
        parts.append(CRLF_BYTES) # Empty line separating headers from body
        parts.append(sdp_bytes) # The actual SDP content

        # Part 2: Metadata
        parts.append(boundary_line)
        # Use standard or Google-specific content type based on needs/config
        # Google specific: meta_content_type = b'application/vnd.google.siprec.metadata+xml'
        meta_content_type = b'application/rs-metadata+xml'
        parts.append(b'Content-Type: ' + meta_content_type)
        parts.append(b'Content-Disposition: recording-session; handling=required')
        # parts.append(b'Content-Transfer-Encoding: 8bit')
        parts.append(CRLF_BYTES) # Empty line separating headers from body
        parts.append(metadata_bytes) # The actual XML content

        # Add the final closing boundary line
        parts.append(closing_boundary_line)

        # Join all parts with CRLF to form the complete multipart body
        body_bytes = CRLF_BYTES.join(parts)

        # --- Prepare SIP Headers ---
        # These headers are for the main SIP INVITE message itself
        invite_headers: dict[str, Any] = {
            # Content-Type indicates the body is multipart/mixed with the specific boundary
            'Content-Type': f'multipart/mixed; boundary="{boundary}"',
            # Standard INVITE headers
            'Accept': 'application/sdp', # What we expect in response body (usually SDP)
            'Allow': 'INVITE, ACK, CANCEL, BYE, OPTIONS', # Methods this client supports
            'Supported': 'timer, replaces, 100rel', # SIP extensions supported
            'Require': 'siprec', # Crucial: Indicate this is a SIPREC session
            # Optional session timer headers
            'Session-Expires': '1800; refresher=uac', # Request session expires in 1800s, client refreshes
            'Min-SE': '90', # Minimum acceptable session expiry
            # Optional Call-Info for integration purposes (e.g., Google CCAI)
            'Call-Info': (f'<{self.config.call_info_url}>;purpose=Goog-ContactCenter-Conversation'
                          if self.config.call_info_url else None),
             # Allow overriding or adding headers via custom_headers argument
             **(custom_headers or {})
        }
        # Filter out any headers explicitly set to None (e.g., if Call-Info URL wasn't provided)
        invite_headers = {k: v for k, v in invite_headers.items() if v is not None}

        # --- Send the INVITE Request ---
        # _send_request handles adding standard headers (Via, From, To, Call-ID, CSeq, etc.),
        # calculating final Content-Length, and incrementing self.cseq.
        if not self._send_request("INVITE", invite_headers, body_bytes):
             logger.error("Failed to send INVITE request.")
             # Return failure and the CSeq that *would* have been used
             return False, invite_cseq_num

        # --- Receive and Process Responses ---
        # INVITE can receive multiple responses (1xx Provisional, then final 2xx-6xx)
        final_status: Optional[int] = None
        final_headers: SipHeaders = {}
        final_body: bytes = b''
        response_count = 0
        max_responses = 10 # Limit number of provisional responses to handle

        while response_count < max_responses:
            response_count += 1
            logger.debug(f"Waiting for INVITE response (attempt {response_count})...")
            # Use a longer timeout for INVITE as server might take time to process
            status, headers, body, raw = self._receive_response(timeout=30.0)

            # Handle no response / immediate timeout
            if status is None:
                if response_count == 1: # Only log full error if no response at all on first try
                     logger.error("Failed to receive any response (or timed out) for INVITE.")
                     if raw: logger.debug(f"Partial raw data received before failure:\n{raw.decode(errors='ignore')}")
                else: # If we got provisional(s) but then timed out waiting for final
                    logger.error(f"Timed out waiting for final response after receiving status {final_status}.")
                # Return failure and the CSeq used for the INVITE
                return False, invite_cseq_num

            # Log received response details
            reason = headers.get('reason-phrase', '')
            cseq_resp = headers.get('cseq', 'N/A')
            logger.info(f"Received response for INVITE: {status} {reason} (CSeq: {cseq_resp})")

            # Process based on status code
            if 100 <= status < 200: # Provisional response (e.g., 100 Trying, 180 Ringing, 183 Session Progress)
                logger.info(f"Received provisional response {status} {reason}. Waiting for final response.")
                final_status = status # Store the latest provisional status, but keep waiting
                # Optionally process headers/body from provisional response if needed (e.g., P-Asserted-Identity)
                if body: logger.debug(f"Provisional response body:\n{body.decode(errors='ignore')}")
                continue # Continue loop to wait for final response

            elif status >= 200: # Final response (2xx Success, 3xx Redirect, 4xx-6xx Failure)
                final_status = status
                final_headers = headers
                final_body = body
                # Received a final response, break the loop
                logger.debug(f"Received final response {status}. Processing result.")
                break
            else: # Should not happen (status < 100 is invalid)
                logger.warning(f"Received invalid status code {status}, ignoring and waiting.")
                final_status = status # Store it anyway, maybe helps debugging

        # --- Handle Final Response Outcome ---
        if final_status is None:
            # This case might happen if loop finishes due to max_responses without a final one
            logger.error(f"Loop finished after {response_count} responses without receiving a final (>=200) response for INVITE.")
            return False, invite_cseq_num

        # Check if the final status was a success (2xx)
        if 200 <= final_status < 300: # Success Case (e.g., 200 OK)
            logger.info(f"Received final {final_status} {final_headers.get('reason-phrase', '')} for INVITE. Call established (pending ACK).")
            logger.debug(f"Final Response Headers: {final_headers}")
            if final_body: logger.debug(f"Final Response Body (SDP):\n{final_body.decode(errors='ignore')}")

            # Critical: Capture the 'tag' parameter from the To header for ACK/BYE
            to_header = final_headers.get('to')
            to_tag_found = False
            # Handle possibility of multiple To headers (unlikely in 2xx but safer parsing)
            to_headers_list = to_header if isinstance(to_header, list) else [to_header] if to_header else []

            for hdr in to_headers_list:
                if isinstance(hdr, str):
                    # Use regex to find 'tag=' parameter
                    match = re.search(r'[;,\s]tag=([\w.-]+)', hdr) # Allow semicolon, comma, or space before tag=
                    if match:
                        self.to_tag = match.group(1)
                        to_tag_found = True
                        break # Found tag in one of the headers

            if to_tag_found:
                logger.info(f"Captured To tag from {final_status} response: {self.to_tag}")
                # Return success and the CSeq number used for this INVITE
                return True, invite_cseq_num
            else:
                # If we got a 2xx but no To tag, we cannot send ACK, so treat as failure.
                logger.error(f"CRITICAL: Received {final_status} success response, but could not find 'tag=' parameter in To header(s): {to_header}")
                return False, invite_cseq_num

        else: # Failure Case (>= 300)
            logger.error(f"INVITE failed with final status: {final_status} {final_headers.get('reason-phrase', '')}")
            # Log body if present, might contain failure details (e.g., Warning header)
            if final_body: logger.error(f"Failure Body:\n{final_body.decode(errors='ignore')}")
            return False, invite_cseq_num


    def send_ack(self, invite_cseq_num: int) -> bool:
        """
        Sends an ACK request to acknowledge a successful (2xx) INVITE response.
        Uses the CSeq number from the corresponding INVITE.
        """
        # ACK is only sent if INVITE was successful and we got a To tag
        if not self.to_tag:
             logger.error("Cannot send ACK: Missing To tag (should have been captured from INVITE 2xx response).")
             return False
        # ACK also needs the Via branch from the original INVITE
        if not self._last_branch:
             # This indicates an internal logic error if INVITE was sent but branch wasn't stored
             logger.error("Cannot send ACK: Missing Via branch from INVITE (internal error).")
             return False

        logger.info(f"Sending ACK for INVITE (CSeq: {invite_cseq_num} ACK)...")

        # --- Construct ACK Headers ---
        # ACK MUST use the same Call-ID, From tag as INVITE.
        # ACK MUST use the To tag received in the 2xx response.
        # ACK MUST use the CSeq *number* from INVITE, but with method ACK.
        # ACK MUST have a Via header with the same branch parameter as the INVITE Via.
        # Route headers: ACK MUST contain the same Route header fields as the INVITE. (We don't handle Route currently).

        ack_via: str = f"{SIP_VERSION}/TLS {self.local_ip}:{self.local_port};branch={self._last_branch}" # Use stored branch from INVITE
        ack_from: str = f"\"{self.config.src_display_name}\" <sip:{self.config.src_number}>;tag={self.from_tag}"

        # Construct To header for ACK using the captured to_tag
        to_port_suffix = f":{self.config.dest_port}" if self.config.dest_port != DEFAULT_SIPS_PORT else ""
        ack_to_uri = f"sip:{self.config.dest_number}@{self.config.dest_host}{to_port_suffix}"
        ack_to: str = f"\"SIPREC-SRS\" <{ack_to_uri}>;tag={self.to_tag}" # Essential: include received tag

        # Headers specific to ACK, passed to _send_request
        ack_headers: dict[str, str] = {
            'Via': ack_via, # Overrides default Via calculation in _send_request
            'From': ack_from, # Overrides default From
            'To': ack_to, # Overrides default To, includes tag
            'Call-ID': self.call_id, # Same Call-ID
            'CSeq': f"{invite_cseq_num} ACK", # Correct CSeq num and method
            'Max-Forwards': str(DEFAULT_MAX_FORWARDS), # Standard Max-Forwards
            'Content-Length': "0" # ACK never has a body
            # Contact header is optional in ACK
            # User-Agent will be added by _send_request
        }

        # Call _send_request with method ACK, specific headers, and empty body.
        # _send_request will *not* increment CSeq for ACK.
        ack_sent: bool = self._send_request("ACK", ack_headers, b'')

        if ack_sent:
            logger.info("ACK sent successfully.")
            return True
        else:
            # _send_request already logged the error
            logger.error("Failed to send ACK.")
            return False

    def _close_socket(self) -> None:
        """Internal helper to close the plain socket if it exists."""
        if self.sock:
             sock_fd = self.sock.fileno() # Get fd for logging
             logger.debug(f"Closing plain socket (fd={sock_fd})...")
             try:
                 # Check if socket is connected before trying shutdown, avoids errors
                 try:
                      peer = self.sock.getpeername()
                      logger.debug(f"Attempting shutdown(RDWR) on connected socket {sock_fd} to {peer}")
                      # Signal intent to close read/write ends of the connection
                      self.sock.shutdown(socket.SHUT_RDWR)
                 except (socket.error, OSError) as peer_err:
                      # Ignore errors like ENOTCONN (not connected), EBADF (bad fd)
                      if peer_err.errno not in (socket.errno.ENOTCONN, socket.errno.EBADF):
                           logger.warning(f"Error during shutdown() on socket {sock_fd}: {peer_err}")
                      else:
                           logger.debug(f"Socket {sock_fd} not connected or already down before shutdown.")
                 finally:
                      # Always attempt to close the socket descriptor
                      self.sock.close()
                      logger.debug(f"Plain socket (fd={sock_fd}) closed.")
             except (socket.error, OSError) as e:
                 logger.warning(f"Error closing plain socket (fd={sock_fd}): {e}")
             finally:
                # Ensure self.sock is None after attempting close
                self.sock = None


    def close(self) -> None:
        """Closes the TLS and underlying socket connection gracefully."""
        if self.ssl_sock:
            sock_fd = self.ssl_sock.fileno()
            logger.info(f"Closing TLS connection (underlying socket fd={sock_fd})...")
            try:
                # Perform TLS shutdown (sends close_notify) if possible
                # This might fail if the peer closed abruptly or socket is broken
                self.ssl_sock.unwrap() # Try to unwrap TLS layer cleanly
                logger.debug(f"TLS layer unwrapped for socket {sock_fd}.")
            except ssl.SSLError as e:
                 # Ignore errors related to socket being closed already during unwrap
                 if "SOCKET_CLOSED" in str(e).upper() or "WRONG_VERSION_NUMBER" in str(e): # Heuristic
                      logger.debug(f"Ignoring SSL error during unwrap (socket likely already closed): {e}")
                 else:
                      logger.warning(f"SSL error during unwrap() on socket {sock_fd}: {e}")
            except (socket.error, OSError) as e:
                 # Ignore "not connected" or "bad fd" errors
                 if e.errno not in (socket.errno.ENOTCONN, socket.errno.EBADF):
                      logger.warning(f"Socket error during unwrap() on socket {sock_fd}: {e}")
                 else:
                      logger.debug(f"Socket {sock_fd} closed or not connected during unwrap.")
            except Exception as e:
                 logger.warning(f"Unexpected error during unwrap() on socket {sock_fd}: {e}")
            finally:
                 # Always try to close the SSL socket object, which also closes the underlying socket
                 try:
                      self.ssl_sock.close()
                      logger.info(f"TLS connection closed (socket fd={sock_fd}).")
                 except (socket.error, OSError, ssl.SSLError) as e:
                      logger.warning(f"Error closing SSL socket object (fd={sock_fd}): {e}")
                 finally:
                      # Ensure both references are cleared
                      self.ssl_sock = None
                      self.sock = None # Underlying socket is closed by ssl_sock.close()
        elif self.sock:
             # If only plain socket exists (e.g., connection failed before TLS wrap)
             logger.info("Closing plain socket (no TLS layer)...")
             self._close_socket() # Use helper to close the plain socket
        else:
             # No connection was active or established
             logger.debug("No active connection to close.")


# --- Main Execution ---

def main() -> None:
    """Parses arguments, runs the SIPREC test client, optionally captures packets and injects keys."""

    # Check for SSLKEYLOGFILE environment variable
    ssl_key_log_file_path: Optional[str] = os.environ.get('SSLKEYLOGFILE')
    if ssl_key_log_file_path:
        print(f"INFO: SSLKEYLOGFILE environment variable detected: {ssl_key_log_file_path}", file=sys.stderr)
        print("INFO: TLS session keys will be logged by the SSL library.", file=sys.stderr)
        # Verify the directory exists and is writable? Optional sanity check.
        keylog_dir = os.path.dirname(ssl_key_log_file_path)
        if keylog_dir and not os.path.isdir(keylog_dir):
            print(f"WARNING: Directory for SSLKEYLOGFILE does not exist: {keylog_dir}", file=sys.stderr)
        # Cannot easily check write permissions here without trying to write.
    else:
        print("INFO: SSLKEYLOGFILE environment variable not set. Set it to log TLS keys for decryption (e.g., in Wireshark). Required for --pcap-file decryption.", file=sys.stderr)

    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Manual SIPREC Test Client using TLS (Python 3.9+). Uses tshark directly for capture.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="Packet capture requires tshark in PATH. Key injection requires 'editcap' (from Wireshark suite) in PATH and SSLKEYLOGFILE to be set. Capture/editcap often needs root/administrator privileges, especially when using '-i any'."
    )

    # Destination details
    parser.add_argument("dest_number", help="Destination user/number part for Request-URI (e.g., '+15551234567' or 'srs_service')")
    parser.add_argument("dest_host", help="Destination SIP server hostname or IP address (e.g., 'srs.example.com')")
    parser.add_argument("-p", "--dest-port", type=int, default=DEFAULT_SIPS_PORT, help="Destination SIP server port for SIPS/TLS")

    # Source details
    parser.add_argument("-s", "--src-number", required=True, help="Source address-of-record (AOR) for From/Contact headers (e.g., 'siprec-client@example.com')")
    parser.add_argument("--src-host", required=True, help="Source host FQDN or public IP for Via header and Contact URI host part (should match where this client runs)")
    parser.add_argument("--src-display-name", default="PythonSIPRECClient", help="Source display name for From/Contact headers")

    # Local network details
    parser.add_argument("--local-port", type=int, default=0, help="Local port to bind to (0=OS default, use specific if needed e.g., 5061). Ensure it's not already in use.")

    # TLS configuration
    parser.add_argument("--cert-file", required=True, help="Path to client TLS certificate file (PEM format)")
    parser.add_argument("--key-file", required=True, help="Path to client TLS private key file (PEM format, unencrypted recommended)")
    parser.add_argument("--ca-file", help="Path to CA certificate file for server verification (PEM format). If omitted, server certificate validation is DISABLED (INSECURE).")

    # SDP/SIPREC behavior
    parser.add_argument("--audio-encoding", default=DEFAULT_AUDIO_ENCODING,
                        help="Audio encoding for SDP in 'NAME/Rate' format (e.g., 'PCMU/8000', 'PCMA/8000'). "
                             f"Supported names: {', '.join(AUDIO_ENCODING_TO_PAYLOAD_TYPE.keys())}. "
                             "See IANA RTP Parameters for more info.")
    parser.add_argument("--options-ping-count", type=int, default=0, help="Number of OPTIONS pings to send before the INVITE. Useful for keep-alive or initial checks. Each ping completes before the next is sent.")
    parser.add_argument("--options-target-uri", help="Optional specific Request-URI for OPTIONS messages (e.g., 'sip:keepalive@example.com'). Defaults to the main destination URI if not set.")
    parser.add_argument("--skip-options", action="store_true", help="Skip the *very first* implicit OPTIONS check before the ping count loop or INVITE.")
    parser.add_argument("--call-info-url", help="URL for Call-Info header, e.g., 'http://<region>-dialogflow.googleapis.com/v2beta1/projects/<proj_id>/conversations/<conv_id>'")

    # Tooling/Debugging
    parser.add_argument("-d", "--debug", action="store_true", help="Enable DEBUG level logging for detailed output.")
    parser.add_argument("--pcap-file", help="Base output file path for packet capture (e.g., '/tmp/capture.pcapng'). Capture only runs if specified. Requires tshark. If SSLKEYLOGFILE is set, attempts to create a second file '<base>-decrypted.pcapng' with injected keys using 'editcap'.")
    parser.add_argument("--capture-interface", default="any", help="Network interface for tshark capture (e.g., 'eth0', 'en0', 'any'). 'any' often requires root/admin privileges.")


    args = parser.parse_args()

    # --- Logging Setup ---
    if args.debug:
        log_level = logging.DEBUG
        logging.getLogger().setLevel(log_level) # Set root logger level
        logger.setLevel(log_level) # Set specific client logger level
        logger.debug("Debug logging enabled.")
    else:
        log_level = logging.INFO
        logger.setLevel(log_level)

    # --- Argument Validation / Refinement ---
    # Validate source number format (basic check)
    if '@' not in args.src_number:
        logger.warning(f"Source number '{args.src_number}' doesn't contain '@'. Changing to {args.src_number}@{args.src_host}.")
        args.src_number = f"{args.src_number}@{args.src_host}"

    # Basic check for file existence before starting
    try:
         required_files = {'cert-file': args.cert_file, 'key-file': args.key_file}
         if args.ca_file: required_files['ca-file'] = args.ca_file
         for name, path in required_files.items():
              if not os.path.exists(path):
                   raise FileNotFoundError(f"Required file --{name} not found: {path}")
              if not os.path.isfile(path):
                   raise FileNotFoundError(f"Path specified for --{name} is not a file: {path}")
    except FileNotFoundError as fnf_error:
         print(f"Error: {fnf_error}", file=sys.stderr)
         sys.exit(1)

    # Validate audio encoding format (basic structure check)
    try:
        if '/' not in args.audio_encoding or not args.audio_encoding.split('/')[1].isdigit():
             raise ValueError("Invalid format")
        # Check if encoding name is known (optional, create_sdp handles fallback)
        enc_name = args.audio_encoding.split('/')[0].strip().upper()
        if enc_name not in AUDIO_ENCODING_TO_PAYLOAD_TYPE:
             logger.warning(f"Audio encoding name '{enc_name}' from '{args.audio_encoding}' is not explicitly mapped. Will attempt to use it, but SDP generation might default to '{DEFAULT_AUDIO_ENCODING}'.")
    except ValueError:
        logger.warning(f"Provided --audio-encoding '{args.audio_encoding}' is not in 'NAME/Rate' format. Using default '{DEFAULT_AUDIO_ENCODING}'.")
        args.audio_encoding = DEFAULT_AUDIO_ENCODING # Reset to default for consistency


    # --- Packet Capture Setup ---
    tshark_process: Optional[subprocess.Popen] = None # To hold the Popen object
    tshark_failed_to_start: bool = False # Flag if tshark launch fails
    pcap_base_file = args.pcap_file # Store the original requested path
    pcap_decrypted_file = None # Path for the file with injected keys
    tshark_path: Optional[str] = None # Store path to tshark executable

    # Conditions for attempting capture: pcap file requested
    if args.pcap_file:
        # Check if tshark executable is findable by shutil.which
        tshark_path = shutil.which("tshark")
        if tshark_path is None:
             logger.error("Packet capture requested (--pcap-file) but 'tshark' executable not found in system PATH. Please install Wireshark/tshark. Skipping capture.")
             tshark_failed_to_start = True # Mark as failed immediately
        else:
            # All conditions met, proceed with capture setup
            logger.info("Packet capture requested via --pcap-file. Capture will be attempted using tshark directly.")
            try:
                 # Resolve destination host IP for the capture filter
                 dest_ip = get_ip_by_name(args.dest_host)
                 # Create BPF filter to capture traffic to/from the destination IP and port
                 bpf_filter = f"host {dest_ip} and port {args.dest_port}"

                 # Determine the decrypted filename (if keys will be injected later)
                 if ssl_key_log_file_path:
                     base, ext = os.path.splitext(pcap_base_file)
                     pcap_decrypted_file = f"{base}-decrypted{ext if ext else '.pcapng'}" # Append -decrypted
                     logger.info(f"SSLKEYLOGFILE is set. Will attempt key injection into '{pcap_decrypted_file}' using editcap after capture.")
                 else:
                     logger.warning("SSLKEYLOGFILE is not set. Captured pcap file will not be automatically decrypted.")

                 # Construct tshark command
                 tshark_cmd = [
                     tshark_path,
                     "-i", args.capture_interface,
                     "-f", bpf_filter,
                     "-w", pcap_base_file,
                     # "-q", # Optionally quiet tshark's packet summary output
                 ]

                 logger.info(f"Starting packet capture via tshark...")
                 logger.info(f"  Command: {' '.join(tshark_cmd)}")
                 logger.info(f"  Output File (raw): {pcap_base_file}")
                 if args.capture_interface == 'any':
                     logger.info(f"  Interface: 'any' (may require root/admin privileges)")
                 else:
                     logger.info(f"  Interface: '{args.capture_interface}'")

                 # Start tshark as a background process
                 # Capture stderr to check for immediate errors
                 tshark_process = subprocess.Popen(
                     tshark_cmd,
                     stdout=subprocess.DEVNULL, # Discard packet summary stdout
                     stderr=subprocess.PIPE,
                     text=True, # Decode stderr as text
                     # Ensure process group leadership if needed for termination (usually not needed on Linux/macOS)
                 )

                 # Brief wait to allow tshark to start and potentially fail
                 logger.debug(f"Waiting {TSHARK_STARTUP_WAIT_SEC}s for tshark to initialize...")
                 time.sleep(TSHARK_STARTUP_WAIT_SEC)

                 # Check if tshark terminated prematurely
                 tshark_exit_code = tshark_process.poll()
                 if tshark_exit_code is not None:
                     # tshark exited, likely an error
                     stderr_output = ""
                     if tshark_process.stderr:
                         stderr_output = tshark_process.stderr.read()
                     logger.error(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                     logger.error(f"! tshark process terminated unexpectedly shortly after start (exit code: {tshark_exit_code}).")
                     logger.error(f"! Check permissions, interface name ('{args.capture_interface}'), filter syntax, or tshark installation.")
                     if stderr_output:
                         logger.error(f"! tshark stderr: {stderr_output.strip()}")
                     else:
                         logger.error(f"! (No stderr output captured)")
                     logger.error(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                     tshark_process = None # Clear the process object
                     tshark_failed_to_start = True # Mark as failed
                 else:
                     logger.info("tshark process appears to have started successfully.")

            # Handle specific errors during setup
            except (socket.gaierror, ValueError) as e:
                 logger.error(f"Failed to resolve destination host '{args.dest_host}' for capture filter: {e}. Skipping capture.")
                 tshark_failed_to_start = True
            except FileNotFoundError:
                 # Should be caught by shutil.which, but handle defensively
                 logger.error(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                 logger.error(f"! tshark executable not found at '{tshark_path}' during Popen.")
                 logger.error(f"! Packet capture disabled.")
                 logger.error(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                 tshark_failed_to_start = True
            except Exception as e:
                 # Catch other potential errors (permissions during Popen, etc.)
                 logger.error(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                 logger.error(f"! Failed to start tshark process: {e}")
                 logger.error(f"! Check tshark permissions, command arguments.")
                 logger.error(f"! Packet capture disabled.")
                 logger.error(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                 if tshark_process: # If Popen succeeded but something else failed
                     try:
                          if tshark_process.poll() is None: tshark_process.kill() # Ensure it's killed if started partially
                     except Exception: pass # Ignore errors during cleanup kill
                 tshark_process = None
                 tshark_failed_to_start = True

    # --- Main SIPREC Client Logic ---
    client: Optional[SiprecTester] = None # Initialize client object reference
    exit_code = 0 # Default exit code for success
    try:
        # Only proceed if capture didn't immediately fail (if requested)
        if tshark_failed_to_start:
            raise RuntimeError("Packet capture process (tshark) failed to start. Aborting.")

        # Instantiate and connect the client
        client = SiprecTester(args) # Pass parsed args
        client.connect() # Establish connection *after* capture has (potentially) started

        # Perform initial OPTIONS check unless skipped
        if not args.skip_options:
            if not client.send_options():
                logger.error("Initial OPTIONS check failed.")
                # Abort if no pings are requested, otherwise warn and proceed with pings
                if args.options_ping_count <= 0:
                     logger.error("Aborting test due to initial OPTIONS failure.")
                     raise ConnectionError("Initial OPTIONS check failed")
                else:
                     logger.warning("Proceeding with OPTIONS ping sequence despite initial OPTIONS failure. Connection might be unstable.")
            else:
                 logger.info("Initial OPTIONS check successful.")

        # Handle OPTIONS ping count if requested
        if args.options_ping_count > 0:
            logger.info(f"Starting OPTIONS ping sequence: {args.options_ping_count} pings requested.")
            pings_sent_ok = 0
            ping_success = True
            for i in range(args.options_ping_count):
                ping_number = i + 1
                logger.info(f"Sending OPTIONS ping {ping_number}/{args.options_ping_count}...")

                # Check connection status before sending each ping
                if not client or not client.ssl_sock:
                     logger.error(f"Connection lost before sending OPTIONS ping {ping_number}. Aborting.")
                     ping_success = False
                     break # Exit ping loop

                # Send the OPTIONS ping
                if not client.send_options():
                    logger.error(f"OPTIONS ping {ping_number}/{args.options_ping_count} failed. Aborting INVITE.")
                    ping_success = False
                    break # Exit ping loop
                else:
                     pings_sent_ok += 1
                     logger.info(f"OPTIONS ping {ping_number}/{args.options_ping_count} successful.")
                     # Optional small delay between pings if needed?
                     # time.sleep(0.1)

            # Check if ping sequence failed
            if not ping_success:
                 raise ConnectionError(f"OPTIONS ping sequence failed after {pings_sent_ok} successful pings.")
            else:
                 logger.info(f"OPTIONS ping sequence finished successfully ({pings_sent_ok}/{args.options_ping_count} pings sent).")

        # --- Send INVITE and ACK ---
        # Ensure connection is still active before proceeding
        if not client or not client.ssl_sock:
             logger.error("Connection is down before sending INVITE. Aborting.")
             raise ConnectionError("Connection lost before sending INVITE")

        logger.info("Proceeding to send INVITE...")
        invite_ok: bool
        invite_cseq: int # Capture the CSeq number used for the INVITE for ACK
        # send_invite now implicitly uses the encoding from the stored config
        invite_ok, invite_cseq = client.send_invite()

        if invite_ok:
            # INVITE received a 2xx response
            logger.info("INVITE successful (received 2xx), sending ACK.")
            # Send ACK using the CSeq number from the successful INVITE
            if client.send_ack(invite_cseq):
                 logger.info("ACK sent successfully. SIPREC test sequence complete.")
                 # Optional: Add a small delay here if useful for server processing or capture
                 # time.sleep(1)
            else:
                 # ACK failed to send (e.g., socket error)
                 logger.error("Failed to send ACK after successful INVITE. Session might be unstable.")
                 exit_code = 1 # Mark as failure if ACK fails
        else:
             # INVITE failed (no 2xx response or other error)
             logger.error("INVITE failed or did not receive a successful (2xx) response. ACK not sent.")
             exit_code = 1 # Mark as failure

    # --- Exception Handling ---
    except FileNotFoundError as e:
         # Handles errors finding cert/key/ca files during setup
         logger.error(f"Configuration Error: {e}")
         exit_code = 1
    except (ConnectionError, socket.gaierror, socket.timeout, ssl.SSLError, OSError, RuntimeError) as e:
         # Handles network/connection/runtime related errors (incl. tshark start failure)
         logger.error(f"Execution Error: {e}")
         exit_code = 1
    except KeyboardInterrupt:
         # Allows graceful exit on Ctrl+C
         logger.info("Keyboard interrupt detected. Cleaning up...")
         exit_code = 2 # Use a different exit code for user interrupt
    except Exception as e:
        # Catch any other unexpected exceptions during execution
        logger.exception(f"An unexpected critical error occurred: {e}")
        exit_code = 1
    # --- Cleanup ---
    finally:
        # Close client connection regardless of success or failure
        if client:
            logger.info("Closing client connection...")
            client.close()

        # Stop packet capture (tshark process) if it was started
        if tshark_process and tshark_process.poll() is None: # Check if exists and is running
            logger.info(f"Stopping tshark process (PID: {tshark_process.pid})...")
            try:
                # Try graceful termination first
                tshark_process.terminate()
                try:
                    # Wait for a short period
                    tshark_process.wait(timeout=TSHARK_TERMINATE_TIMEOUT_SEC)
                    logger.info(f"tshark process terminated gracefully (exit code: {tshark_process.returncode}).")
                except subprocess.TimeoutExpired:
                    logger.warning(f"tshark process did not terminate within {TSHARK_TERMINATE_TIMEOUT_SEC}s, sending KILL signal.")
                    tshark_process.kill()
                    try:
                        # Wait again after kill
                        tshark_process.wait(timeout=2.0)
                        logger.info(f"tshark process killed (exit code: {tshark_process.returncode}).")
                    except subprocess.TimeoutExpired:
                        logger.error("tshark process did not respond to KILL signal. Manual cleanup might be needed.")
                    except Exception as wait_err:
                         logger.error(f"Error waiting for tshark process after kill: {wait_err}")
                except Exception as term_err:
                     logger.error(f"Error during tshark process termination/wait: {term_err}")

                # Give the OS a moment to finalize file writing after process exit
                logger.debug("Waiting briefly for capture file to finalize...")
                time.sleep(1.0)
                logger.info(f"Packet capture stopped. Raw output should be in '{pcap_base_file}'")

            except Exception as e:
                # Log error during tshark cleanup, but don't change exit code
                logger.error(f"Error stopping tshark process: {e}")
        elif tshark_process and tshark_process.poll() is not None:
            # Handle case where tshark might have crashed *during* the run
            logger.warning(f"tshark process (PID: {tshark_process.pid}) was found already terminated before cleanup (exit code: {tshark_process.returncode}). Capture might be incomplete.")
        elif args.pcap_file and not tshark_failed_to_start and tshark_process is None:
             # Should not happen if logic is correct, but log it
             logger.warning("Capture file was requested, tshark didn't fail start, but process object is missing at cleanup.")


        # --- Attempt to inject keys using editcap ---
        # Run this only if capture was requested, didn't fail at start, and we have required info
        if args.pcap_file and not tshark_failed_to_start:
            if ssl_key_log_file_path and pcap_decrypted_file:
                logger.info(f"Attempting to inject TLS keys into pcap file using editcap...")
                # Check prerequisites for editcap
                editcap_path = shutil.which("editcap")
                if not editcap_path:
                    logger.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                    logger.error("! 'editcap' executable not found in system PATH.")
                    logger.error("! Please install Wireshark suite or ensure editcap is accessible.")
                    logger.error(f"! Cannot inject keys into '{pcap_base_file}'.")
                    logger.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                elif not os.path.exists(pcap_base_file):
                     logger.error(f"Cannot inject keys: Raw pcap file '{pcap_base_file}' not found or not created.")
                elif not os.path.exists(ssl_key_log_file_path):
                     logger.error(f"Cannot inject keys: SSLKEYLOGFILE '{ssl_key_log_file_path}' not found.")
                elif os.path.getsize(pcap_base_file) == 0:
                     logger.warning(f"Raw pcap file '{pcap_base_file}' is empty. Skipping key injection.")
                else:
                     # All prerequisites met, construct and run editcap command
                     cmd = [
                         editcap_path,
                         "--inject-secrets", f"tls,{ssl_key_log_file_path}",
                         pcap_base_file,
                         pcap_decrypted_file
                     ]
                     logger.debug(f"Running command: {' '.join(cmd)}")
                     try:
                         result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
                         logger.info(f"Successfully injected keys into '{pcap_decrypted_file}'")
                         if result.stdout: logger.debug(f"editcap stdout:\n{result.stdout}")
                         if result.stderr: logger.debug(f"editcap stderr:\n{result.stderr}")
                         # Optional: Delete the original raw pcap file?
                         # try:
                         #     os.remove(pcap_base_file)
                         #     logger.info(f"Removed original raw pcap file: {pcap_base_file}")
                         # except OSError as rm_err:
                         #     logger.warning(f"Could not remove original pcap file {pcap_base_file}: {rm_err}")
                     except FileNotFoundError:
                         # Should be caught by shutil.which, but handle defensively
                         logger.error(f"Error running editcap: Command not found at '{editcap_path}'.")
                     except subprocess.CalledProcessError as e:
                         logger.error(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                         logger.error(f"! editcap command failed with exit code {e.returncode}:")
                         if e.stdout: logger.error(f"  stdout: {e.stdout.strip()}")
                         if e.stderr: logger.error(f"  stderr: {e.stderr.strip()}")
                         logger.error(f"! Failed to create decrypted pcap file '{pcap_decrypted_file}'. Check keylog format and pcap file integrity.")
                         logger.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                     except subprocess.TimeoutExpired:
                         logger.error(f"editcap command timed out after 30 seconds.")
                     except Exception as e:
                         logger.error(f"An unexpected error occurred while running editcap: {e}")
            elif args.pcap_file and ssl_key_log_file_path and not pcap_decrypted_file:
                 # Should not happen if logic is correct, but log just in case
                 logger.warning("Capture ran and SSLKEYLOGFILE was set, but no decrypted file path was generated. Skipping key injection.")
            elif args.pcap_file and not ssl_key_log_file_path:
                 # This is the expected case when no keylog file is set
                 logger.info("SSLKEYLOGFILE not set, skipping key injection step.")
                 # No message needed if capture wasn't requested or failed to start

        logger.info(f"SIPREC client finished with exit code {exit_code}.")
        sys.exit(exit_code) # Exit with the determined code


if __name__ == "__main__":
    main()