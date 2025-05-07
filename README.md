# Python SIPREC TLS Test Client with SRTP/RTP Streaming

## Description

This command-line tool is a Python client designed for testing SIPREC (Session Recording Protocol, RFC 7865) Session Recording Servers (SRS). It focuses on establishing secure TLS connections with mutual authentication and streaming audio from a file using SRTP (Secure Real-time Transport Protocol) or plain RTP.

It establishes a TLS connection, optionally performs OPTIONS pings, sends a SIP INVITE with SDP (offering SRTP/RTP) and SIPREC metadata, handles the server's response (parsing SDP answer for media details like destination IP/port and SRTP keys), sends ACK, streams audio from a file in separate threads (one per channel, based on SDP labels), optionally saves the raw encoded streams to WAV files, sends BYE upon completion or interrupt, and closes the connection.

**IMPORTANT WARNING:** Based on current testing, using SRTP with encryption `AES_CM_128_HMAC_SHA1_32` is **known not to work reliably with Google SIP SBCs**. The negotiation may appear successful, but media does not flow correctly. Using `AES_CM_128_HMAC_SHA1_32` is the recommended and functional approach when targeting Google SIP SBCs.

It uses `pylibsrtp` for SRTP handling and `soundfile`+`numpy` for reliable G.711 audio encoding.

The client optionally integrates with `tshark` and `editcap` (from Wireshark) to capture network traffic and inject TLS keys for easier debugging in Wireshark, provided the `SSLKEYLOGFILE` environment variable is set.

## Features

*   Connects to SIPREC SRS using **TLS v1.2+** with client certificate authentication.
*   Sends SIP **INVITE** with `multipart/mixed` body (SDP & SIPREC XML metadata).
*   Offers configurable audio codecs in SDP (e.g., PCMA/8000, PCMU/8000).
*   Offers **SRTP** (SDES crypto attributes) or plain **RTP** based on `--srtp-encryption`.
*   Parses the server's SDP **answer** to determine RTP/SRTP destination IP/port and required SRTP keys.
*   Matches SDP answer media streams based on `a=label:` attributes (expects labels "1" and "2" corresponding to client offer).
*   Streams audio from a 2-channel audio file (e.g., WAV) using separate threads for each channel.
    *   Uses `pylibsrtp` for SRTP encryption/decryption context based on negotiated keys.
    *   Uses `soundfile` and `numpy` for robust G.711 (PCMA/PCMU) encoding.
*   Optionally saves the raw, *unencrypted* encoded audio payload for each stream to separate `.wav` files (requires PCMA/PCMU encoding).
*   Handles provisional (1xx) and final (2xx+) responses to INVITE.
*   Sends **ACK** for successful INVITE (2xx response).
*   Sends **BYE** on exit/interrupt if the INVITE established a dialog.
*   Optional **OPTIONS** pings before INVITE.
*   Optional **Packet Capture** using `tshark` and **TLS Decryption** using `editcap` (requires `SSLKEYLOGFILE`).
*   Detailed debug logging (`--debug`).

## Prerequisites

*   **Python 3.8 or higher.**
*   **Python Packages:** Install using pip:
    ```bash
    pip install pylibsrtp soundfile numpy
    ```
*   **Client TLS Certificate:** PEM-formatted certificate with Client Authentication EKU.
*   **Client Private Key:** Corresponding PEM-formatted *unencrypted* private key.
*   **CA Certificate Bundle (Recommended):** PEM file to verify the server's certificate (`--ca-file`). Omit=INSECURE.
*   **Audio File (Optional):** A 2-channel audio file (e.g., WAV, 8kHz) if streaming is desired (`--audio-file`).
*   **Network Connectivity:** Reachable SRS server on the specified SIPS port (e.g., 5061 TCP).
*   **(Optional, for Capture/Decryption)** `tshark` and `editcap` (from Wireshark) in system PATH.
*   **(Optional, for Decryption)** `SSLKEYLOGFILE` environment variable set to a writable file path *before* running the script.

## Setup Instructions (GCP Example)

These steps outline setting up a test environment on a Google Cloud VM.

### 1. Create VM

Use a small Debian VM (e.g., `e2-small`).
```bash
# Replace <YOUR_PROJECT_ID> and potentially zone
gcloud compute instances create siprec-client-vm \
    --project=<YOUR_PROJECT_ID> \
    --zone=us-central1-a \
    --machine-type=e2-small \
    --image-project=debian-cloud --image-family=debian-11 # Or newer

gcloud compute ssh siprec-client-vm --project=<YOUR_PROJECT_ID> --zone=us-central1-a
```

### 2. Install Dependencies on VM

```bash
sudo apt update && sudo apt upgrade -y
# Install Python 3.8+ (usually default on Debian 11+), pip, git, Wireshark tools
sudo apt install -y python3 python3-pip git wireshark-common tshark
# Install required Python libraries
pip3 install pylibsrtp soundfile numpy

# Optional: Allow non-root tshark capture (Logout/Login may be needed after adding group)
# sudo dpkg-reconfigure wireshark-common # Choose "Yes"
# sudo usermod -a -G wireshark $USER
```

### 3. Obtain Client TLS Certificate

*   The certificate **must** have the **Client Authentication** Extended Key Usage (EKU).
*   The CA must be trusted by your target SRS (check SRS documentation). Sectigo (via PositiveSSL) is often a cost-effective, trusted option for Google SBCs.
*   Prepare PEM files:
    *   `--cert-file` (e.g., `client_fullchain.crt`): Your client cert + intermediate CA cert(s). **Do not include the Root CA.**
        ```bash
        # Example: Concatenate received certs
        cat your_client_cert.crt intermediate_ca.crt > client_fullchain.crt
        ```
    *   `--key-file` (e.g., `client.key`): Your *unencrypted* private key. Secure it (`chmod 400`).
    *   `--ca-file` (e.g., `server_cas.pem`): The CA bundle to verify the *server*. For Google, use their trust bundle.

### 4. Deploy the Script

Clone the repository or copy the `siprec_client_streamer_pylibsrtp.py` script to the VM. Place your certificate and key files securely on the VM.

## Usage

```bash
# Set keylog file for potential decryption BEFORE running
export SSLKEYLOGFILE=/tmp/sslkeys.log

# Run the client
python siprec_client_streamer_pylibsrtp.py [OPTIONS] dest_number dest_host
```

### Arguments

*   `dest_number`: (Required) Destination user/number for Request-URI (e.g., `rec-target@domain`).
*   `dest_host`: (Required) Destination SRS hostname or IP.
*   `-p`, `--dest-port`: Destination SIPS/TLS port (Default: 5061).
*   `-s`, `--src-number`: (Required) Source AOR (e.g., `client@example.com`).
*   `--src-host`: (Required) Source public IP or FQDN for Via/Contact.
*   `--src-display-name`: Source display name (Default: "PythonSIPRECClient").
*   `--local-port`: Local SIP source port (Default: 0 = ephemeral).
*   `--cert-file`: (Required) Path to client cert file (PEM, with chain).
*   `--key-file`: (Required) Path to client private key file (PEM, unencrypted).
*   `--ca-file`: Path to CA bundle to verify server cert (PEM). Omit=INSECURE.
*   `--audio-encoding`: Audio codec ('NAME/Rate', Default: "PCMA/8000"). Supports PCMA, PCMU, G722, G729 etc. (PCMA/PCMU needed for WAV saving).
*   `--options-ping-count`: Number of OPTIONS pings before INVITE (Default: 0).
*   `--options-target-uri`: Specific Request-URI for OPTIONS.
*   `--call-info-url`: URL for `Call-Info` header.
*   `--srtp-encryption`: SRTP profile offer (Default: `AES_CM_128_HMAC_SHA1_80`). Choices: `AES_CM_128_HMAC_SHA1_80`, `AES_CM_128_HMAC_SHA1_32`, `NONE` (for plain RTP). **Use `NONE` for Google SBCs.**
*   `--audio-file`: Path to 2-channel audio file (e.g., WAV) for streaming. If omitted, no streaming occurs.
*   `--packet-time`: RTP packet duration in ms (Default: 20).
*   `--stream-duration`: Max stream duration in seconds (0 = full file / Ctrl+C).
*   `--save-stream1-file`: Save payload for label "1" to WAV file (PCMA/PCMU only).
*   `--save-stream2-file`: Save payload for label "2" to WAV file (PCMA/PCMU only).
*   `-d`, `--debug`: Enable DEBUG logging.
*   `--pcap-file`: Capture traffic to this base file (requires `tshark`). Appends `-decrypted` if `SSLKEYLOGFILE` is set and `editcap` runs.
*   `--capture-interface`: Network interface for `tshark` (Default: `any`, often needs root).
*   `--capture-sip-range`: IP/CIDR for SIP capture filter (Default: `74.125.88.128/25`).
*   `--capture-sip-port`: TCP port for SIP capture filter (Default: `5672`).
*   `--capture-media-range`: IP/CIDR for Media capture filter (Default: `74.125.39.0/24`).

## Examples

1.  **Basic Test (No Streaming, Default PCMA)**
    ```bash
    python siprec_client_streamer_pylibsrtp.py \
        rec-target@srs.example.com srs.example.com \
        --src-number sip:myclient@mydomain.com \
        --src-host my.public.vm.ip.address \
        --cert-file client_fullchain.crt \
        --key-file client.key \
        --ca-file server_cas.pem
    ```

2.  **Stream Plain RTP (Recommended for Google SBC), Save Streams**
    ```bash
    # Ensure audio.wav is 2-channel, 8000 Hz
    export SSLKEYLOGFILE=/tmp/sslkeys.log
    python siprec_client_streamer_pylibsrtp.py \
        rec-target@srs.google.com srs.google.com \
        --src-number sip:client@example.com \
        --src-host 1.2.3.4 \
        --cert-file client.crt --key-file client.key --ca-file google_cas.pem \
        --audio-file /path/to/audio.wav \
        --srtp-encryption NONE \
        --stream-duration 60 \
        --save-stream1-file /tmp/caller_stream.wav \
        --save-stream2-file /tmp/callee_stream.wav \
        --pcap-file /tmp/siprec_rtp.pcapng \
        --debug
    ```

3.  **Stream SRTP (May Fail on Google SBC), Capture**
    ```bash
    # Ensure audio.wav is 2-channel, 8000 Hz
    export SSLKEYLOGFILE=/tmp/sslkeys.log
    python siprec_client_streamer_pylibsrtp.py \
        rec-target@srs.example.com srs.example.com \
        --src-number sip:tester@mydomain.com \
        --src-host 203.0.113.50 \
        --cert-file client.crt --key-file client.key --ca-file server_cas.pem \
        --audio-file /path/to/audio.wav \
        --srtp-encryption AES_CM_128_HMAC_SHA1_80 \
        --pcap-file /tmp/siprec_srtp.pcapng \
        --capture-interface eth0 # Use specific interface if 'any' fails
    ```

## Streaming Details

*   If `--audio-file` is provided, the script expects a 2-channel audio file compatible with `soundfile` (e.g., WAV).
*   It parses the 200 OK SDP answer, looking for media descriptions (`m=audio...`) with `a=label:1` and `a=label:2`.
*   It extracts the destination IP, port, and SRTP parameters (if `RTP/SAVP` is negotiated and keys are parseable) for each labeled stream.
*   Two threads are started: one streams channel 0 to the target associated with label "1", the other streams channel 1 to the target for label "2".
*   Audio is read in chunks matching `--packet-time`, encoded using `soundfile` (to PCMA/PCMU), packetized into RTP, optionally encrypted using `pylibsrtp` (if SRTP context was created), and sent via UDP.
*   If `--save-streamX-file` is used, the *original encoded payload* (before SRTP encryption) is written to a WAV file with the correct headers. This requires the audio encoding to be PCMA or PCMU.

## Packet Capture & Decryption

*   `--pcap-file`: Enables capture using `tshark`. Requires `tshark` in PATH and potentially root privileges.
*   `SSLKEYLOGFILE`: Set this environment variable *before* running the script to a writable file path. Python's `ssl` module logs keys here.
*   `editcap`: If `SSLKEYLOGFILE` is set, `tshark` ran, and `editcap` is in PATH, the script attempts to inject the keys into the capture.
*   Output: `<pcap-file>` (raw) and `<pcap-file-base>-decrypted.pcapng` (if key injection succeeds). Open the decrypted file in Wireshark.

## Troubleshooting

*   **SRTP Fails (Especially Google SBC):** Use `--srtp-encryption NONE`. This is a known limitation.
*   **No Media Flows:** Check SDP negotiation in logs (`--debug`). Verify firewall rules allow UDP traffic from client's RTP ports (default `16000`, `16002`) to the server's advertised RTP/SRTP ports. Check if the server actually sent valid SDP answers.
*   **`soundfile` Errors / `libsndfile` not found:** `soundfile` relies on the `libsndfile` C library. Install it using your system's package manager (e.g., `sudo apt install libsndfile1` on Debian/Ubuntu).
*   **`pylibsrtp` Errors:** Ensure it's installed correctly (`pip install pylibsrtp`). It might have system dependencies (check its documentation if installation fails).
*   **Certificate Verification Failed:** See Setup section. Check CA trust, client cert EKU, chain order, key match.
*   **Handshake Errors (SSL/TLS):** Check TLS versions, ciphers. Ensure key is unencrypted. Use `--debug`.
*   **Connection Timeout/Refused:** Check SRS address/port, network reachability, firewalls (TCP 5061 typically).
*   **WAV Saving Fails:** Ensure `--audio-encoding` is `PCMA/8000` or `PCMU/8000`. Check file path permissions.
*   **`tshark`/`editcap` Not Found/Permission Errors:** Install Wireshark tools (`wireshark-common`), ensure they're in PATH. Run with `sudo` if needed for capture interface.
*   **Key Injection Fails:** Verify `SSLKEYLOGFILE` path/permissions, ensure it contains keys, check `editcap` logs.