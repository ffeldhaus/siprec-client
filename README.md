# Python SIPREC TLS Test Client

## Description

This command-line tool is a basic Python client designed for testing SIPREC (Session Recording Protocol, RFC 7865) Session Recording Servers (SRS) that require TLS connections with mutual authentication (client certificate validation).

It establishes a secure TLS connection, optionally performs OPTIONS pings, sends a SIP INVITE request containing SDP (Session Description Protocol) and SIPREC metadata, handles the server's response, sends the required ACK, and then closes the connection. The SIP INVITE body uses a manually constructed `multipart/mixed` format.

A key feature is its optional integration with `tshark` (from the Wireshark suite) to directly capture the network traffic during the test session to a PCAPNG file. If the `SSLKEYLOGFILE` environment variable is set correctly *before* running the script, it will subsequently attempt to use `editcap` (also from Wireshark) to inject the captured TLS session keys into a second, decrypted PCAPNG file, allowing easy analysis in Wireshark.

## Features

*   Connects to SIPREC SRS using **TLS v1.2+**.
*   Supports **client certificate authentication**.
*   Sends configurable number of **OPTIONS** requests (pings) before INVITE.
*   Sends SIP **INVITE** requests compliant with SIPREC requirements (`Require: siprec`).
*   Constructs `multipart/mixed` body **manually** containing:
    *   `application/sdp` part
    *   `application/rs-metadata+xml` part (SIPREC metadata)
*   Configurable **audio codec** for SDP (e.g., PCMA/8000, PCMU/8000).
*   Handles provisional (1xx) and final (2xx+) responses to INVITE.
*   Sends **ACK** for successful INVITE (2xx response).
*   **Packet Capture:** Optionally captures traffic using `tshark` to a specified file.
*   **Decryption:** Optionally attempts to inject TLS keys from `SSLKEYLOGFILE` into the capture file using `editcap` for easy Wireshark decryption.
*   Provides detailed **debug logging**.

## Prerequisites

*   **Python 3.9 or higher.**
*   **Client TLS Certificate:** A valid PEM-formatted TLS certificate with the **Client Authentication** Extended Key Usage (EKU) enabled.
*   **Client Private Key:** The corresponding PEM-formatted *unencrypted* private key for the client certificate.
*   **CA Certificate Bundle (Recommended):** PEM-formatted file containing the Certificate Authority certificates needed to verify the **server's** TLS certificate. If omitted (`--ca-file`), server verification is disabled (INSECURE).
*   **Network Connectivity:** Ability to reach the target SRS server over TCP on the specified SIPS port (usually 5061).
*   **(Optional, for Packet Capture)** `tshark`: The command-line utility from the Wireshark suite must be installed and in the system's PATH.
*   **(Optional, for Packet Decryption)** `editcap`: Another command-line utility from Wireshark, also required to be in the PATH.
*   **(Optional, for Packet Decryption)** `SSLKEYLOGFILE` environment variable must be set to a valid file path *before* running the script.

## Setup Instructions

These instructions guide you through setting up a suitable environment on Google Cloud Platform (GCP) and obtaining the necessary TLS certificate.

### 1. Set up a Virtual Machine

We recommend using a small, cost-effective VM for running the client. An `e2-small` instance on GCP with the default Debian image is a good choice.

```bash
# Make sure you have gcloud CLI installed and configured
# Replace <YOUR_PROJECT_ID> and potentially zone/region
gcloud compute instances create siprec-client-vm \
    --project=<YOUR_PROJECT_ID> \
    --zone=us-central1-a \
    --machine-type=e2-small
```

Connect to your newly created VM via SSH:

gcloud compute ssh siprec-client-vm --project=<YOUR_PROJECT_ID> --zone=us-central1-a

### 2. Install Dependencies

Update the package list and install necessary software (Python 3, pip, Git, and Wireshark tools):

```
sudo apt update
sudo apt upgrade -y
sudo apt install -y python3 python3-pip git wireshark-common
```

Note: wireshark-common provides tshark and editcap. You might be prompted about non-superusers capturing packets during installation; select the appropriate option for your security needs.

If you want your user to be able to capture packages, you have to choose "yes" when prompted about capturing for non-superusers and need to add your user to the wireshark group with:
```
sudo usermod -a -G wireshark $USER
```

### 3. Obtain a Client TLS Certificate

This is a crucial step. The SIPREC SRS (like Google Cloud SIP SBC) will need to trust the Certificate Authority (CA) that issued your client certificate.

Requirement: The certificate MUST have the Client Authentication Extended Key Usage (EKU) OID (1.3.6.1.5.5.7.3.2).

Trusted CA: Ensure the CA is trusted by your target SRS. For Google Cloud SIP SBC, refer to their documentation for the list of trusted CAs. Sectigo is a trusted CA by the Google SBC.

Recommendation (Cost-Effective): PositiveSSL certificates, issued by Sectigo, are often the cheapest option that meets the requirements and is typically trusted by Google. Purchase a basic SSL certificate. During the Certificate Signing Request (CSR) generation process, ensure you specify details relevant to your client (e.g., a specific hostname or identifier for the Common Name (CN) or Subject Alternative Name (SAN)).

Certificate Chain:

When you receive your certificate from the CA (e.g., PositiveSSL/Sectigo), you typically get:

Your Client/End-entity Certificate.

One or more Intermediate CA Certificates.

The Root CA Certificate (sometimes provided, sometimes assumed to be in the trust store).

You need to prepare two main PEM files for the script:

--cert-file (e.g., client_fullchain.crt): This file MUST contain your client certificate followed by the intermediate CA certificate(s) in the correct order (client cert -> intermediate CA -> ... -> CA just below the root). Do NOT include the Root CA certificate in this file.

--key-file (e.g., client.key): This file MUST contain only the unencrypted private key corresponding to your client certificate. If your key is encrypted, decrypt it first (e.g., using openssl rsa).

You can concatenate the certificates into the client_fullchain.crt file like this:

```
# Assuming you received your_cert.crt and intermediate_ca.crt from Sectigo
cat your_cert.crt intermediate_ca.crt > client_fullchain.crt
```

Finding the Chain: Sectigo provides CA bundles. You can often find the necessary intermediates here (ensure you get the correct chain for your specific certificate type): Sectigo Support - Certificate Bundles (Link provided by user). Download the appropriate bundle and extract the intermediate(s).

--ca-file (e.g., server_cas.pem): This file is used by the client to verify the SRS server's certificate. If you are connecting to a Google Cloud service, you would typically use the Google Trust Services CA bundle. If you omit this flag, server certificate validation is disabled (not recommended). This file is not related to the client certificate chain you present to the server.

Security: Ensure your private key file (client.key) has strict permissions (chmod 400 client.key).

### 4. Deploy the Script

Clone the repository or download the siprec_client_manual_multipart.py script onto your VM:

```
# Example using Git
git clone <your-repo-url>
cd <your-repo-directory>
```

Place your prepared certificate (client_fullchain.crt) and key (client.key) files, and optionally the server CA file (server_cas.pem), in a secure location accessible by the script user on the VM.

#### Usage

```
# Run the client (use sudo if needed for packet capture on privileged interfaces)
SSLKEYLOGFILE=/tmp/sslkeys.log python siprec_client_manual_multipart.py [OPTIONS] dest_number dest_host
```

#### Arguments

dest_number: (Required) Destination user/number part for the SIP Request-URI (e.g., +15551234567, srs_service_address).

dest_host: (Required) Destination SIPREC SRS hostname or IP address (e.g., srs.example.com).

-p, --dest-port PORT: Destination SRS port for SIPS/TLS (Default: 5061).

-s, --src-number AOR: (Required) Source Address-of-Record (AOR) for From/Contact headers (e.g., sip:client@yourdomain.com). Needs to be a full SIP URI like user@host.

--src-host HOST_OR_IP: (Required) Source public IP or FQDN for Via/Contact host parts. Should be the address of the machine running the script.

--src-display-name NAME: Source display name for From/Contact (Default: "PythonSIPRECClient").

--local-port PORT: Local port to bind the client socket to (Default: 0, meaning OS assigns an ephemeral port).

--cert-file PATH: (Required) Path to the client TLS certificate file (PEM format, must include intermediates).

--key-file PATH: (Required) Path to the client TLS private key file (PEM format, unencrypted).

--ca-file PATH: Path to the CA certificate bundle file for verifying the SRS server's certificate (PEM format). If omitted, server certificate validation is disabled.

--audio-encoding CODEC: Audio encoding for SDP in 'NAME/Rate' format (Default: "PCMA/8000"). Supported: PCMU, PCMA, G722, G729 (see script for exact list). Example: --audio-encoding PCMU/8000.

--options-ping-count NUM: Number of OPTIONS pings to send sequentially before the INVITE (Default: 0).

--options-target-uri URI: Specific Request-URI for OPTIONS pings (Default: Uses main dest_number@dest_host). Example: --options-target-uri sip:ping@srs.example.com.

--skip-options: Skip the initial implicit OPTIONS check before pings/INVITE.

--call-info-url URL: URL to include in the Call-Info header (e.g., for Google CCAI integration).

-d, --debug: Enable detailed DEBUG level logging.

--pcap-file PATH: Capture traffic to this base file path (e.g., /tmp/capture.pcapng). Requires tshark. If SSLKEYLOGFILE is set, also attempts to create <PATH>-decrypted.pcapng using editcap.

--capture-interface IFACE: Network interface for tshark capture (Default: any). Using any or specific interfaces like eth0 often requires root/administrator privileges (sudo).

#### Examples

1. Basic Test (PCMA/8000, No Pings, No Capture)

```sh
python siprec_client_manual_multipart.py \
    rec-target@srs.example.com srs.example.com \
    --src-number sip:myclient@mydomain.com \
    --src-host my.public.vm.ip.address \
    --cert-file /path/to/client_fullchain.crt \
    --key-file /path/to/client.key \
    --ca-file /path/to/server_cas.pem
```

2. Test with PCMU/8000 and 3 OPTIONS Pings

```sh
python siprec_client_manual_multipart.py \
    +15551234567 srs.regional.example.net \
    --src-number sip:tester-01@mycompany.com \
    --src-host 203.0.113.10 \
    --cert-file client_fullchain.crt \
    --key-file client.key \
    --ca-file server_cas.pem \
    --audio-encoding PCMU/8000 \
    --options-ping-count 3
```

3. Test with Packet Capture and Decryption

```sh
SSLKEYLOGFILE=tls_keys.log python siprec_client_manual_multipart.py \
    srs-service srs.gcp.example.com \
    --src-number sip:siprec-gw@customer.com \
    --src-host vm-external-ip.example.net \
    --cert-file /etc/ssl/private/client_fullchain.crt \
    --key-file /etc/ssl/private/client.key \
    --ca-file /etc/ssl/certs/google_trust_services.pem \
    --call-info-url "http://example.com/calls/unique-id-123" \
    --pcap-file /tmp/siprec_test.pcapng \
    --capture-interface any \
    --debug # Enable debug for more verbose output
```

After running, look for:

/tmp/siprec_test.pcapng (Raw encrypted traffic)

/tmp/siprec_test-decrypted.pcapng (Decrypted traffic, viewable in Wireshark if key injection succeeded)

Check /home/user/tls_keys.log to ensure keys were logged.

Packet Capture & Decryption

The --pcap-file option enables packet capture during the script's execution.

tshark: The script invokes tshark in the background to capture packets matching the destination host and port on the specified --capture-interface.

Permissions: tshark often requires root privileges (sudo) to capture on interfaces like any or eth0. Ensure the user running the script (or root via sudo) has the necessary permissions.

Filter: It captures traffic to/from the resolved IP address of dest_host on port --dest-port.

Output: The raw capture is saved to the path specified by --pcap-file.

SSLKEYLOGFILE: For decryption to work, the SSLKEYLOGFILE environment variable must be set to a valid file path before you run the Python script. Python's ssl module will automatically log the TLS session keys to this file.

Permissions: Ensure the specified keylog file exists and is writable by the user running the script. Keep this file secure as it contains sensitive key material.

editcap: After the SIP session completes and tshark is stopped, if SSLKEYLOGFILE was set and editcap is found in the PATH, the script attempts to run editcap to inject the keys from the log file into the raw pcap file.

Output: A new file named <pcap-file-base>-decrypted.pcapng is created.

Verification: Open the -decrypted.pcapng file in Wireshark. If successful, the TLS/SIP traffic should be automatically decrypted. Check Wireshark's TLS preferences (Edit -> Preferences -> Protocols -> TLS) to ensure the (Pre)-Master-Secret log filename field is clear or pointing elsewhere, allowing editcap's embedded keys to be used.

### Troubleshooting

Permissions Denied (tshark/pcap): Run the script with sudo if capturing on privileged interfaces (any, eth0, etc.). Ensure the output directory for --pcap-file is writable.

Permissions Denied (SSLKEYLOGFILE): Ensure the path specified exists and is writable by the user running the script before execution.

Certificate Verification Failed:

Server cert: Ensure --ca-file points to the correct CA bundle for the SRS server, or omit it to disable verification (insecure). Check server hostname matches the certificate SAN/CN.

Client cert: Ensure the SRS trusts the CA that issued your client certificate (--cert-file). Verify the --cert-file contains the full chain (Cert + Intermediates). Verify the Client Authentication EKU is present. Ensure the --key-file matches the certificate.

Handshake Errors (SSL/TLS): Check TLS versions, cipher compatibility. Ensure the private key (--key-file) is not password-protected.

tshark/editcap Not Found: Ensure the Wireshark suite is installed correctly and the tools are in your system's PATH (which tshark, which editcap).

Connection Timeout/Refused: Verify the dest_host and dest_port are correct and reachable. Check firewalls (on the client VM, GCP network, and the SRS side) allow traffic on the destination port (e.g., TCP 5061).

DNS Resolution Error: Ensure dest_host and --src-host can be resolved by the VM. Check /etc/resolv.conf.

Key Injection Fails: Verify SSLKEYLOGFILE was set correctly before running, contains valid key entries, and editcap executed without errors (check script logs). Ensure the raw pcap file (--pcap-file) was created and is not empty.