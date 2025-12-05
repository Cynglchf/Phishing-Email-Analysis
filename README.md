# Phishing Email Analysis

The project aims to analyse and evaluate the data contained in a real phishing email. All URLs examined in this project are presented in a defanged format.

Do not visit these addresses under any circumstances unless you have the necessary expertise and a secure isolated environment.


# Phishing Email Content

The email is a phishing attempt designed to create a sense of urgency and threat prompting the recipient to click a link without careful consideration. While it appears to come from “McAfee,” it contains multiple signs of forgery and malicious intent. 
The email is shown below for reference:


<img width="1521" height="35" alt="Email" src="https://github.com/user-attachments/assets/f303504f-2326-4852-8212-44fa96d09c2f" />

<img width="1641" height="177" alt="Header" src="https://github.com/user-attachments/assets/2d1d8828-0024-458e-8a62-515f6eda633e" />

<img width="414" height="727" alt="Content" src="https://github.com/user-attachments/assets/bd18a763-adc9-4915-9cce-3810f133913c" />


The link shown in the message was presented as:

```hxxps[:]//storage[.]googleapis[.]com/...```

Based on my research this address belongs to Google Cloud Storage, which attackers often use to distribute malicious links. The attackers exploit a well-known service to create a sense of trust. Following the link redirects the user to the next website:

```hxxps[:]//www[.]sxzpqm8trk[.]com/```


<img width="1336" height="615" alt="Virustotal 1" src="https://github.com/user-attachments/assets/4e6ecd23-65d9-4270-b318-f5b2b9a044fa" />

<img width="361" height="414" alt="FalconSandbox" src="https://github.com/user-attachments/assets/dea767bd-dc2e-4666-b538-64a977113675" />


# Header Analysis

| Field | Value | Explanation |
| --- | --- | --- |
| From | McAfees partnerprogram <alerts@✓protection-parter✓> | Exploits a well-known brand. |
| Return Path | <> | Empty return path to bypass SPF checks. |
| Message-ID | *********@cryptomus.com  | Not related to McAfee |
| Sending Service | Mailgun (X-Mailgun-*) | Email was sent using a third-party mailing service Mailgun not an official McAfee mail server. |
| SCL | 8 | Spam filtering marked the message as High confidence spam |




# Authentication Results

| Test | Result | Explanation |
| --- | --- | --- |
| **SPF** | **PASS** | The attacker used Mailgun’s pre-approved SPF records. |
| **DKIM** | **FAIL** | DKIM signature is completely missing. |
| **DMARC** | **FAIL** | The domain has no DMARC record. |
| **ARC** | **FAIL** | Authentication chain is broken. Message marked as untrusted. |

# Originating IP Analysis

The source of the phishing email was traced to the first reliable "Received" header, which identified the actual sender as IP address ```15.***.***.***```. The reverse DNS lookup for this IP address returned the hostname:

https[:]//oz7e70p1[.]guardian[.]za[.]com

It is clear that the address is not related in any way to McAfee or any of the services claimed in the message.

This IP address was analyzed using multiple reputation and threat intelligence services, including [Cisco Talos Intelligence](https://talosintelligence.com/), [VirusTotal](https://www.virustotal.com/), and [AbuseIPDB](https://www.abuseipdb.com/) to determine any links to known malicious activity.

However, no reports or negative reputation were found for this IP address in the consulted services.

<img width="622" height="309" alt="AbuseIPDB" src="https://github.com/user-attachments/assets/b4e0e20c-46b9-4b1e-8b7c-286a2090408c" />

# Conclusion

This email was a clear example of a phishing attack. It combines social engineering, brand impersonation and technical obfuscation to increase the likelihood of a successful attack.

The email contained several indications of forgery, such as misleading sender address, an empty return path, missing DKIM and the absence of a DMARC policy. The email contains malicious links that exploit trusted services such as Google Cloud Storage to appear more credible. It was also classified as high-confidence spam (SCL = 8).
