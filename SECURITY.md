# Security model

## Safety boundary

PhishGuard parses URL text locally. It never navigates to the URL, resolves DNS,
opens a socket, downloads content, checks a certificate, or calls a reputation
service. The submitted value is not stored.

## Limitations

- Every finding is a heuristic warning unless labeled as a directly parsed
  structural fact.
- `https://` means the URL declares HTTPS. It does not prove that a valid
  certificate exists or that the destination is trustworthy.
- Approximate registered-domain handling is not a full Public Suffix List
  implementation and can be wrong for multi-label suffixes.
- Brand matching covers a small demonstration list and can generate false
  positives or miss impersonation.
- A clean-looking URL can still lead to a compromised or malicious site.
- Do not paste URLs containing private access tokens, session IDs, or personal
  information into screenshots or public reports.

When uncertain, navigate independently using a known bookmark and verify the
sender through a separate channel.
