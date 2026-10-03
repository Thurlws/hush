# Security

## Reporting a problem

Please report security problems privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**. Only the maintainer sees the
report. Please don't open a public issue for them.

It helps to include:

- what an attacker can do, and what they need first (nothing, a chat key, a seat in a
  chat, the server's files, ...)
- the version (`hushd -V` or `hush -V`) and how hush was built or installed
- steps, or a test, that show it happening

hush is maintained by one person in their spare time, so there's no fixed response
time, but security reports come before anything else.

## Supported versions

Only the latest release gets fixes. Right now that's 0.1.0.

## What's already known

[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) lists what hush protects and what it
doesn't, such as the metadata the server sees, browsers trusting the JavaScript the
server sends, and the lack of forward secrecy. Those are known limits rather than bugs,
but a report is still welcome if you've found a way to make one of them worse than the
threat model says.
