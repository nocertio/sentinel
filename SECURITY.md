# Security policy

Report suspected vulnerabilities through [NoCert contact](https://nocert.io/contact).
Identify the report as a security issue. Do not disclose an exploitable issue,
credentials, private keys or customer information in a public issue or pull request.
Start with a description and a synthetic reproduction; arrange a private channel
before sending sensitive artifacts.

The current disclosure policy is at [nocert.io/security](https://nocert.io/security).
Contact details and supported report languages are published in
[security.txt](https://nocert.io/.well-known/security.txt).

Use the latest stable Sentinel release. Older releases have no separate
maintenance branch or guaranteed backport window. Report affected versions and
whether the issue can be reproduced with the latest release. No response-time
SLA or bug bounty is promised here.

The agent runs in your environment and observes potentially sensitive internal
names and locations. Review the data inventory in the README, local permissions,
scan scope and Kubernetes RBAC before deployment. Never test against systems
without authorization.
