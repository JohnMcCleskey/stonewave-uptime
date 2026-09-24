# Security

This repo holds only a GET-only uptime checker and its target list. It has no credentials for the monitored sites. It uses one secret: an alert-signing key that the relay accepts only for uptime alerts. That key is stored as a GitHub Actions secret, and only the scheduled or manually run `uptime` workflow reads it. Pull request workflows never do. Third-party actions are pinned to full commit SHAs.

Please report security issues privately through GitHub: **Security → Report a vulnerability** on this repository. Please don't open a public issue.
