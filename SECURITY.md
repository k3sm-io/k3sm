# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues** — for
a distribution that runs privileged (root) components, a public report is a disclosed
0-day before there is a fix.

Report privately, in order of preference:

1. **GitHub Private Security Advisories** — open the repository's **Security** tab and
   choose **Report a vulnerability** (GitHub's private advisory flow). This is the
   preferred channel: it is private, supports coordinated/embargoed collaboration, and
   can issue a CVE.
2. **Email** — <michelle@k3sm.io>. Use this if the advisory flow is unavailable to
   you, or if you would rather not open a GitHub account to make a report.
3. **Direct contact** — message the maintainer **[@kitsumiko](https://github.com/kitsumiko)** on GitHub.

k3sm runs **privileged components** (a root networking helper, process
sandboxing). Please treat **local privilege escalation** and **sandbox escape**
findings as high severity, and include the affected component and a reproduction.

## Supported versions

k3sm is **pre-release** — there are no supported release lines yet. Please report
against the latest `main`. A supported-versions policy will be published with the
first tagged release.

## Disclosure process

We follow **coordinated disclosure**: we will acknowledge your report, work on a
fix under embargo, and (unless you prefer otherwise) credit you when the fix is
released.
