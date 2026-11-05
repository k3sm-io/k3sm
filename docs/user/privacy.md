# Privacy

What k3sm.app sends when it checks for an update, and what that still tells the server it asks.

## The App's Update Check

A release build of k3sm.app checks for a newer app with one request: a `GET` of

```
https://github.com/k3sm-io/k3sm/releases/latest/download/k3sm_release-index.p7m
```

The request carries:

- the fixed user agent `k3sm-app`, which names no version;
- no query string, no cookie and no credential;
- no header the app sets other than the user agent.

The session is ephemeral: it stores no cookie, cache or credential. It needs TLS 1.2 or later. GitHub
answers with a redirect to its content network, and the app follows it only to
`objects.githubusercontent.com` or `release-assets.githubusercontent.com`, over https with no port.
Every redirected request is rebuilt with the same fixed user agent, and a redirect to any other host
stops the check. The redirect target carries a signed query that belongs to GitHub, not to k3sm.

The app sends no installation identifier, no account name, no list of workloads or nodes, and no
version of k3sm or of the app.

## What It Still Reveals

The request is an ordinary HTTPS request, so the hosts that answer it see:

- **Your source address.** GitHub and its content network see the public address the request comes
  from.
- **The timing.** About a minute after the app starts and then about once a day, spread by a random
  offset (about every two days under Low power), and whenever you choose Check for Updates or
  Check Now.
- **That a k3sm app asked.** The URL and the `k3sm-app` user agent say that k3sm.app is the client.
- **The redirect host.** A request that follows the redirect reaches one of the two content hosts
  above, which see the same address and time.

What GitHub records and keeps is GitHub's practice. k3sm does not control it and this page makes no
claim about it.

## Turning It Off

Settings > Updates holds **Check for app updates automatically**, on by default. With it off, the app
sends the request only when you choose Check for Updates or Check Now. A development build never
sends it. The app does not check automatically while its first-run screen is showing.

## Other Network Requests

This page covers the app's own update check. `k3sm update check` and the server's hourly check run
from the command line and the server, and they read GitHub's release data; see
[Upgrade](upgrade.md#checking-for-an-update).
