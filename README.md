# stonewave-uptime

An outside uptime check for StoneWave's hosted services. Every 5 minutes a GitHub Actions run sends one `GET` to each target in [`targets.json`](targets.json). When a target fails twice in a row, it alerts StoneWave through a signed ops relay (email and Telegram). When the target passes again, it sends a recovery alert.

This repo is public so the 5-minute schedule costs nothing. It contains no application code, no customer data, and no credentials for the sites it checks.

## What it checks

| Target | Passes when |
|---|---|
| `orders-health`: `https://orders.stonewave.life/health` | HTTP 200 and `"ok": true`. The service answers 503 with `ok: false` when its database is down. |
| `orders-login`: `https://orders.stonewave.life/` | A redirect to `/login`. The service is up and still requires sign-in. |
| `www`: `https://www.stonewave.life/` | HTTP 200 |

Every request is a plain `GET`: no redirects followed, no cookies, no tokens. The checker identifies itself with `User-Agent: stonewave-uptime/1`.

## Alerts

| Alert | When |
|---|---|
| `uptime_down` | A target has failed 2 checks in a row, about 10 minutes. Sent once per incident. |
| `uptime_recovered` | The first passing check after an `uptime_down` |

- **Signing:** each alert is signed with HMAC-SHA256 (`x-sp-alert-signature: t=<unix>,v1=<hex>`) using a secret that the relay accepts only for uptime alerts. A leak of that secret can't be used to send any other kind of alert.
- **Duplicates:** alert ids are fixed per incident (`up-<target>-<start>`), so a retry after a failed delivery never alerts twice.
- **State between runs** lives in the Actions cache (`.uptime-state/`). When a run starts without it (the first run, or an empty cache), one failure is enough to alert, so a cache problem can't hide an outage. If state is lost in the middle of an incident, a second `uptime_down` may go out, and the recovery alert for the earlier one may not. The run log says `no saved state` when that happens.
- **If the relay can't be reached** (for example, www itself is down), the run fails. For scheduled runs, GitHub emails the failure to **the user who last edited the cron line** in `.github/workflows/uptime.yml`, provided that user has email on for failed Actions runs. That email is the fallback channel.
- **If this schedule stops,** StoneWave notices: a separate hourly job reads this workflow's status from the GitHub API and alerts when it's disabled or hasn't run for 2 hours.

## Setup (once)

1. **Settings → Secrets and variables → Actions → New repository secret.** Add:
   - `SP_ALERT_URL`: the ops relay endpoint.
   - `SP_UPTIME_ALERT_SECRET`: the uptime-only signing secret.
2. **Make the failure emails yours.** From the account that should receive them, edit `.github/workflows/uptime.yml` on github.com once. Change `*/5 * * * *` to `2-59/5 * * * *`, which also moves runs off the busy top of the hour. Then turn on GitHub → Settings → Notifications → Actions → email for failed workflows.
3. **Actions:** confirm the `uptime` workflow is enabled.
4. **Security → Private vulnerability reporting → Enable**, so the button that `SECURITY.md` points to exists.

Until the secrets are set, a passing run still succeeds, and a failing target fails the run so GitHub emails you.

## Drills

Actions → **uptime** → **Run workflow**:

| Drill | Expect |
|---|---|
| `fail` | One `uptime_down` for target `drill`. It checks a path that can't return 200 and alerts on the first failure. |
| `recover` | One `uptime_recovered`. It points the same drill check at `/health`. |
| `fallback` | A **failed run** and GitHub's failed-run email. The drill alert goes to an address that can't resolve (`relay.invalid`). This proves only the email settings of whoever starts the drill. |

Scheduled runs email a different person: their own actor. After setup, and after any re-enable, open the latest **scheduled** run and check it says it was triggered by the account that should get the failure emails. StoneWave's hourly status check also alerts if scheduled runs belong to an unexpected account.

To retry, start a new run from **Run workflow**. Re-running an old run also works; state is always restored from the newest copy.

## Keeping it running

- **GitHub turns off scheduled workflows in a public repo after 60 days without commits.** The hourly status check will alert. Re-enable the workflow at Actions → **uptime** → **Enable workflow**, from the account that should get the failure emails. Merging a Dependabot PR also counts as activity.
- **GitHub may run scheduled workflows late under load.** Expect roughly 5–15 minutes between runs.
- **Actions are pinned to full commit SHAs.** Dependabot opens a monthly PR when they move.
- **To add or change a target,** edit `targets.json`. Names must be lowercase letters, digits and dashes, up to 30 characters. URLs must be `https`. Don't put customer names or private paths in this public repo.

## Development

```sh
python3 -m unittest discover -s . -p 'test_*.py' -v
```

Standard library only (Python 3.10+). The `test` workflow runs the tests on every push and pull request, without any secrets.
