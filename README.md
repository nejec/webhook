# webhook

A simple webhook server for use with Gophish events and send the payload to
Slack via webhook.

## Usage

```console
./webhook --help
usage: webhook [<flags>]

Flags:
      --help                 Show context-sensitive help (also try --help-long and --help-man).
  -u, --path="/webhook"      Webhook server path
  -p, --port="9999"          Webhook server port
  -h, --server=127.0.0.1     Server address
  -s, --secret=SECRET        Webhook secret
  -i, --slackHook=SLACKHOOK  Slack incoming webhook
  -c, --channel=CHANNEL      Slack channel to post notifications
  -e, --emoji=EMOJI          Slack notification emoji
  -n, --name=NAME            Slack username
      --loglevel="INFO"      Show debug information
```
