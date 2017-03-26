Caddy Developer Portal
======================

This is the backend service that powers the [Caddy website](https://github.com/caddyserver/website). It maintains the database of developer accounts, registered plugins, and cached builds.

**This program must be running in order to use the Download page, the User Guide pages, or the Developer Portal pages.** Those pages require content from the database that this program provides. You do not need to run this program unless you are working on the website and need those pages to work.

## Installation

Note: You do NOT need this program unless you are working on the Caddy website and need all pages to work.

```bash
$ go get github.com/caddyserver/devportal/cmd/devportal
```

## Basic Use

The `devportal` command can be run like so:

```bash
$ devportal -siteroot ~/caddy-website/site
```

You must provide the path to the root of the Caddy website. (Don't forget the "site" subfolder!)

This will create a database (or use an existing one) in the current directory, called caddy.db. You can change this with the `-db` flag.

Run `devportal -h` for a list of all flags and options.

With just this command, you will be able to use the documentation pages and developer portal (account) area of the site.

## Advanced Use

To use the build, deploy, or download functions of the developer portal, you will need to run a [Caddy build worker](https://github.com/caddyserver/buildworker). Make sure the dev portal can talk to the build worker by setting the same `BUILDWORKER_CLIENT_ID` and `BUILDWORKER_CLIENT_KEY` environment variables as you did for the build worker. If the build worker is listening on an address other than the default, tell the developer portal that address with the `-buildworker` command line option.

The dev portal caches successful builds. If you will be performing builds locally and don't want to clutter up your disk, set `-cachesize` to a small value (minimum 1, since all downloads are served from the cache).

Change the cache directory by setting `-cachedir` (default is "./cache"). However, keep in mind that any previous cache directories may still be referenced by the database, which stores an index of the cached builds. If you delete a cache directory, be sure to clear its entries from the database.

If you will be using any of the functions to send email, you need to set `SENDGRID_API_KEY` with your SendGrid API key.

The log can be found in devportal.log in the current directory, unless you change that with the `-log` option. It can also be set to `stdout` or `stderr`. Logs are rolled automatically.
