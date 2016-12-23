Caddy Developer Portal
======================

*Currently under heavy construction*

This is the web service that powers the [Caddy website](https://github.com/caddyserver/website). It maintains the database of developer accounts, registered plugins, and cached builds.


## Basic Usage

The `devportal` command can be run like so:

```bash
$ devportal
```

This will create a database (or use an existing one) in the current directory, called caddy.db. You can change this with the `-db` flag.

To use the build, deploy, or download functions of the developer portal, you will need to run a [Caddy build worker](https://github.com/caddyserver/buildworker). Make sure the dev portal can talk to the build worker by setting the same `BUILDWORKER_CLIENT_ID` and `BUILDWORKER_CLIENT_KEY` environment variables as you did for the build worker. If the build worker is listening on an address other than the default, tell the developer portal that address with the `-buildworker` command line option.

The dev portal caches successful builds. If you will be performing builds locally and don't want to clutter up your disk, set `-cachesize` to a small value (minimum 1, since all downloads are served from the cache).

Change the cache directory by setting `-cachedir` (default is "./cache"). However, keep in mind that any previous cache directories may still be referenced by the database, which stores an index of the cached builds. If you delete a cache directory, be sure to clear its entries from the database.
