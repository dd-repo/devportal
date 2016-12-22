Caddy Developer Portal
======================

*Currently under heavy construction*

This is the web service that powers the Caddy website. It maintains the database of developer accounts, registered plugins, and cached builds.


## Basic Usage

The `devportal` command can be run like so:

```bash
$ devportal
```

*(TODO: There will be command line options and env variables to set; finish this readme)*

To use the build, deploy, or download functions of the developer portal, you will need to run a [Caddy build worker](https://github.com/caddyserver/buildworker).
