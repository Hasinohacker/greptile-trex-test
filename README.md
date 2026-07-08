# Greptile TREX Test

Minimal Jest project for authorized Greptile/TREX sandbox validation.

The included test is sanitized: it reports execution and environment surface
status only. It does not send raw secrets, sensitive file contents, or cloud
metadata response bodies.

Run local syntax validation:

```sh
npm run check
```

Run the probe:

```sh
npm test
```
