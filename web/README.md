# Static OAuth metadata — example only

`public/oauth-client-metadata.example.json` is intentionally not a functioning
registration. Replace its example.invalid host and example namespaces with owned
identifiers and validate the callback and scope behavior before deployment.

No static files are deployed and no confidential client secret belongs here.
Hosted HTTPS metadata with a loopback callback requires testing against supported
providers; the example is not proof of interoperability or granted permissions.
