shib-http-client
================

Minimalistic wrapper around the Apache HTTPClient adding Shibboleth support

A bit of naming first:

* IdP (identity provider) - the server who knows who you are
* SP (service provider) - the server who wants to know who you are

The process is roughly this:

1. You make a request to the SP
2. SP wants to know who you are
3. You ask IdP to prove your identity by giving you a ticket
4. You pass the ticket on to the SP
5. the SP replies to your request

The goal of this project is to perform the steps 2-3 for you.

This client aims to be minimalisic but functional. So the "features" are:

* *No IdP discovery* - a pre-defined IdP is used
* *No fancy logins* - login to the IdP happens via HTTP Basic authentication
* *No certificate checks* - it is easy to disable all certificate checks. If you don't disable 
this, make sure your Java environment knows about the certificates used by the IdP and SP.


Example
-------

<pre><code>
// The last argument indicates to accept any certificate
HttpClient client = new ShibHttpClient(aIdpUrl, aUsername, aPassword, true);
HttpGet req = new HttpGet("https://my/protected/url");
HttpResponse res = client.execute(req);
... = res.getEntity().getContent(); // returns an InputStream
</code></pre>

[![githalytics.com alpha](https://cruel-carlota.pagodabox.com/eaced398ef831f1b082ced9a07694513 "githalytics.com")](http://githalytics.com/reckart/shib-http-client)