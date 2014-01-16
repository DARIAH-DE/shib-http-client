shib-http-client
================

Minimalistic wrapper around the Apache HTTPClient adding Shibboleth support

A bit of naming first:

* IdP (identity provider) - the server who knows who you are
* SP (service provider) - the server who wants to know who you are
* ECP (Enhanced Client or Proxy) - the protocol used by this client to perform authentication
  (needs to be enabled on the IdP and SP, see Troubleshooting below)

The process goes roughly like this:

1. You make a request to the SP
2. SP wants to know who you are
3. You ask IdP to prove your identity by giving you a ticket
4. You pass the ticket on to the SP
5. the SP replies to your request

The goal of this project is to perform the steps 2-4 for you.

This client aims to be minimalisic but functional. So the "features" are:

* *No IdP discovery* - a pre-defined IdP is used
* *No fancy logins* - login to the IdP happens via HTTP Basic authentication
* *No certificate checks* - it is easy to disable all certificate checks. If you don't disable 
this, make sure your Java environment knows about the certificates used by the IdP and SP.


Example
-------

<pre><code>// Initialize OpenSAML
DefaultBootstrap.bootstrap();

// The last argument indicates to accept any certificate
HttpClient client = new ShibHttpClient(aIdpUrl, aUsername, aPassword, true);
HttpGet req = new HttpGet("https://my/protected/url");
HttpResponse res = client.execute(req);
... = res.getEntity().getContent(); // returns an InputStream
</code></pre>


Download
--------

shib-http-client is available from [Maven Central](http://search.maven.org/#search%7Cga%7C1%7Cshib-http-client).

You can download and use it as a JAR, or you can add it to a Maven project as a dependency:

```xml
<dependency>
    <groupId>de.tudarmstadt.ukp.shibhttpclient</groupId>
    <artifactId>shib-http-client</artifactId>
    <version>1.0.0</version>
</dependency>
```

Troubleshooting
---------------

###### IdP URL sanity check

The IdP URL should point directly at the ECP profile endpoint of the IdP, so it should be similar
to this:

<pre><code>https://MY-IDP-HOST/idp/profile/SAML2/SOAP/ECP</code></pre>

###### ECP check

If the client does not work as expected, you should check if the SP does support ECP at
all. You can do this with a 'simple' command (replace URL with the URL you want to test):

<pre><code>curl -k -I -H 'Accept: application/vnd.paos+xml' -H 'PAOS: ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"' URL
</code></pre>

*Note:* The command is quite long. You may need to scroll sideways to see the rest.

<pre><code>HTTP/1.1 200 OK
Date: Wed, 23 Oct 2013 10:54:36 GMT
Server: Apache/2.2.17 (Linux/SUSE)
Expires: 01-Jan-1997 12:00:00 GMT
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Content-Length: 1356
Content-Type: application/vnd.paos+xml
</code></pre>

If the reply does not look approximately like this, in particular if the Content-Type line is not
there, then the remote host does not have ECP enabled and you cannot use this client to access the
host. Ask the administrator of the remote host to enable the ECP profile.

Acknowledgements
----------------

Thanks to the folks from the Shibboleth mailing list.

The development of this project was supported by [DARIAH-DE project](https://de.dariah.eu).

![DARIAH Logo](https://de.dariah.eu/liferay-dariah-theme/images/dariah-logo.png)

The development of this project was supported by PaNData as part of the [Umbrella ID](https://www.umbrellaid.org/euu) system.

![Umbrella Logo](https://www.umbrellaid.org/euu/layout/img/logo.png)


Licensed under the Apache Software License 2.0. For copyright information, refer to the NOTICE.txt
file.

[![githalytics.com alpha](https://cruel-carlota.pagodabox.com/eaced398ef831f1b082ced9a07694513 "githalytics.com")](http://githalytics.com/reckart/shib-http-client)
