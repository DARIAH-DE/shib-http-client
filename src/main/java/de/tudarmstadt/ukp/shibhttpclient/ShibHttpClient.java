/*******************************************************************************
 * Copyright 2013
 * Ubiquitous Knowledge Processing (UKP) Lab
 * Technische Universität Darmstadt
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package de.tudarmstadt.ukp.shibhttpclient;

import static java.util.Arrays.asList;
import static de.tudarmstadt.ukp.shibhttpclient.Utils.*;

import java.io.IOException;
import java.util.List;

import javax.security.sasl.AuthenticationException;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.ecp.RelayState;
import org.opensaml.saml2.ecp.Response;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.ws.soap.soap11.impl.HeaderBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.util.Base64;

/**
 * Simple Shibbolethized {@link HttpClient} using basic HTTP username/password authentication to
 * authenticate against a predefined IdP. The client indicates its ECP capability to the SP.
 * Authentication happens automatically if the SP replies to any requesting using a PAOS
 * authentication solicitation.
 * <p>
 * GET and HEAD requests work completely transparent. For other requests, in particular POST, mind
 * to handle the {@link RetryOperationException} exception.
 */
public class ShibHttpClient
    implements HttpClient
{
    private final Log log = LogFactory.getLog(getClass());

    private static final String MIME_TYPE_PAOS = "application/vnd.paos+xml";

//    private static final QName E_PAOS_REQUEST = new QName(SAMLConstants.PAOS_NS, "Request");
//
//    private static final QName A_RESPONSE_CONSUMER_URL = new QName("responseConsumerURL");

    private static final String HEADER_AUTHORIZATION = "Authorization";

    private static final String HEADER_CONTENT_TYPE = "Content-Type";

    private static final String HEADER_ACCEPT = "Accept";

    private static final String HEADER_PAOS = "PAOS";

    private DefaultHttpClient client;

    private String idpUrl;

    private String username;

    private String password;

    private BasicParserPool parserPool;

    private static final List<String> REDIRECTABLE = asList("HEAD", "GET");

    /**
     * Create a new client.
     * 
     * @param aIdpUrl
     *            the URL of the IdP. Should probably by something ending in "/SAML2/SOAP/ECP"
     * @param aUsername
     *            the user name to log into the IdP.
     * @param aPassword
     *            the password to log in to the IdP.
     * @param aAnyCert
     *            if {@code true} accept any certificate from any remote host. Otherwise,
     *            certificates need to be installed in the JRE.
     */
    public ShibHttpClient(String aIdpUrl, String aUsername, String aPassword, boolean aAnyCert)
    {
        setIdpUrl(aIdpUrl);
        setUsername(aUsername);
        setPassword(aPassword);

        // Use a pooling connection manager, because we'll have to do a call out to the IdP
        // while still being in a connection with the SP
        PoolingClientConnectionManager connMgr = new PoolingClientConnectionManager();
        if (aAnyCert) {
            // Ignore unknown certificates
            connMgr.getSchemeRegistry().register(new Scheme("https", 443, getAnyCertManager()));
        }
        connMgr.setMaxTotal(10);
        connMgr.setDefaultMaxPerRoute(5);

        client = new DefaultHttpClient(connMgr);
        // The client needs to remember the auth cookie
        client.getParams().setParameter(ClientPNames.COOKIE_POLICY,
                CookiePolicy.BROWSER_COMPATIBILITY);

        // Add the ECP/PAOS handlers
        client.addRequestInterceptor(new HttpRequestPreprocessor());
        client.addResponseInterceptor(new HttpRequestPostprocessor());

        parserPool = new BasicParserPool();
        parserPool.setNamespaceAware(true);
    }

    public void setIdpUrl(String aIdpUrl)
    {
        idpUrl = aIdpUrl;
    }

    public void setUsername(String aUsername)
    {
        username = aUsername;
    }

    public void setPassword(String aPassword)
    {
        password = aPassword;
    }

    @Override
    public HttpParams getParams()
    {
        return client.getParams();
    }

    @Override
    public ClientConnectionManager getConnectionManager()
    {
        return client.getConnectionManager();
    }

    @Override
    public HttpResponse execute(HttpUriRequest aRequest)
        throws IOException, ClientProtocolException
    {
        return client.execute(aRequest);
    }

    @Override
    public HttpResponse execute(HttpUriRequest aRequest, HttpContext aContext)
        throws IOException, ClientProtocolException
    {
        return client.execute(aRequest, aContext);
    }

    @Override
    public HttpResponse execute(HttpHost aTarget, HttpRequest aRequest)
        throws IOException, ClientProtocolException
    {
        return client.execute(aTarget, aRequest);
    }

    @Override
    public HttpResponse execute(HttpHost aTarget, HttpRequest aRequest, HttpContext aContext)
        throws IOException, ClientProtocolException
    {
        return client.execute(aTarget, aRequest, aContext);
    }

    @Override
    public <T> T execute(HttpUriRequest aRequest, ResponseHandler<? extends T> aResponseHandler)
        throws IOException, ClientProtocolException
    {
        return client.execute(aRequest, aResponseHandler);
    }

    @Override
    public <T> T execute(HttpUriRequest aRequest, ResponseHandler<? extends T> aResponseHandler,
            HttpContext aContext)
        throws IOException, ClientProtocolException
    {
        return client.execute(aRequest, aResponseHandler, aContext);
    }

    @Override
    public <T> T execute(HttpHost aTarget, HttpRequest aRequest,
            ResponseHandler<? extends T> aResponseHandler)
        throws IOException, ClientProtocolException
    {
        return client.execute(aTarget, aRequest, aResponseHandler);
    }

    @Override
    public <T> T execute(HttpHost aTarget, HttpRequest aRequest,
            ResponseHandler<? extends T> aResponseHandler, HttpContext aContext)
        throws IOException, ClientProtocolException
    {
        return client.execute(aTarget, aRequest, aResponseHandler, aContext);
    }

    /**
     * Add the ECP/PAOS headers to each outgoing request.
     */
    private final static class HttpRequestPreprocessor
        implements HttpRequestInterceptor
    {
        @Override
        public void process(final HttpRequest req, final HttpContext ctx)
        {
            req.addHeader(HEADER_ACCEPT, MIME_TYPE_PAOS);
            req.addHeader(HEADER_PAOS, "ver=\"" + SAMLConstants.PAOS_NS + "\";\""
                    + SAMLConstants.SAML20ECP_NS + "\"");
        }
    }

    /**
     * Analyze responses to detect POAS solicitations for an authentication. Answer these and then
     * transparently proceeed with the original request. If the original request is not
     * redirectable, a {@link RetryOperationException} is thrown to notify the original called to
     * retry the request.
     */
    public final class HttpRequestPostprocessor
        implements HttpResponseInterceptor
    {
        @Override
        public void process(HttpResponse res, HttpContext ctx)
            throws HttpException, IOException
        {
            HttpUriRequest req = (HttpUriRequest) ctx.getAttribute("http.request");
            log.trace("Accessing " + req.getURI() + " " + req.getMethod());
            
            // -- Check if authentication is necessary --------------------------------------------
            boolean isSamlSoap = false;
            if (res.getEntity().getContentType() != null) {
                ContentType contentType = ContentType.parse(res.getEntity().getContentType()
                        .getValue());
                isSamlSoap = MIME_TYPE_PAOS.equals(contentType.getMimeType());
            }

            if (!isSamlSoap) {
                return;
            }

            // -- Parse PAOS response -------------------------------------------------------------
            log.trace("Detected login request");
            Envelope initialLoginSoapResponse = (Envelope) unmarshallMessage(parserPool, res
                    .getEntity().getContent());
            
            // -- Capture relay state (optional) --------------------------------------------------
            RelayState relayState = null;
            if (!initialLoginSoapResponse.getHeader()
                    .getUnknownXMLObjects(RelayState.DEFAULT_ELEMENT_NAME).isEmpty()) {
                relayState = (RelayState) initialLoginSoapResponse.getHeader()
                        .getUnknownXMLObjects(RelayState.DEFAULT_ELEMENT_NAME).get(0);
                relayState.detach();
                log.trace("Relay state: captured");
            }

            // -- Capture response consumer -------------------------------------------------------
//            // pick out the responseConsumerURL attribute value from the SP response so that
//            // it can later be compared to the assertionConsumerURL sent from the IdP
//            String responseConsumerURL = ((XSAny) initialLoginSoapResponse.getHeader()
//                    .getUnknownXMLObjects(E_PAOS_REQUEST).get(0)).getUnknownAttributes().get(
//                    A_RESPONSE_CONSUMER_URL);
//            log.debug("responseConsumerURL: [" + responseConsumerURL + "]");

            // -- Send log-in request to the IdP --------------------------------------------------
            // Prepare the request to the IdP
            log.debug("Logging in to IdP [" + idpUrl + "]");
            Envelope idpLoginSoapRequest = new EnvelopeBuilder().buildObject();
            Body b = initialLoginSoapResponse.getBody();
            b.detach();
            idpLoginSoapRequest.setBody(b);

            // Try logging in to the IdP using HTTP BASIC authentication
            HttpPost idpLoginRequest = new HttpPost(idpUrl);
            idpLoginRequest.addHeader(HEADER_AUTHORIZATION,
                    "Basic " + Base64.encodeBytes((username + ":" + password).getBytes()));
            idpLoginRequest.setEntity(new StringEntity(xmlToString(idpLoginSoapRequest)));
            HttpResponse idpLoginResponse = client.execute(idpLoginRequest);

            // -- Handle log-in response tfrom the IdP --------------------------------------------
            log.debug("Status: " + idpLoginResponse.getStatusLine());
            Envelope idpLoginSoapResponse = (Envelope) unmarshallMessage(parserPool,
                    idpLoginResponse.getEntity().getContent());
            EntityUtils.consume(idpLoginResponse.getEntity());
            String assertionConsumerServiceURL = ((Response) idpLoginSoapResponse.getHeader()
                    .getUnknownXMLObjects(Response.DEFAULT_ELEMENT_NAME).get(0))
                    .getAssertionConsumerServiceURL();
            log.debug("assertionConsumerServiceURL: " + assertionConsumerServiceURL);

            List<XMLObject> responses = idpLoginSoapResponse.getBody().getUnknownXMLObjects(
                    org.opensaml.saml2.core.Response.DEFAULT_ELEMENT_NAME);
            if (!responses.isEmpty()) {
                org.opensaml.saml2.core.Response response = (org.opensaml.saml2.core.Response) responses
                        .get(0);

                // Get root code (?)
                StatusCode sc = response.getStatus().getStatusCode();
                while (sc.getStatusCode() != null) {
                    sc = sc.getStatusCode();
                }

                // Hm, they don't like us
                if ("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed".equals(sc.getValue())) {
                    throw new AuthenticationException(sc.getValue());
                }
            }

//            // compare the responseConsumerURL from the SP to the assertionConsumerServiceURL from
//            // the IdP and if they are not identical then send a SOAP fault to the SP
//            if (false) {
//                // Nice guys should send a fault to the SP - we are NOT nice yet
//            }

            // -- Forward ticket to the SP --------------------------------------------------------
            // craft the package to send to the SP by copying the response from the IdP but
            // removing the SOAP header sent by the IdP and instead putting in a new header that
            // includes the relay state sent by the SP
            Header header = new HeaderBuilder().buildObject();
            header.getUnknownXMLObjects().clear();
            if (relayState != null) {
                header.getUnknownXMLObjects().add(relayState);
            }
            idpLoginSoapResponse.setHeader(header);

            // push the response to the SP at the assertion consumer service URL included in
            // the response from the IdP
            log.debug("Logging in to SP");
            HttpPost spLoginRequest = new HttpPost(assertionConsumerServiceURL);
            spLoginRequest.setHeader(HEADER_CONTENT_TYPE, MIME_TYPE_PAOS);
            spLoginRequest.setEntity(new StringEntity(xmlToString(idpLoginSoapResponse)));
            HttpClientParams.setRedirecting(spLoginRequest.getParams(), false);
            HttpResponse spLoginResponse = client.execute(spLoginRequest);
            log.debug("Status: " + spLoginResponse.getStatusLine());
            log.debug("Authentication complete");

            // -- Handle unredirectable cases -----------------------------------------------------
            // If we get a redirection and the request is redirectable, then let the client redirect
            // If the request is not redirectable, signal that the operation must be retried.
            if (spLoginResponse.getStatusLine().getStatusCode() == 302
                    && !REDIRECTABLE.contains(req.getMethod())) {
                EntityUtils.consume(spLoginResponse.getEntity());
                throw new RetryOperationException();
            }

            // -- Transparently return response to original request -------------------------------
            // Return response received after login as actual response to original caller
            res.setEntity(spLoginResponse.getEntity());
            res.setHeaders(spLoginResponse.getAllHeaders());
            res.setStatusLine(spLoginResponse.getStatusLine());
            res.setLocale(spLoginResponse.getLocale());
        }
    }
}
