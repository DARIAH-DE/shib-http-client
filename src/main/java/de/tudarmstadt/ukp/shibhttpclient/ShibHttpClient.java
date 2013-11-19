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

import static de.tudarmstadt.ukp.shibhttpclient.Utils.unmarshallMessage;
import static de.tudarmstadt.ukp.shibhttpclient.Utils.xmlToString;
import static java.util.Arrays.asList;

import java.io.IOException;
import java.net.ProxySelector;
import java.security.GeneralSecurityException;
import java.util.List;

import javax.security.sasl.AuthenticationException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.NonRepeatableRequestException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestWrapper;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.cookie.Cookie;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
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
 * GET and HEAD requests work completely transparent using redirection. If another request is
 * performed, the client tries a HEAD request to the specified URL first. If this results in an
 * authentication request, a login is performed before the original request is executed.
 */
public class ShibHttpClient
implements HttpClient
{
    private final Log log = LogFactory.getLog(getClass());

    private static final String AUTH_IN_PROGRESS = ShibHttpClient.class.getName()
            + ".AUTH_IN_PROGRESS";

    private static final String MIME_TYPE_PAOS = "application/vnd.paos+xml";

//    private static final QName E_PAOS_REQUEST = new QName(SAMLConstants.PAOS_NS, "Request");
//
//    private static final QName A_RESPONSE_CONSUMER_URL = new QName("responseConsumerURL");

    private static final String HEADER_AUTHORIZATION = "Authorization";

    private static final String HEADER_CONTENT_TYPE = "Content-Type";

    private static final String HEADER_ACCEPT = "Accept";

    private static final String HEADER_PAOS = "PAOS";

    private CloseableHttpClient client;

    private BasicCookieStore cookieStore;

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
        PoolingHttpClientConnectionManager connMgr;
        if (aAnyCert) {
            try {
                SSLContextBuilder builder = new SSLContextBuilder();
                builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
                SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build());
                PlainConnectionSocketFactory plainsf = new PlainConnectionSocketFactory();
                Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder
                        .<ConnectionSocketFactory> create()
                        .register("http", plainsf)
                        .register("https", sslsf)
                        .build();
                connMgr = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
            }
            catch (GeneralSecurityException e) {
                // There shouldn't be any of these exceptions, because we do not use an actual
                // keystore
                throw new IllegalStateException(e);
            }
        }
        else {
            connMgr = new PoolingHttpClientConnectionManager();
        }
        connMgr.setMaxTotal(10);
        connMgr.setDefaultMaxPerRoute(5);
        
        // retrieve the JVM parameters for proxy state (do we have a proxy?)
        SystemDefaultRoutePlanner sdrp = new SystemDefaultRoutePlanner(ProxySelector.getDefault());

        // The client needs to remember the auth cookie
        cookieStore = new BasicCookieStore();
        RequestConfig globalRequestConfig = RequestConfig.custom()
                .setCookieSpec(CookieSpecs.BROWSER_COMPATIBILITY)
                .build();

        // Add the ECP/PAOS headers - needs to be added first so the cookie we get from
        // the authentication can be handled by the RequestAddCookies interceptor later
        HttpRequestPreprocessor preProcessor = new HttpRequestPreprocessor();
        // Automatically log into IdP if SP requests this
        HttpRequestPostprocessor postProcessor = new HttpRequestPostprocessor();

        // build our client
        client = HttpClients.custom()
                .setConnectionManager(connMgr)
                // use a proxy if one is specified for the JVM
                .setRoutePlanner(sdrp)
                // The client needs to remember the auth cookie
                .setDefaultRequestConfig(globalRequestConfig)
                .setDefaultCookieStore(cookieStore)
                // Add the ECP/PAOS headers - needs to be added first so the cookie we get from
                // the authentication can be handled by the RequestAddCookies interceptor later
                .addInterceptorFirst(preProcessor)
                // Automatically log into IdP if SP requests this
                .addInterceptorFirst(postProcessor)
                .build();

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
    private final class HttpRequestPreprocessor
        implements HttpRequestInterceptor
    {
        @Override
        public void process(final HttpRequest req, final HttpContext ctx)
                throws HttpException, IOException
        {
            if (req.getRequestLine().getMethod() == "CONNECT") {
                log.trace("Received CONNECT -- Likely to be a proxy request. Skipping pre-processor");
                return;
            }

            req.addHeader(HEADER_ACCEPT, MIME_TYPE_PAOS);
            req.addHeader(HEADER_PAOS, "ver=\"" + SAMLConstants.PAOS_NS + "\";\""
                    + SAMLConstants.SAML20ECP_NS + "\"");

            HttpRequest r = req;
            if (req instanceof HttpRequestWrapper) { // does not forward request to original
                r = ((HttpRequestWrapper) req).getOriginal();
            }

            // This request is not redirectable, so we better knock to see if authentication
            // is necessary.
            if (!REDIRECTABLE.contains(r.getRequestLine().getMethod())
                    && r.getParams().isParameterFalse(AUTH_IN_PROGRESS)) {
//                    && !r.getRequestLine().getUri().startsWith(idpUrl)) {
                log.trace("Unredirectable request [" + r.getRequestLine().getMethod()
                        + "], trying to knock first at " + r.getRequestLine().getUri());
                HttpHead knockRequest = new HttpHead(r.getRequestLine().getUri());
                client.execute(knockRequest);
                
                for (Cookie c : cookieStore.getCookies()) {
                    log.trace(c.toString());
                }
                log.trace("Knocked");
            }
        }
    }

    /**
     * Analyze responses to detect POAS solicitations for an authentication. Answer these and then
     * transparently proceeed with the original request.
     */
    public final class HttpRequestPostprocessor
        implements HttpResponseInterceptor
    {
        @Override
        public void process(HttpResponse res, HttpContext ctx)
            throws HttpException, IOException
        {
            HttpRequest originalRequest;
            // check for RequestWrapper objects, retrieve the original request
            if (ctx.getAttribute("http.request") instanceof HttpRequestWrapper) { // does not forward request to original
                log.trace("RequestWrapper found");
                originalRequest = (HttpRequest) ((HttpRequestWrapper) ctx.getAttribute("http.request")).getOriginal();
            }
            else {  // use a basic HttpRequest because BasicHttpRequest objects cannot be recast to HttpUriRequest objects
                originalRequest = (HttpRequest) ctx.getAttribute("http.request");
            }

            log.trace("Accessing [" + originalRequest.getRequestLine().getUri() + " "
                    + originalRequest.getRequestLine().getMethod() + "]");

            // -- Check if authentication is already in progress ----------------------------------
            if (res.getParams().isParameterTrue(AUTH_IN_PROGRESS)) {
                log.trace("Authentication in progress -- skipping post processor");
                return;
            }

            // -- Check if authentication is necessary --------------------------------------------
            boolean isSamlSoap = false;
            if (res.getFirstHeader(HEADER_CONTENT_TYPE) != null) {
                ContentType contentType = ContentType.parse(res.getFirstHeader(HEADER_CONTENT_TYPE)
                        .getValue());
                isSamlSoap = MIME_TYPE_PAOS.equals(contentType.getMimeType());
            }

            if (!isSamlSoap) {
                return;
            }

            log.trace("Detected login request");

            // -- If the request was a HEAD request, we need to try again using a GET request  ----
            HttpResponse paosResponse = res;
            if (originalRequest.getRequestLine().getMethod() == "HEAD") {
                log.trace("Original request was a HEAD, restarting authenticiation with GET");

                HttpGet authTriggerRequest = new HttpGet(originalRequest.getRequestLine().getUri());
                authTriggerRequest.getParams().setBooleanParameter(AUTH_IN_PROGRESS, true);
                paosResponse = client.execute(authTriggerRequest);
            }

            // -- Parse PAOS response -------------------------------------------------------------
            Envelope initialLoginSoapResponse = (Envelope) unmarshallMessage(parserPool,
                    paosResponse.getEntity().getContent());

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
            idpLoginRequest.getParams().setBooleanParameter(AUTH_IN_PROGRESS, true);
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

            // compare the responseConsumerURL from the SP to the assertionConsumerServiceURL from
            // the IdP and if they are not identical then send a SOAP fault to the SP
            // if (false) {
            //     // Nice guys should send a fault to the SP - we are NOT nice yet
            // }

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
            spLoginRequest.getParams().setBooleanParameter(AUTH_IN_PROGRESS, true);
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
                    && !REDIRECTABLE.contains(originalRequest.getRequestLine().getMethod())) {
                EntityUtils.consume(spLoginResponse.getEntity());
                throw new NonRepeatableRequestException("Request of type [" + 
                        originalRequest.getRequestLine().getMethod() + "] cannot be redirected");
            }

            // -- Transparently return response to original request -------------------------------
            // Return response received after login as actual response to original caller
            res.setEntity(spLoginResponse.getEntity());
            res.setHeaders(spLoginResponse.getAllHeaders());
            res.setStatusLine(spLoginResponse.getStatusLine());
        }
    }
}
