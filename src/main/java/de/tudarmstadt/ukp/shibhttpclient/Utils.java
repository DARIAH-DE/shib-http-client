/*******************************************************************************
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
 * 
 * For copyright information, see NOTICE.txt file.
 ******************************************************************************/

package de.tudarmstadt.ukp.shibhttpclient;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.ClientProtocolException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

final class Utils
{
    private static final Log LOG = LogFactory.getLog(Utils.class);
    
    private Utils()
    {
        // No instances
    }

    /**
     * Helper method that deserializes and unmarshalls the message from the given stream. This
     * method has been adapted from {@code org.opensaml.ws.message.decoder.BaseMessageDecoder}.
     * 
     * @param messageStream
     *            input stream containing the message
     * 
     * @return the inbound message
     * 
     * @throws MessageDecodingException
     *             thrown if there is a problem deserializing and unmarshalling the message
     */
    static XMLObject unmarshallMessage(ParserPool parserPool, InputStream messageStream)
        throws ClientProtocolException
    {
        try {
            Document messageDoc = parserPool.parse(messageStream);
            Element messageElem = messageDoc.getDocumentElement();

            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(
                    messageElem);
            if (unmarshaller == null) {
                throw new ClientProtocolException(
                        "Unable to unmarshall message, no unmarshaller registered for message element "
                                + XMLHelper.getNodeQName(messageElem));
            }

            XMLObject message = unmarshaller.unmarshall(messageElem);

            return message;
        }
        catch (XMLParserException e) {
            throw new ClientProtocolException(
                    "Encountered error parsing message into its DOM representation", e);
        }
        catch (UnmarshallingException e) {
            throw new ClientProtocolException(
                    "Encountered error unmarshalling message from its DOM representation", e);
        }
    }

    static String xmlToString(XMLObject aObject)
        throws IOException
    {
        Document doc;
        try {
            doc = Configuration.getMarshallerFactory().getMarshaller(aObject).marshall(aObject)
                    .getOwnerDocument();
        }
        catch (MarshallingException e) {
            throw new IOException(e);
        }

        try {
            Source source = new DOMSource(doc);
            StringWriter stringWriter = new StringWriter();
            Result result = new StreamResult(stringWriter);
            TransformerFactory factory = TransformerFactory.newInstance();
            Transformer transformer = factory.newTransformer();
            transformer.transform(source, result);
            return stringWriter.getBuffer().toString();
        }
        catch (TransformerException e) {
            throw new IOException(e);
        }
    }
    
    static String xmlToString(Element doc)
    {
        StringWriter sw = new StringWriter();
        try {
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

            transformer.transform(new DOMSource(doc), new StreamResult(sw));
            return sw.toString();
        }
        catch (TransformerException e) {
            LOG.error("Unable to print message contents: ", e);
            return "<ERROR: " + e.getMessage()+ ">";
        }
    }
}
