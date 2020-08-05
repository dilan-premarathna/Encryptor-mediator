package org.wso2.carbon.mediator.encrypt;

import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.soap.SOAPBody;
import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.apache.synapse.registry.Registry;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.mediation.registry.WSO2Registry;
import org.wso2.carbon.registry.core.Resource;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.Security;
import java.util.Iterator;

public class GPGEncrypt extends AbstractMediator {

    private static final Logger log = LoggerFactory.getLogger(GPGEncrypt.class);

    public boolean mediate(MessageContext messageContext) {

        // add the bouncy castle security provider
        // or have it installed in $JAVA_HOME/jre/lib/ext
        Security.addProvider(new BouncyCastleProvider());

        Registry registry = messageContext.getConfiguration().getRegistry();
        WSO2Registry wso2Registry = (WSO2Registry) registry;
        Resource resource = wso2Registry.getResource(messageContext.getProperty("publicKeyPath").toString());

        try {
            // read a public key

            PGPPublicKey publicKey = readPublicKeyFromCol(resource.getContentStream());
            // make an output stream connected to a file
            // this also works with output streams in servlets
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(); //new FileOutputStream(new File("big_secret.asc"));

            // make one of our encryption utilities
            PGPEncryptionUtil util = new PGPEncryptionUtil(publicKey, "secrets.txt", byteArrayOutputStream);

            // finally write something
            PrintWriter pw = new PrintWriter(util.getPayloadOutputStream());
            pw.println(messageContext.getProperty("secret").toString());

            // flush the stream and close up everything
            pw.flush();
            util.close();

            String xmlFragment = "<success>" + byteArrayOutputStream + "</success>";
            SOAPBody body = messageContext.getEnvelope().getBody();
            OMNode firstOMChild = body.getFirstOMChild();
            if (firstOMChild != null) {
                firstOMChild.detach();
            }
            body.addChild(AXIOMUtil.stringToOM(xmlFragment));
        } catch (Exception e) {
            log.error("can't encrypt the content", e);
        }

        return true;
    }

    /**
     * Decode a PGP public key block and return the keyring it represents and get the first encyption key off the given keyring
     */

    private static PGPPublicKey readPublicKeyFromCol(InputStream in) throws Exception {

        PGPPublicKeyRing pkRing = null;
        PGPPublicKeyRingCollection pkCol = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in));
        Iterator it = pkCol.getKeyRings();
        while (it.hasNext()) {
            pkRing = (PGPPublicKeyRing) it.next();
            Iterator pkIt = pkRing.getPublicKeys();
            while (pkIt.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) pkIt.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }
        return null;
    }

}