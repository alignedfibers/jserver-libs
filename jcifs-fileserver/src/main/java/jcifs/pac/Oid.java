package jcifs.pac;

import java.io.InputStream;
import java.io.IOException;

import jcifs.pac.DerValue;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class Oid {
    private final ASN1ObjectIdentifier oid;
    private byte[] derEncoding;

    public Oid(String strOid) throws GSSException {

        try {
            oid = new ASN1ObjectIdentifier(strOid);
            derEncoding = oid.getEncoded();  // full DER
        } catch (Exception e) {
            throw new GSSException(
                    GSSException.FAILURE,
                    "Improperly formatted Object Identifier String - " + strOid
            );
        }
    }

    public Oid(InputStream derOid) throws GSSException {
        try {
            DerValue derVal = new DerValue(derOid);
            derEncoding = derVal.toByteArray();
            oid = derVal.getOID();
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE,
                    "Improperly formatted ASN.1 DER encoding for Oid");
        }
    }

    public Oid(byte [] data) throws GSSException {
        try {
            DerValue derVal;
            derVal = new DerValue(data);
            derEncoding = derVal.toByteArray();
            oid = derVal.getOID();
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE,
                    "Improperly formatted ASN.1 DER encoding for Oid");
        }
    }

    static Oid getInstance(String strOid) {
        Oid retVal = null;
        try {
            retVal =  new Oid(strOid);
        } catch (GSSException e) {
            // squelch it!
        }
        return retVal;
    }

}
