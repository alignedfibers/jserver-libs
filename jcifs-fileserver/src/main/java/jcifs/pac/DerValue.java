package jcifs.pac;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * Minimal replacement for sun.security.util.DerValue
 * Only implements what jcifs Oid actually uses:
 *   - constructor(InputStream)
 *   - toByteArray()
 *   - getOID()
 */
public class DerValue {
    private ASN1Primitive value;
    /***
     * Using this parse method for now as kind of a place holder in case
     * we at some point need to add functionality here.
     * **/
    private ASN1Primitive parse(InputStream in) throws IOException {
        try (ASN1InputStream asn = new ASN1InputStream(in)) {
            ASN1Primitive obj = asn.readObject();

            if (obj == null) {
                throw new IOException("DER: no data in InputStream");
            }

            return obj;
        }
    }



    /**
     * Get an ASN1/DER encoded datum from an input stream.  The
     * stream may have additional data following the encoded datum.
     * In case of indefinite length encoded datum, the input stream
     * must hold only one datum.
     *
     * @param in the input stream holding a single DER datum,
     *  which may be followed by additional data
     */
    public DerValue(InputStream in) throws IOException {
        this.value = parse(in);
    }

    /**
     * Get an ASN1/DER encoded datum from an input stream w/ additional
     * arg to control whether DER checks are enforced.
     */
    DerValue(InputStream in, boolean allowBER) throws IOException {
        // allowBER ignored ASN1 safely handles internally, kept for any compat issue
        this.value = parse(in);
    }

    /**
     * Get an ASN.1/DER encoded datum from a buffer w/ additional
     * arg to control whether DER checks are enforced.
     */
    DerValue(byte[] buf, boolean allowBER) throws IOException {
        this(new ByteArrayInputStream(buf), allowBER);   // #2
    }

    /**
     * Get an ASN.1/DER encoded datum from a buffer.  The
     * entire buffer must hold exactly one datum, including
     * its tag and length.
     *
     * @param buf buffer holding a single DER-encoded datum.
     */
    public DerValue(byte[] buf) throws IOException {
        this(buf, true);
    }



    public byte[] toByteArray() throws IOException {
        return value.getEncoded();  // DER-encode the parsed value
    }

    public ASN1ObjectIdentifier getOID() throws IOException {
        if (!(value instanceof ASN1ObjectIdentifier)) {
            throw new IOException("DER: value is not an OID");
        }
        return (ASN1ObjectIdentifier) value;
    }






    //public DerValue(byte[] buf, boolean allowBER){}
    //public DerValue(byte[] buf, int offset, int len){}
    //public DerValue(InputStream in, boolean allowBER){}
    //public DerValue(InputStream in){}


    // constructors from byte[] or stream
    // getTag()
    // getOID()
    // getOctetString()
    // getInteger()
    // getGeneralString()
    // getSequence()
    // getTaggedObject()
    // getData()  (nested DerValue)
    // encode()   (write back)
}
