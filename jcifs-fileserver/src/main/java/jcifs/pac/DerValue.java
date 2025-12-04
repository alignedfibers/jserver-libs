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

    public DerValue(InputStream in) throws IOException {
        ASN1InputStream asn = new ASN1InputStream(in);
        this.value = asn.readObject();
        if (this.value == null) {
            throw new IOException("DER: no data in InputStream");
        }
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

    public DerValue(byte[] buf) throws IOException {
        this(buf, true);                      // #1
    }

    DerValue(byte[] buf, boolean allowBER) throws IOException {
        this(new ByteArrayInputStream(buf), allowBER);   // #2
    }

    DerValue(InputStream in, boolean allowBER) throws IOException {
        data = init(false, in, allowBER);     // #3 (the real parsing)
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
