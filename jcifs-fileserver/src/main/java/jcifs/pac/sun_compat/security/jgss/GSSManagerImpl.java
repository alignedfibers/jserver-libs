package jcifs.pac.sun_compat.security.jgss;

import jcifs.pac.jgss_compat.*;
import jcifs.util.transport.Message;

import java.security.Provider;
import java.io.InputStream;
import java.io.OutputStream;

public class GSSManagerImpl extends GSSManager {

    public GSSManagerImpl() {}

    // ================================================================
    // NAME CREATION
    // ================================================================
    @Override
    public GSSName createName(String name, Oid type) throws GSSException {
        return new GSSName() {
            @Override public String toString() { return name; }
            @Override public boolean equals(Object o) { return (o instanceof GSSName) && name.equals(o.toString()); }
            @Override public int hashCode() { return name.hashCode(); }
            @Override public byte[] export() { return name.getBytes(); }
            @Override public Oid getStringNameType() { return type; }
            @Override public GSSName canonicalize(Oid mech) { return this; }
            @Override public boolean equals(GSSName another) throws GSSException {
                return (another != null) && name.equals(another.toString());
            }
            @Override public boolean isAnonymous(){return name == null || name.isEmpty();}
            @Override public boolean isMN(){return false;}
        };
    }
    @Override
    public GSSName createName(byte[] bytes, Oid type) throws GSSException {
        return createName(new String(bytes), type);
    }
    @Override
    public GSSName createName(String name, Oid type, Oid mech) throws GSSException {
        return createName(name, type); // mech ignored — jcifs never uses it
    }
    @Override
    public GSSName createName(byte[] bytes, Oid type, Oid mech) throws GSSException {
        return createName(new String(bytes), type); // mech ignored — jcifs never uses it
    }

    // ================================================================
    // CREDENTIAL CREATION (jcifs barely uses these)
    // ================================================================

    public GSSCredential createCredential(GSSName name, int usage) throws GSSException {
        return new GSSCredential() {
            @Override public void dispose() {}
            @Override public GSSName getName() { return name; }
            @Override public GSSName getName(Oid mech) { return name; }
            @Override public int getRemainingLifetime() { return INDEFINITE_LIFETIME; }
            @Override public int getRemainingInitLifetime(Oid mech) { return INDEFINITE_LIFETIME; }
            @Override public int getRemainingAcceptLifetime(Oid mech) { return INDEFINITE_LIFETIME; }
            @Override public int getUsage() { return usage; }
            @Override public int getUsage(Oid mech) { return usage; }
            @Override public Oid[] getMechs() { return new Oid[0]; }
            @Override public void add(GSSName n, int il, int al, Oid mech, int u) {}
            @Override public boolean equals(Object o) { return this == o; }
            @Override public int hashCode() { return name.hashCode(); }
        };
    }

    @Override
    public GSSCredential createCredential(GSSName n, int l, Oid m, int u) throws GSSException {
        return createCredential(n, u);
    }

    @Override
    public GSSCredential createCredential(GSSName n, int l, Oid[] m, int u) throws GSSException {
        return createCredential(n, u);
    }
    @Override
    public GSSCredential createCredential(int l) throws GSSException{
        return createCredential(null,l);
    }

    // ================================================================
    // CONTEXT CREATION (this is the important one)
    // jcifs uses the context only to:
    //   - initSecContext()
    //   - getMIC()/verifyMIC() in some flows
    //   - request* methods (no-ops)
    // ================================================================
    @Override
    public GSSContext createContext(GSSName target, Oid mech, GSSCredential cred, int lifetime) {
        return createBasicContext();
    }

    @Override
    public GSSContext createContext(GSSCredential cred) {
        return createBasicContext();
    }

   /* @Override
    public GSSContext createContext() {
        return createBasicContext();
    }*/
    @Override
    public GSSContext createContext(byte[] interProcessToken){
        return createBasicContext();
    }

    // ================== MINIMAL CONTEXT USED BY JCIFS ==================
    private GSSContext createBasicContext() {
        return new GSSContext() {

            private boolean established = false;

            @Override public byte[] initSecContext(byte[] tok, int o, int l) {
                established = true;
                return new byte[0]; // jcifs ignores this for NTLM path
            }

            @Override public boolean isEstablished() {
                return established;
            }

            // jcifs uses these for flags only
            @Override public boolean getIntegState() { return false; }
            @Override public boolean getConfState() { return false; }
            //@Override public boolean getSeqState() { return false; }
            //@Override public boolean getMutualAuthState() { return false; }
            @Override public boolean getReplayDetState() { return false; }
            @Override public boolean getCredDelegState() { return false; }
            @Override public boolean getAnonymityState() { return false; }

            // request* calls are no-ops
            @Override public void requestMutualAuth(boolean v) {}
            @Override public void requestCredDeleg(boolean v) {}
            @Override public void requestConf(boolean v) {}
            @Override public void requestInteg(boolean v) {}
            @Override public void requestAnonymity(boolean v) {}
            @Override public void requestReplayDet(boolean v) {}
            @Override public void requestSequenceDet(boolean v) {}

            @Override public void dispose() {}

            // MIC operations not used by NTLM path
            @Override public byte[] getMIC(byte[] b, int o, int l, MessageProp p) { return new byte[0]; }
            @Override public void verifyMIC(byte[] m, int mo, int ml, byte[] d, int o, int l, MessageProp p) {}

            // unused stubs
            @Override public byte[] export() { return new byte[0]; }
            @Override public GSSName getSrcName() { return null; }
            @Override public GSSName getTargName() { return null; }
            @Override public Oid getMech() { return null; }
            @Override public int initSecContext(InputStream in, OutputStream out) throws GSSException {
                // jcifs never uses this; treat it as one-step establish
                this.established = true;
                return 0;
            }

            @Override public byte[] acceptSecContext(byte[] inToken, int offset, int len) throws GSSException {
                return new byte[0];
            }
            @Override public void acceptSecContext(InputStream inStream, OutputStream outStream){
                //no-op
            }

            @Override public int getWrapSizeLimit(int qop, boolean confReq, int maxTokenSize) throws GSSException {
                return 0;
            }

            @Override
            public byte[] wrap(byte[] inBuf, int offset, int len, MessageProp msgProp) throws GSSException {
                return new byte[0];
            }

            @Override public void wrap(InputStream inStream, OutputStream outStream, MessageProp msgProp){

            }
            @Override public void unwrap(InputStream inStream, OutputStream outStream, MessageProp msgProp){

            }

            @Override
            public byte[] unwrap(byte[] inBuf, int offset, int len, MessageProp msgProp) throws GSSException {
                return new byte[0];
            }

            @Override
            public void getMIC(InputStream inStream, OutputStream outStream, MessageProp msgProp){
                //no-op
            }

            @Override
            public void verifyMIC(InputStream tokStream, InputStream msgStream, MessageProp msgProp) throws GSSException {
                //no-op
            }

            @Override
            public void requestLifetime(int lifetime) throws GSSException {
                //no-op
            }

            @Override
            public void setChannelBinding(ChannelBinding cb) throws GSSException {
                //no-op
            }

            @Override
            public boolean getMutualAuthState() {
                return false;
            }

            @Override
            public boolean getSequenceDetState() {
                return false;
            }

            @Override
            public boolean isTransferable() throws GSSException {
                return false;
            }

            @Override
            public boolean isProtReady() {
                return false;
            }

            @Override
            public int getLifetime() {
                return 0;
            }

            @Override
            public GSSCredential getDelegCred() throws GSSException {
                return null;
            }

            @Override
            public boolean isInitiator() throws GSSException {
                return false;
            }
        };
    }

    // ================================================================
    // MECHANISM ENUMERATION — jcifs never calls these
    // ================================================================
    @Override public Oid[] getMechs() { return new Oid[0]; }
    @Override public Oid[] getNamesForMech(Oid mech) { return new Oid[0]; }
    @Override public Oid[] getMechsForName(Oid nameType) { return new Oid[0]; }
    @Override public void addProviderAtFront(Provider p, Oid mech){return;}
    @Override public void addProviderAtEnd(Provider p, Oid mech){return;}
}
