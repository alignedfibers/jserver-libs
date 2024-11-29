package jcifs.pac;

import jcifs.pac.InquireType;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;

public interface ExtendedGSSContext extends GSSContext {
    Object inquireSecContext(InquireType var1) throws GSSException;

    void requestDelegPolicy(boolean var1) throws GSSException;

    boolean getDelegPolicyState();
}
