package jcifs.pac;

public enum InquireType {
    /** @deprecated */
    @Deprecated
    KRB5_GET_SESSION_KEY,
    KRB5_GET_SESSION_KEY_EX,
    KRB5_GET_TKT_FLAGS,
    KRB5_GET_AUTHZ_DATA,
    KRB5_GET_AUTHTIME,
    KRB5_GET_KRB_CRED;

    private InquireType() {
    }
}
