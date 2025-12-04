package jcifs.pac;

public interface GSSName {

    /**
     * Oid indicating a host-based service name form.  It is used to
     * represent services associated with host computers.  This name form
     * is constructed using two elements, "service" and "hostname", as
     * follows: service@hostname.<p>
     *
     * It represents the following Oid value:<br>
     *  <code>{ iso(1) member-body(2) United
     * States(840) mit(113554) infosys(1) gssapi(2) generic(1) service_name(4)
     * }</code>
     */
    Oid NT_HOSTBASED_SERVICE
            = Oid.getInstance("1.2.840.113554.1.2.1.4");

    /**
     * Name type to indicate a named user on a local system.<p>
     * It represents the following Oid value:<br>
     *  <code>{ iso(1) member-body(2) United
     * States(840) mit(113554) infosys(1) gssapi(2) generic(1) user_name(1)
     * }</code>
     */
    Oid NT_USER_NAME
            = Oid.getInstance("1.2.840.113554.1.2.1.1");

    /**
     * Name type to indicate a numeric user identifier corresponding to a
     * user on a local system. (e.g. Uid).<p>
     *
     *  It represents the following Oid value:<br>
     * <code>{ iso(1) member-body(2) United States(840) mit(113554)
     * infosys(1) gssapi(2) generic(1) machine_uid_name(2) }</code>
     */
    Oid NT_MACHINE_UID_NAME
            = Oid.getInstance("1.2.840.113554.1.2.1.2");

    /**
     * Name type to indicate a string of digits representing the numeric
     * user identifier of a user on a local system.<p>
     *
     * It represents the following Oid value:<br>
     * <code>{ iso(1) member-body(2) United
     * States(840) mit(113554) infosys(1) gssapi(2) generic(1)
     * string_uid_name(3) }</code>
     */
    Oid NT_STRING_UID_NAME
            = Oid.getInstance("1.2.840.113554.1.2.1.3");

    /**
     * Name type for representing an anonymous entity.<p>
     * It represents the following Oid value:<br>
     * <code>{ 1(iso), 3(org), 6(dod), 1(internet),
     * 5(security), 6(nametypes), 3(gss-anonymous-name) }</code>
     */
    Oid NT_ANONYMOUS
            = Oid.getInstance("1.3.6.1.5.6.3");

    /**
     * Name type used to indicate an exported name produced by the export
     * method.<p>
     *
     * It represents the following Oid value:<br> <code>{ 1(iso),
     * 3(org), 6(dod), 1(internet), 5(security), 6(nametypes),
     * 4(gss-api-exported-name) }</code>
     */
    Oid NT_EXPORT_NAME
            = Oid.getInstance("1.3.6.1.5.6.4");

    /**
     * Compares two <code>GSSName</code> objects to determine if they refer to the
     * same entity.
     *
     * @param another the <code>GSSName</code> to compare this name with
     * @return true if the two names contain at least one primitive element
     * in common. If either of the names represents an anonymous entity, the
     * method will return false.
     *
     * @throws GSSException when the names cannot be compared, containing the following
     * major error codes:
     *         {@link GSSException#BAD_NAMETYPE GSSException.BAD_NAMETYPE},
     *         {@link GSSException#FAILURE GSSException.FAILURE}
     */
    boolean equals(GSSName another) throws GSSException;

    /**
     * Compares this <code>GSSName</code> object to another Object that might be a
     * <code>GSSName</code>. The behaviour is exactly the same as in {@link
     * #equals(GSSName) equals} except that no GSSException is thrown;
     * instead, false will be returned in the situation where an error
     * occurs.
     * @return true if the object to compare to is also a <code>GSSName</code> and the two
     * names refer to the same entity.
     * @param another the object to compare this name to
     * @see #equals(GSSName)
     */
    @Override
    boolean equals(Object another);

    /**
     * {@return a hashcode value for this GSSName}
     */
    @Override
    int hashCode();

    /**
     * Creates a name that is canonicalized for some
     * mechanism.
     *
     * @return a <code>GSSName</code> that contains just one primitive
     * element representing this name in a canonicalized form for the desired
     * mechanism.
     * @param mech the oid for the mechanism for which the canonical form of
     * the name is requested.
     *
     * @throws GSSException containing the following
     * major error codes:
     *         {@link GSSException#BAD_MECH GSSException.BAD_MECH},
     *         {@link GSSException#BAD_NAMETYPE GSSException.BAD_NAMETYPE},
     *         {@link GSSException#BAD_NAME GSSException.BAD_NAME},
     *         {@link GSSException#FAILURE GSSException.FAILURE}
     */
    GSSName canonicalize(Oid mech) throws GSSException;

    /**
     * Returns a canonical contiguous byte representation of a mechanism name
     * (MN), suitable for direct, byte by byte comparison by authorization
     * functions.  If the name is not an MN, implementations may throw a
     * GSSException with the NAME_NOT_MN status code.  If an implementation
     * chooses not to throw an exception, it should use some system specific
     * default mechanism to canonicalize the name and then export
     * it. Structurally, an exported name object consists of a header
     * containing an OID identifying the mechanism that authenticated the
     * name, and a trailer containing the name itself, where the syntax of
     * the trailer is defined by the individual mechanism specification. The
     * format of the header of the output buffer is specified in RFC 2743.<p>
     *
     * The exported name is useful when used in large access control lists
     * where the overhead of creating a <code>GSSName</code> object on each
     * name and invoking the equals method on each name from the ACL may be
     * prohibitive.<p>
     *
     * Exported names may be re-imported by using the byte array factory
     * method {@link GSSManager#createName(byte[], Oid)
     * GSSManager.createName} and specifying the NT_EXPORT_NAME as the name
     * type object identifier. The resulting <code>GSSName</code> name will
     * also be a MN.
     *
     * @return a byte[] containing the exported name. RFC 2743 defines the
     * "Mechanism-Independent Exported Name Object Format" for these bytes.
     *
     * @throws GSSException containing the following
     * major error codes:
     *         {@link GSSException#BAD_NAME GSSException.BAD_NAME},
     *         {@link GSSException#BAD_NAMETYPE GSSException.BAD_NAMETYPE},
     *         {@link GSSException#FAILURE GSSException.FAILURE}
     */
    byte[] export() throws GSSException;

    /**
     * Returns a textual representation of the <code>GSSName</code> object.  To retrieve
     * the printed name format, which determines the syntax of the returned
     * string, use the {@link #getStringNameType() getStringNameType}
     * method.
     *
     * @return a String representing this name in printable form.
     */
    String toString();

    /**
     * Returns the name type of the printable
     * representation of this name that can be obtained from the <code>
     * toString</code> method.
     *
     * @return an Oid representing the namespace of the name returned
     * from the toString method.
     *
     * @throws GSSException containing the following
     * major error codes:
     *         {@link GSSException#FAILURE GSSException.FAILURE}
     */
    Oid getStringNameType() throws GSSException;

    /**
     * Tests if this name object represents an anonymous entity.
     *
     * @return true if this is an anonymous name, false otherwise.
     */
    boolean isAnonymous();

    /**
     * Tests if this name object represents a Mechanism Name (MN). An MN is
     * a GSSName the contains exactly one mechanism's primitive name
     * element.
     *
     * @return true if this is an MN, false otherwise.
     */
    boolean isMN();
}
