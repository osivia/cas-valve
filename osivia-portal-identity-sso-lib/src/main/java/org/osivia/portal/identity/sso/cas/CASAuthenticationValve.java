/******************************************************************************
 * JBoss, a division of Red Hat *
 * Copyright 2006, Red Hat Middleware, LLC, and individual *
 * contributors as indicated by the @authors tag. See the *
 * copyright.txt in the distribution for a full listing of *
 * individual contributors. *
 * *
 * This is free software; you can redistribute it and/or modify it *
 * under the terms of the GNU Lesser General Public License as *
 * published by the Free Software Foundation; either version 2.1 of *
 * the License, or (at your option) any later version. *
 * *
 * This software is distributed in the hope that it will be useful, *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU *
 * Lesser General Public License for more details. *
 * *
 * You should have received a copy of the GNU Lesser General Public *
 * License along with this software; if not, write to the Free *
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA *
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org. *
 ******************************************************************************/
package org.osivia.portal.identity.sso.cas;

import java.io.IOException;
import java.security.Principal;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.catalina.Context;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.log4j.Logger;
import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl;
import org.jasig.cas.client.authentication.GatewayResolver;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Saml11TicketValidator;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.jboss.portal.identity.helper.IdentityTools;


/*
 * Created on May 23, 2007
 *
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class CASAuthenticationValve extends ValveBase {


    private static final int HTTPS_PORT = 443;

    private static final int HTTP_PORT = 80;

    private static final String UTF_8 = "UTF-8";

    /**
     * request header defined on a web server in front of the portal
     */
    public static final String VIRTUAL_HOST_REQUEST_HEADER = "osivia-virtual-host";

    private static final String SEP = ":";

    /** . */
    private static final Logger log = Logger.getLogger(CASAuthenticationValve.class);


    /**
     * The name of the filter initialization parameter the value of which should
     * be the https: address of the CAS Login servlet. Optional parameter, but
     * required for successful redirection of unauthenticated requests to
     * authentication.
     */
    public final static String LOGIN_INIT_PARAM = "edu.yale.its.tp.cas.client.filter.loginUrl";

    /**
     * The name of the filter initialization parameter the value of which must be
     * the https: address of the CAS Validate servlet. Must be a CAS 2.0 validate
     * servlet (CAS 1.0 non-XML won't suffice). Required parameter.
     */
    public final static String VALIDATE_INIT_PARAM = "edu.yale.its.tp.cas.client.filter.validateUrl";

    /**
     * The name of the filter initialization parameter the value of which must be
     * the address of the service this filter is filtering. The filter will use
     * this as the service parameter for CAS login and validation. Either this
     * parameter or SERVERNAME_INIT_PARAM must be set.
     */
    public final static String SERVICE_INIT_PARAM = "edu.yale.its.tp.cas.client.filter.serviceUrl";

    /**
     * The name of the filter initialization parameter the vlaue of which must be
     * the server name, e.g. www.yale.edu , of the service this filter is
     * filtering. The filter will construct from this name and the request the
     * full service parameter for CAS login and validation.
     */
    public final static String SERVERNAME_INIT_PARAM = "edu.yale.its.tp.cas.client.filter.serverName";

    /**
     * The name of the filter initialization parameter the value of which must be
     * the String that should be sent as the "renew" parameter on the request for
     * login and validation. This should either be "true" or not be set. It is
     * mutually exclusive with GATEWAY.
     */
    public final static String RENEW_INIT_PARAM = "edu.yale.its.tp.cas.client.filter.renew";

    /**
     * The name of the filter initialization parameter the value of which must be
     * a whitespace delimited list of services (ProxyTicketReceptors) authorized
     * to proxy authentication to the service filtered by this Filter. These must
     * be https: URLs. This parameter is optional - not setting it results in no
     * proxy tickets being acceptable.
     */
    public final static String AUTHORIZED_PROXY_INIT_PARAM = "edu.yale.its.tp.cas.client.filter.authorizedProxy";

    /**
     * The name of the filter initialization parameter the value of which must be
     * the https: URL to which CAS should send Proxy Granting Tickets when this
     * filter validates tickets.
     */
    public final static String PROXY_CALLBACK_INIT_PARAM = "edu.yale.its.tp.cas.client.filter.proxyCallbackUrl";

    /**
     * The name of the filter initialization parameter the value of which
     * indicates whether this filter should wrap requests to expose the
     * authenticated username.
     */
    public final static String WRAP_REQUESTS_INIT_PARAM = "edu.yale.its.tp.cas.client.filter.wrapRequest";

    /**
     * The name of the filter initialization parameter the value of which is the
     * value the Filter should send for the gateway parameter on the CAS login
     * request.
     */
    public final static String GATEWAY_INIT_PARAM = "edu.yale.its.tp.cas.client.filter.gateway";

    // Session attributes used by this filter

    /**
     * <p>
     * Session attribute in which the username is stored.
     * </p>
     */
    public final static String CAS_FILTER_USER = "edu.yale.its.tp.cas.client.filter.user";

    /**
     * Session attribute in which the CASReceipt is stored.
     */
    public final static String CAS_FILTER_RECEIPT = "edu.yale.its.tp.cas.client.filter.receipt";


    public static final String CONST_CAS_ASSERTION = "_const_cas_assertion_";

    // *********************************************************************
    // Configuration state
    /** Secure URL whereat CAS offers its login service. */
    private String casLogin;

    /** Secure URL to perfrom CAS signout */
    private String casLogout;

    /** Secure URL whereat CAS offers its CAS 2.0 validate service */
    private String casValidate;

    /** Filtered service URL for use as service parameter to login and validate */
    private String casServiceUrl;

    /**
     * Name of server, for use in assembling service URL for use as service
     * parameter to login and validate.
     */
    private String casServerName;

    /**
     * Secure URL whereto this filter should ask CAS to send Proxy Granting
     * Tickets.
     */
    private String casProxyCallbackUrl;



    private String casServerUrlPrefix = null;


    public String getCasServerUrlPrefix() {
        return casServerUrlPrefix;
    }


    public void setCasServerUrlPrefix(String casServerUrlPrefix) {
        this.casServerUrlPrefix = casServerUrlPrefix;
    }


    private GatewayResolver gatewayStorage = new DefaultGatewayResolverImpl();


    private Set urlPatterns;

    /**
    *
    */
    private String authType = null;

    /**
     * The character encoding set on the request, taken from
     * the file.encoding system property.
     */
    private String fileEncoding = null;



    public CASAuthenticationValve() {
        super();
        fileEncoding = System.getProperty("file.encoding");

    }

    /**
     *
     * @return
     */
    public String getCasLogin() {
        return casLogin;
    }

    /**
     *
     * @param casLogin
     */
    public void setCasLogin(String casLogin) {
        this.casLogin = casLogin;
    }

    /**
     *
     * @return
     */
    public String getCasLogout() {
        return casLogout;
    }

    /**
     *
     * @param casLogout
     */
    public void setCasLogout(String casLogout) {
        this.casLogout = casLogout;
    }

    /**
     *
     * @return
     */
    public String getCasServerName() {
        return casServerName;
    }

    /**
     *
     * @param casServerName
     */
    public void setCasServerName(String casServerName) {
        this.casServerName = casServerName;
    }

    /**
     *
     * @return
     */
    public String getCasValidate() {
        return casValidate;
    }

    /**
     *
     * @param casValidate
     */
    public void setCasValidate(String casValidate) {
        this.casValidate = casValidate;
    }

    /**
     *
     * @return
     */
    public String getAuthType() {
        return authType;
    }

    /**
     *
     * @param authType
     */
    public void setAuthType(String authType) {
        this.authType = authType;
    }

    /**
     *
     * @return
     */
    public String getCasServiceUrl() {
        return this.casServiceUrl;
    }

    /**
     *
     * @param casServiceUrl
     */
    public void setCasServiceUrl(String casServiceUrl) {
        this.casServiceUrl = casServiceUrl;
    }

    /**
     * Gets the cas proxy callback url.
     *
     * @return the cas proxy callback url
     */
    public String getCasProxyCallbackUrl() {
        return casProxyCallbackUrl;
    }

    /**
     * Sets the cas proxy callback url.
     *
     * @param casProxyCallbackUrl
     *            the new cas proxy callback url
     */
    public void setCasProxyCallbackUrl(String casProxyCallbackUrl) {
        this.casProxyCallbackUrl = casProxyCallbackUrl;
    }




    public final boolean redirectToCAS(final ServletRequest servletRequest, final ServletResponse servletResponse) throws IOException, ServletException {

        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;
        final HttpSession session = request.getSession(false);
        final Assertion assertion = session != null ? (Assertion) session.getAttribute(CONST_CAS_ASSERTION) : null;

        if (assertion != null) {
            return false;
        }

        final String serviceUrl = constructServiceUrl(request, response);
        final String ticket = CommonUtils.safeGetParameter(request,getArtifactParameterName());

        if (CommonUtils.isNotBlank(ticket)) {
            return false;
        }

        final String modifiedServiceUrl;

        log.debug("no ticket and no assertion found");
         modifiedServiceUrl = serviceUrl;

        if (log.isDebugEnabled()) {
            log.debug("Constructed service url: " + modifiedServiceUrl);
        }

        final String urlToRedirectTo = CommonUtils.constructRedirectUrl(getCasLogin(), getServiceParameterName(), modifiedServiceUrl, false, false);

        if (log.isDebugEnabled()) {
            log.debug("redirecting to \"" + urlToRedirectTo + "\"");
        }

        response.sendRedirect(urlToRedirectTo);
        return true;
    }


    /**
    *
    */
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        HttpServletRequest httpRequest = request;
        HttpSession session = httpRequest.getSession();
        request.setAttribute("ssoEnabled", "true");


        // set character encoding before retrieving request parameters
        if (fileEncoding != null) {
            request.setCharacterEncoding(fileEncoding);
        }

        String requestURI = request.getRequestURI();
        if (isSecuredURI(requestURI) ) {
            // perform CAS login by going to the CAS authentication server
            if(redirectToCAS(request, response)) {
                return;
            }
        }


        final String ticket = CommonUtils.safeGetParameter(request, getArtifactParameterName());


        if (CommonUtils.isNotBlank(ticket) && (session.getAttribute(CONST_CAS_ASSERTION) == null)) {
            try {
                log.info("avant validation cas");
                
                final Assertion assertion = this.getTicketValidator().validate(ticket, constructServiceUrl(request, response));

                StringBuffer sb = new StringBuffer();

                sb.append("principal:" + assertion.getPrincipal() + "\n");
                Set<String> attributes = assertion.getPrincipal().getAttributes().keySet();
                for( String attr: attributes){
                    sb.append(attr + "=" + assertion.getPrincipal().getAttributes().get(attr) + "\n");
                }

                log.info(sb.toString());


                session.setAttribute(CONST_CAS_ASSERTION, assertion);


                // perform the portal JAAS authentication
                String user = assertion.getPrincipal().getName();

                if (user.startsWith("uid=")) {
                    // ex: uid=mdupont,ou=personnels EN,ou=ac-rennes,ou=education,o=gouv,c=fr
                    String[] dn = user.split(",");
                    String uid = dn[0];
                    String uidValue = uid.split("=")[1];

                    String codeAca = (String) assertion.getPrincipal().getAttributes().get("ENTCodeAcademie");
                    codeAca = codeAca != null ? "@" + codeAca : "";
                    user = uidValue + codeAca;
                }

                request.setAttribute("ssoSuccess", new Boolean(true));
                Principal principal = ((Context) this.container).getRealm().authenticate(user, (String) null);
                if (principal != null) {
                    this.register(request, response, principal, this.authType, user, (String) null);
                }
            } catch (final TicketValidationException e) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                log.warn(e, e);
                return;
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                log.warn(e, e);
                return;
            }
        }

        // continue processing the request
        this.getNext().invoke(request, response);

        // Perform a logout on the CAS SSO Session
        // LBI #360 CAS signout sent before portal logout
        // if(request.getAttribute("org.jboss.portal.logout") != null)
        // {
        // response.sendRedirect(this.casLogout);
        // }
    }

    /**
     * Register an authenticated Principal and authentication type in our
     * request, in the current session (if there is one), and with our
     * SingleSignOn valve, if there is one. Set the appropriate cookie to be
     * returned.
     *
     * @param request
     *            The servlet request we are processing
     * @param response
     *            The servlet response we are generating
     * @param principal
     *            The authenticated Principal to be registered
     * @param authType
     *            The authentication type to be registered
     * @param username
     *            Username used to authenticate (if any)
     * @param password
     *            Password used to authenticate (if any)
     */
    private void register(Request request, Response response, Principal principal, String authType, String username, String password) {
        // Cache the authentication information in our request
        request.setAuthType(authType);
        request.setUserPrincipal(principal);

        Session session = request.getSessionInternal(false);
        // Cache the authentication information in our session, if any
        if (session != null) {
            session.setAuthType(authType);
            session.setPrincipal(principal);
            if (username != null) {
                session.setNote(Constants.SESS_USERNAME_NOTE, username);
            } else {
                session.removeNote(Constants.SESS_USERNAME_NOTE);
            }
            if (password != null) {
                session.setNote(Constants.SESS_PASSWORD_NOTE, password);
            } else {
                session.removeNote(Constants.SESS_PASSWORD_NOTE);
            }
        }
    }







    private boolean isSecuredURI(String uri) {
        Set patterns = getSecuredUrlPatterns();

        if (log.isDebugEnabled()) {
            log.debug("Checking if requested uri '" + uri + "' matches secured url patterns: " + patterns);
        }

        for (Iterator iterator = patterns.iterator(); iterator.hasNext();) {
            String pattern = (String) iterator.next();

            if (uri.indexOf(pattern) != -1) {
                return true;
            }
        }
        return false;
    }


    public Set getSecuredUrlPatterns() {
        if (urlPatterns == null) {
            urlPatterns = IdentityTools.findSecuredURLs((Context) this.container);

            // Remove wildcards
            Set urls = new HashSet();
            for (Iterator iterator = urlPatterns.iterator(); iterator.hasNext();) {
                String pattern = (String) iterator.next();
                urls.add(pattern.replaceAll("\\*", ""));
            }
            urlPatterns = urls;
        }

        return urlPatterns;
    }


    /** The TicketValidator we will use to validate tickets. */
    private TicketValidator ticketValidator;


    protected TicketValidator getTicketValidator() {
        if (this.ticketValidator == null) {

            final Saml11TicketValidator validator = new Saml11TicketValidator(getCasServerUrlPrefix());
            validator.setTolerance(Long.parseLong("360000"));
            validator.setRenew(false);
            validator.setHostnameVerifier(null);
            validator.setEncoding( null);
            // validator.setDisableXmlSchemaValidation(parseBoolean(getPropertyFromInitParams(filterConfig, "disableXmlSchemaValidation", "false")));

            this.ticketValidator = validator;
        }
        return this.ticketValidator;
    }

    public final void setTicketValidator(final TicketValidator ticketValidator) {
        this.ticketValidator = ticketValidator;
    }


    protected final String constructServiceUrl(final HttpServletRequest request, final HttpServletResponse response) {
        return CommonUtils.constructServiceUrl(request, response, getService(), getCasServerName(), getArtifactParameterName(), true);
    }


    private String getService() {
        return null;
    }

    private String getArtifactParameterName() {
        return "SAMLart";
    }


    private String getServiceParameterName() {
        return "TARGET";
    }





}