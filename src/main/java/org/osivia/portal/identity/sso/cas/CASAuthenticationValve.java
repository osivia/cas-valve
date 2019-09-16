/******************************************************************************
 * JBoss, a division of Red Hat                                               *
 * Copyright 2006, Red Hat Middleware, LLC, and individual                    *
 * contributors as indicated by the @authors tag. See the                     *
 * copyright.txt in the distribution for a full listing of                    *
 * individual contributors.                                                   *
 *                                                                            *
 * This is free software; you can redistribute it and/or modify it            *
 * under the terms of the GNU Lesser General Public License as                *
 * published by the Free Software Foundation; either version 2.1 of           *
 * the License, or (at your option) any later version.                        *
 *                                                                            *
 * This software is distributed in the hope that it will be useful,           *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU           *
 * Lesser General Public License for more details.                            *
 *                                                                            *
 * You should have received a copy of the GNU Lesser General Public           *
 * License along with this software; if not, write to the Free                *
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA         *
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.                   *
 ******************************************************************************/
package org.osivia.portal.identity.sso.cas;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
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
import org.jboss.portal.identity.helper.IdentityTools;
import org.osivia.portal.api.customization.CustomizationContext;
import org.osivia.portal.api.feeder.IFeederService;
import org.osivia.portal.api.locator.Locator;
import org.osivia.portal.api.theming.IAttributesBundle;
import org.osivia.portal.core.customization.ICustomizationService;


import edu.yale.its.tp.cas.client.CASAuthenticationException;
import edu.yale.its.tp.cas.client.CASReceipt;
import edu.yale.its.tp.cas.client.ProxyTicketValidator;
import edu.yale.its.tp.cas.client.Util;

/*
 * Created on May 23, 2007
 * 
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class CASAuthenticationValve extends ValveBase
{


	private static final int HTTPS_PORT = 443;

	private static final int HTTP_PORT = 80;

	private static final String UTF_8 = "UTF-8";

    /**
     * request header defined on a web server in front of the portal
     */
    public static final String VIRTUAL_HOST_REQUEST_HEADER = "osivia-virtual-host";

    private static final String SEP = ":";

    /** . */
	private static final Logger log = Logger.getLogger("valve");


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

   // *********************************************************************
   // Configuration state
   /** Secure URL whereat CAS offers its login service. */
   private String casLogin;
   
   /**Secure URL to perfrom CAS signout */
   private String casLogout;

   /** Secure URL whereat CAS offers its CAS 2.0 validate service */
   private String casValidate;

   /** Filtered service URL for use as service parameter to login and validate */
   private String casServiceUrl;
   
   /** enable broken security mode (non-production) */
   private Boolean brokenSecurityMode = Boolean.FALSE;

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

   /** True if renew parameter should be set on login and validate */
   private boolean casRenew;

   /** True if this filter should set gateway=true on login redirect */
   private final boolean casGateway = false;

   /**
    * List of ProxyTicketReceptor URLs of services authorized to proxy to the
    * path behind this filter.
    */
   private final List authorizedProxies = new ArrayList();

   /**
    * 
    */
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
   
   /** Customization service. */
   private ICustomizationService customizationService;
   
   


   public CASAuthenticationValve() 
   {
      super();
      fileEncoding = System.getProperty("file.encoding");
      // Customization service
      customizationService = Locator.findMBean(ICustomizationService.class, ICustomizationService.MBEAN_NAME);
   }

   /**
    * 
    * @return
    */
   public String getCasLogin()
   {
      return casLogin;
   }

   /**
    * 
    * @param casLogin
    */
   public void setCasLogin(String casLogin)
   {
      this.casLogin = casLogin;
   }
   
   /**
    * 
    * @return
    */
   public String getCasLogout()
   {
      return casLogout;
   }

   /**
    * 
    * @param casLogout
    */
   public void setCasLogout(String casLogout)
   {
      this.casLogout = casLogout;
   }

   /**
    * 
    * @return
    */
   public String getCasServerName()
   {
      return casServerName;
   }

   /**
    * 
    * @param casServerName
    */
   public void setCasServerName(String casServerName)
   {
      this.casServerName = casServerName;
   }

   /**
    * 
    * @return
    */
   public String getCasValidate()
   {
      return casValidate;
   }

   /**
    * 
    * @param casValidate
    */
   public void setCasValidate(String casValidate)
   {
      this.casValidate = casValidate;
   }

   /**
    * 
    * @return
    */
   public String getAuthType()
   {
      return authType;
   }

   /**
    * 
    * @param authType
    */
   public void setAuthType(String authType)
   {
      this.authType = authType;
   }
   
   /**
    * 
    * @return
    */
   public String getCasServiceUrl()
   {
      return this.casServiceUrl;
   }
   
   /**
    * 
    * @param casServiceUrl
    */
   public void setCasServiceUrl(String casServiceUrl)
   {
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
  
   
   
	   
	   /**
	 * @return the brokenSecurityMode
	 */
	public Boolean getBrokenSecurityMode() {
		return brokenSecurityMode;
	}
	
	/**
	 * @param brokenSecurityMode the brokenSecurityMode to set
	 */
	public void setBrokenSecurityMode(Boolean brokenSecurityMode) {
		this.brokenSecurityMode = brokenSecurityMode;
	}

/**
    * 
    */
   @Override
public void invoke(Request request, Response response) throws IOException,
         ServletException
   {
      HttpServletRequest httpRequest = request;
      HttpSession session = httpRequest.getSession();
      request.setAttribute("ssoEnabled", "true");

      // set character encoding before retrieving request parameters
      if(fileEncoding!=null) 
      {
         request.setCharacterEncoding(fileEncoding);
      }
      
      // #1980 - evaluate upstream CAS server if casName is provided
      String requestURI = request.getRequestURI();
      if (request.getParameter("ticket") != null
            && request.getParameter("casName") != null
            && session.getAttribute(CAS_FILTER_USER) == null)
      {
         // perform CAS login by going to the CAS authentication server
         redirectToCAS(request,
               response);
         return;
      }
     

      if (isSecuredURI(requestURI)
            && request.getParameter("ticket") == null
            && session.getAttribute(CAS_FILTER_USER) == null)
      {
          
         if (requestURI.indexOf("/auth/noredirect/pagemarker/") == -1)   { 
         // perform CAS login by going to the CAS authentication server
         redirectToCAS(request,
               response);
         }  else
         {
             String header = request.getHeader(VIRTUAL_HOST_REQUEST_HEADER);
             response.sendRedirect(header+"/osivia-portal-custom-web-assets/redirection/ajax-reload.jsp");
         }
         
         return;
      }

      
      if (request.getParameter("ticket") != null
            && session.getAttribute(CAS_FILTER_USER) == null)
      {
         CASReceipt receipt = null;
         boolean skip = false;
         try
         {
            receipt = getAuthenticatedUser(httpRequest);
         }
         catch (CASAuthenticationException e)
         {
            skip = true;

				if (log.isDebugEnabled()) {
					log.error("Authentification failed", e);
				}
         }

         if (!skip && !isReceiptAcceptable(receipt))
         {
            skip = true;
         }

         if(!skip)
         {
            session.setAttribute(CAS_FILTER_USER, receipt.getUserName());
            session.setAttribute(CAS_FILTER_RECEIPT, receipt);
            

            String casResponse = (String) request.getAttribute("casresponse");
            if (log.isDebugEnabled()) {
                log.debug("casresponse:"+casResponse);
            }
            session.setAttribute("edu.yale.its.tp.cas.client.filter.response", casResponse);
            
   
            // perform the portal JAAS authentication
            String user = receipt.getUserName();
            request.setAttribute("ssoSuccess", new Boolean(true));
            
            
            // Feeder invocations
            Map<String, Object> customizerAttributes = new HashMap<String, Object>();
            customizerAttributes.put(IFeederService.CUSTOMIZER_ATTRIBUTE_REQUEST, request);
            CustomizationContext context = new CustomizationContext(customizerAttributes);
            this.customizationService.customize(IFeederService.CUSTOMIZER_ID, context);

            
            
            Principal principal = ((Context) this.container).getRealm()
                  .authenticate(user, (String) null);
            if (principal != null)
            {
               this.register(request, response, principal, this.authType, user,
                     (String) null);
            }
             
         }
      }

      // continue processing the request
      this.getNext().invoke(request, response);
        
      //Perform a logout on the CAS SSO Session
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
    *           The servlet request we are processing
    * @param response
    *           The servlet response we are generating
    * @param principal
    *           The authenticated Principal to be registered
    * @param authType
    *           The authentication type to be registered
    * @param username
    *           Username used to authenticate (if any)
    * @param password
    *           Password used to authenticate (if any)
    */
   private void register(Request request, Response response,
         Principal principal, String authType, String username, String password)
   {
      // Cache the authentication information in our request
      request.setAuthType(authType);
      request.setUserPrincipal(principal);

      Session session = request.getSessionInternal(false);
      // Cache the authentication information in our session, if any
      if (session != null)
      {
         session.setAuthType(authType);
         session.setPrincipal(principal);
         if (username != null)
         {
            session.setNote(Constants.SESS_USERNAME_NOTE, username);
         }
         else
         {
            session.removeNote(Constants.SESS_USERNAME_NOTE);
         }
         if (password != null)
         {
            session.setNote(Constants.SESS_PASSWORD_NOTE, password);
         }
         else
         {
            session.removeNote(Constants.SESS_PASSWORD_NOTE);
         }
      }
   }

   // CAS related utility
   // methods---------------------------------------------------------------------------------------------------------
   /**
    * Is this receipt acceptable as evidence of authentication by credentials
    * that would have been acceptable to this path? Current implementation
    * checks whether from renew and whether proxy was authorized.
    * 
    * @param receipt
    * @return true if acceptable, false otherwise
    */
   private boolean isReceiptAcceptable(CASReceipt receipt)
   {
      if (receipt == null) throw new IllegalArgumentException(
            "Cannot evaluate a null receipt.");
      if (this.casRenew && !receipt.isPrimaryAuthentication())
      {
         return false;
      }
      if (receipt.isProxied())
      {
         if (!this.authorizedProxies.contains(receipt.getProxyingService()))
         {
            return false;
         }
      }
      return true;
   }

   /**
    * Converts a ticket parameter to a CASReceipt, taking into account an
    * optionally configured trusted proxy in the tier immediately in front of
    * us.
    * 
    * @throws ServletException -
    *            when unable to get service for request
    * @throws CASAuthenticationException -
    *            on authentication failure
    */
   private CASReceipt getAuthenticatedUser(HttpServletRequest request)
         throws ServletException, CASAuthenticationException
   {
      ProxyTicketValidator pv = null;

      pv = new ProxyTicketValidator();
      pv.setCasValidateUrl(casValidate);
      pv.setServiceTicket(request.getParameter("ticket"));
      pv.setService(getService(request));
      pv.setRenew(Boolean.valueOf(casRenew).booleanValue());
      if (casProxyCallbackUrl != null)
      {
         pv.setProxyCallbackUrl(casProxyCallbackUrl);
      }
		if (log.isDebugEnabled()) {
		log.debug("getAuthenticatedUser -> try to validate the ticket "
				+ pv.toString());
		}

		if(brokenSecurityMode){ 
			pv.setBrokenSecurityMode(true);
		}
			
		
		
      CASReceipt receipt =  CASReceipt.getReceipt(pv);
      
      request.setAttribute("casresponse",pv.getResponse());
      
      return receipt;
   }

   
   /**
    * Redirects the user to CAS, determining the service from the request.
    */
   private void redirectToCAS(HttpServletRequest request,
         HttpServletResponse response) throws IOException, ServletException
   {

	   
      String casLoginString = casLogin + "?service="
            + getService(request)
            + ((casRenew) ? "&renew=true" : "")
            + (casGateway ? "&gateway=true" : "");
      
      // #1980 - evaluate upstream CAS server if casName is provided
      if(request.getParameter("casName") != null && request.getParameter("ticket") != null) {
    	  
    	  String encodeCasName = URLEncoder.encode(request.getParameter("casName").toString(), UTF_8);
    	  
    	  casLoginString += "&casName=" + encodeCasName + "&ticket=" + request.getParameter("ticket");
      }

      response.sendRedirect(casLoginString);
   }
   

    /**
     * Returns either the configured service or figures it out for the current
     * request. The returned service is URL-encoded.
     */
    private String getService(HttpServletRequest request) throws ServletException {

		if (log.isDebugEnabled()) {
			log.debug("redirectToCAS -> entering getService...");
		}

        String serviceString;

        // [Osivia] Service provided by the header (provided by front Apache)
        String header = request.getHeader(VIRTUAL_HOST_REQUEST_HEADER);

        // [Osivia] get the current server name, do not use the servername set in portal properties
        // do not add ports if they are standard
		String currentServerName = request.getServerName();

		if (request.getServerPort() != HTTP_PORT
				&& request.getServerPort() != HTTPS_PORT) {
			currentServerName = currentServerName.concat(SEP).concat(
					Integer.toString(request.getServerPort()));
		}

        // ensure we have a server name or service name
        if (casServerName == null && casServiceUrl == null)
            throw new ServletException("need one of the following configuration " + "parameters: edu.yale.its.tp.cas.client.filter.serviceUrl or "
                    + "edu.yale.its.tp.cas.client.filter.serverName");

        try {
            // use the given string if it's provided
            if (casServiceUrl != null) {
                serviceString = URLEncoder.encode(casServiceUrl, UTF_8);

				if (log.isDebugEnabled()) {
					log.debug("use the given string casServiceUrl : "
						+ serviceString);
				}

            } else if (header != null) {
                // [Osivia] get url from front web server
                
                StringBuffer sb = new StringBuffer();
                
                sb.append(header);
                sb.append(request.getRequestURI());

                // Ticket management :  Copied from Util.getService
                if (request.getQueryString() != null) {
                    // first, see whether we've got a 'ticket' at all
                    int ticketLoc = request.getQueryString().indexOf("ticket=");

                    // if ticketLoc == 0, then it's the only parameter and we ignore
                    // the whole query string

                    // if no ticket is present, we use the query string wholesale
                    if (ticketLoc == -1)
                        sb.append("?" + request.getQueryString());
                    else if (ticketLoc > 0) {
                        ticketLoc = request.getQueryString().indexOf("&ticket=");
                        if (ticketLoc == -1) {
                            // there was a 'ticket=' unrelated to a parameter named 'ticket'
                            sb.append("?" + request.getQueryString());
                        } else if (ticketLoc > 0) {
                            // otherwise, we use the query string up to "&ticket="
                            sb.append("?" + request.getQueryString().substring(0, ticketLoc));
                        }
                    }
                }
                  

                serviceString = URLEncoder.encode(sb.toString(), UTF_8);

				if (log.isDebugEnabled()) {
					log.debug("use the url given by front web server: "
						+ serviceString);
				}
            } else if (currentServerName != null) {
                // [Osivia] try to build service url
                serviceString = Util.getService(request, currentServerName);

				if (log.isDebugEnabled()) {
				log.debug("try to build service url with the request : "
						+ serviceString);
				}
            } else {
                // otherwise, return our best guess at the service
                serviceString = Util.getService(request, casServerName);

				if (log.isDebugEnabled()) {
				log.debug("default case, return our best guess at the service : "
						+ serviceString);
				}
            }
        } catch (UnsupportedEncodingException e) {
            throw new ServletException(e);
        }
        return serviceString;
    }

   private boolean isSecuredURI(String uri)
   {
      Set patterns = getSecuredUrlPatterns();

      if (log.isDebugEnabled())
      {
         log.debug("Checking if requested uri '" + uri + "' matches secured url patterns: " + patterns);
      }

      for (Iterator iterator = patterns.iterator(); iterator.hasNext();)
      {
         String pattern = (String)iterator.next();

         if (uri.indexOf(pattern) != -1)
         {
            return true;
         }
      }
      return false;
   }


   public Set getSecuredUrlPatterns()
   {
      if (urlPatterns == null)
      {
         urlPatterns = IdentityTools.findSecuredURLs((Context)this.container);

         //Remove wildcards
         Set urls = new HashSet();
         for (Iterator iterator = urlPatterns.iterator(); iterator.hasNext();)
         {
            String pattern = (String)iterator.next();
            urls.add(pattern.replaceAll("\\*",""));
         }
         urlPatterns = urls;
      }

      return urlPatterns;
   }
}
