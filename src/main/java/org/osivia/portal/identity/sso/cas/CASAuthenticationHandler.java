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


//jmx related
import javax.management.MBeanServer;
import javax.management.ObjectName;

import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.jboss.mx.util.MBeanProxy;
import org.jboss.mx.util.MBeanServerLocator;
import org.jboss.portal.identity.sso.AuthenticationService;

/*
 * Created on May 23, 2007
 * 
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class CASAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler
{
   /**
    * 
    */
   protected boolean authenticateUsernamePasswordInternal(UsernamePasswordCredentials credentials) throws AuthenticationException
   {
      try
      {
         boolean status = false;
         
         String username = credentials.getUsername();
         String password = credentials.getPassword();         
         
         MBeanServer mbeanServer = MBeanServerLocator.locateJBoss();
         AuthenticationService authService = (AuthenticationService)
         MBeanProxy.get(AuthenticationService.class,new ObjectName("portal:service=Module,type=CASAuthenticationService"),mbeanServer);
              
         //Perform this operation in the context of a UserTransaction         
         status = authService.authenticate(username, password);
         
         return status;
      }
      catch(Exception e)
      {
         e.printStackTrace();
         return false;
      }
   }
}
