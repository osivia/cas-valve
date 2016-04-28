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

import java.util.Iterator;
import java.util.Set;

import javax.naming.InitialContext;

import org.apache.log4j.Logger;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.jboss.portal.identity.MembershipModule;
import org.jboss.portal.identity.Role;
import org.jboss.portal.identity.User;
import org.jboss.portal.identity.UserModule;
import org.jboss.portal.identity.UserProfileModule;
import org.jboss.portal.identity.sso.AuthenticationService;

/*
 * Created on May 24, 2007
 * 
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class CASAuthenticationService implements AuthenticationService
{
   private static Logger log = Logger.getLogger(CASAuthenticationService.class);
   
    private UserModule userModule = null;
   private UserProfileModule profileModule = null;
   private MembershipModule membershipModule = null;
   private String havingRole = null;
   
   /**
    * 
    *
    */
   public void start()
   {
      try
      {
         InitialContext initialContext = new InitialContext();
         
         this.userModule = (UserModule)initialContext.lookup("java:/portal/UserModule");
         this.profileModule = (UserProfileModule)initialContext.lookup("java:/portal/UserProfileModule");
         this.membershipModule = (MembershipModule)initialContext.lookup("java:/portal/MembershipModule");
      }
      catch(Exception e)
      {
         log.error(this, e);
         this.stop();
      }
   }
   
   /**
    * 
    *
    */
   public void stop()
   {
      this.userModule = null;
      this.profileModule = null;
      this.membershipModule = null;
      this.havingRole = null;
   }
   
   /**
    * 
    * @return
    */
   public String getHavingRole()
   {
      return havingRole;
   }

   /**
    * 
    * @param havingRole
    */
   public void setHavingRole(String havingRole)
   {
      this.havingRole = havingRole;
   }

   /**
    * 
    */
   public boolean authenticate(String username, String password)
   {
      Session session = null;
      Transaction tx = null;
      try
      {
         boolean status = false;
         
         InitialContext initialContext = new InitialContext();
         SessionFactory sessionFactory = (SessionFactory)initialContext.lookup("java:/portal/IdentitySessionFactory");
         session = sessionFactory.openSession();
         tx = session.beginTransaction();
         
         User user = this.userModule.findUserByUserName(username);         
         if(user != null)
         {
            //Check and make sure the user account is enabled
            Boolean enabled = (Boolean)this.profileModule.getProperty(user, User.INFO_USER_ENABLED);
            if(enabled != null && enabled.booleanValue())
            {
               //Check and make sure user has proper role setup
               if(this.havingRole != null && this.havingRole.trim().length()>0)
               {
                  boolean hasTheRole = false;
                  Set roles = this.membershipModule.getRoles(user);
                  for (Iterator i = roles.iterator(); i.hasNext();)
                  {
                     Role role = (Role)i.next();
                     if (this.havingRole.equals(role.getName()))
                     {
                        hasTheRole = true;
                        break;
                     }
                  }
                  if (!hasTheRole)
                  {
                     return false;
                  }
               }
               
               //Now perform validation
               status = user.validatePassword(password);
            }
         }         
                  
         return status;
      }
      catch(Exception e)
      {
         log.error(this, e);
         return false;
      }
      finally
      {
         tx.commit();
         session.close();
      }
   }
}
