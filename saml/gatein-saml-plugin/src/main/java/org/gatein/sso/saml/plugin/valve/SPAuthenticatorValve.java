package org.gatein.sso.saml.plugin.valve;

import java.security.Principal;
import java.util.List;

import org.apache.catalina.connector.Request;
import org.picketlink.identity.federation.bindings.tomcat.sp.ServiceProviderAuthenticator;
import org.picketlink.identity.federation.bindings.tomcat.sp.holder.ServiceProviderSAMLContext;

/**
 *Service Provider Authenticator Valve
 *
 */
public class SPAuthenticatorValve extends ServiceProviderAuthenticator {
	
	/* (non-Javadoc)
	 * @see org.picketlink.identity.federation.bindings.tomcat.sp.AbstractSPFormAuthenticator#getGenericPrincipal(org.apache.catalina.connector.Request, java.lang.String, java.util.List)
	 */
	@Override
	protected Principal getGenericPrincipal(Request request, String username,
			List<String> roles) {
		ServiceProviderSAMLContext.push(username, roles);
		Principal principal = context.getRealm().authenticate(username,
				ServiceProviderSAMLContext.EMPTY_PASSWORD);
		ServiceProviderSAMLContext.clear();
		return principal;
	}
}