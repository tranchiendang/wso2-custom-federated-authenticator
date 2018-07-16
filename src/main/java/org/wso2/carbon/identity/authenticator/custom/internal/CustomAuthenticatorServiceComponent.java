package org.wso2.carbon.identity.authenticator.custom.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.authenticator.custom.CustomAuthenticator;

import java.util.Hashtable;

/**
 * @scr.component name="identity.application.authenticator.custom.component" immediate="true"
 */
public class CustomAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(CustomAuthenticatorServiceComponent.class);

    protected void activate(ComponentContext ctxt) {
        try {
            CustomAuthenticator authenticator = new CustomAuthenticator();
            Hashtable<String, String> props = new Hashtable<String, String>();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    authenticator, props);
            if (log.isDebugEnabled()) {
                log.debug("custom authenticator is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error while activating the custom authenticator ", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("custom authenticator is deactivated");
        }
    }
}
