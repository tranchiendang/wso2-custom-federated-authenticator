/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.custom;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of custom
 */
public class CustomAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(CustomAuthenticator.class);

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return org.wso2.carbon.identity.authenticator.custom.CustomAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return org.wso2.carbon.identity.authenticator.custom.CustomAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get OAuth2 Scope
     *
     * @param scope                   Scope
     * @param authenticatorProperties Authentication properties.
     * @return OAuth2 Scope
     */
    @Override
    protected String getScope(String scope, Map<String, String> authenticatorProperties) {
        return "";
    }

    /**
     * Process the response of the custom end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                AuthenticationContext context) throws AuthenticationFailedException {
        boolean authenticated = true; // Assign the authentication step based on the webservice output
        if(!authenticated){
            throw new AuthenticationFailedException("Access token is empty or null");
        }

        Map<ClaimMapping, String> claims = new HashMap<ClaimMapping, String>();
        String username = "mrt";
        claims.put(ClaimMapping.build("name", "name", null,false), username);

        log.info("--------------- CustomAuthenticatorFederated: username is " + username + " -----------------------");

        AuthenticatedUser authenticatedUserObj = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUserObj.setAuthenticatedSubjectIdentifier(username);
        authenticatedUserObj.setUserAttributes(claims);
        context.setSubject(authenticatedUserObj);
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        //We are not redirecting the use to any external page, therefore setting this attribute to null
        log.info("--------------- CustomAuthenticatorFederated canHandle()-----------------------");
        request.setAttribute(FrameworkConstants.REQ_ATTR_HANDLED, null);
        return true;
    }
}
