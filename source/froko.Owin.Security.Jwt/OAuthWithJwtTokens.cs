//-------------------------------------------------------------------------------
// <copyright file="OAuthWithJwtTokens.cs" company="frokonet.ch">
//   Copyright (c) 2014-2016
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
// </copyright>
//-------------------------------------------------------------------------------

namespace froko.Owin.Security.Jwt
{
    using System;
    using System.Configuration;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.Owin.Security.DataHandler.Encoder;

    /// <summary>
    /// Abstract configuration class for OAuth authentication with Json Web Tokens (JWT)
    /// </summary>
    public abstract class OAuthWithJwtTokens
    {
        /// <summary>
        /// Gets the issuer from an App setting called "Issuer"
        /// </summary>
        public virtual string Issuer => ConfigurationManager.AppSettings["Issuer"];

        /// <summary>
        /// Gets the audience id from an App setting called "AudienceId"
        /// </summary>
        public virtual string AudienceId => ConfigurationManager.AppSettings["AudienceId"];

        /// <summary>
        /// Gets the audience secret from an App setting called "AudienceSecret"
        /// </summary>
        public virtual byte[] AudienceSecret => TextEncodings.Base64Url.Decode(ConfigurationManager.AppSettings["AudienceSecret"]);
        
        /// <summary>
        /// Gets all allowed origns
        /// </summary>
        public virtual AllowedOrigins AllowedOrigins => AllowedOrigins.All;

        /// <summary>
        /// Gets the fact that insecure HTTP is allowed (Default: true / allowed)
        /// </summary>
        public virtual bool AllowInsecureHttp => true;

        /// <summary>
        /// Gets the token endpoint path
        /// </summary>
        public virtual string TokenEndpointPath => "/oauth/token";

        /// <summary>
        /// Gets the access token expiration time span
        /// </summary>
        public virtual TimeSpan AccessTokenExpireTimeSpan => TimeSpan.FromDays(1);

        /// <summary>
        /// Verifies credentials
        /// </summary>
        /// <param name="userName">The user name</param>
        /// <param name="password">The password</param>
        public abstract Task<bool> VerifyCredentials(UserName userName, Password password);

        /// <summary>
        /// Fills claims to an identity
        /// </summary>
        /// <param name="userName">The user name</param>
        /// <param name="identity">The identity</param>
        public abstract Task FillClaims(UserName userName, ClaimsIdentity identity);
    }
}