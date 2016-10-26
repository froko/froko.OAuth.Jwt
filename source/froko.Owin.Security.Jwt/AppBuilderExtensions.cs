//-------------------------------------------------------------------------------
// <copyright file="AppBuilderExtensions.cs" company="frokonet.ch">
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
    
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.DataHandler.Encoder;
    using Microsoft.Owin.Security.Jwt;
    using Microsoft.Owin.Security.OAuth;

    using global::Owin;

    /// <summary>
    /// Extension methods for the <see cref="IAppBuilder"/> interface
    /// </summary>
    public static class AppBuilderExtensions
    {
        private const string TokenEndpointPath = "/oauth/token";

        private static readonly TimeSpan AccessTokenExpireTimeSpan = TimeSpan.FromDays(1);
        private static readonly AllowedOrigins AllOrigins = AllowedOrigins.All;

        /// <summary>
        /// Configures OAuth authentication with Json Web Tokens (JWT)
        /// and allows the use of insecure HTTP
        /// </summary>
        /// <remarks>
        /// This represents the most simple use case:
        /// - Username and password must be the same
        /// - The user name is added as role name to the <see cref="ClaimsIdentity"/> object
        /// </remarks>
        /// <param name="app">The app builder to configure</param>
        public static void UseOauthWithJwtTokens(this IAppBuilder app)
        {
            app.UseOauthWithJwtTokens(new SimpleOAuthWithJwtTokens());
        }

        /// <summary>
        /// Configures OAuth authentication with Json Web Tokens (JWT)
        /// and allows only secure HTTPS
        /// </summary>
        /// <param name="app">The app builder to configure</param>
        /// <param name="verifyCredentials">Async function call which verifies credentials</param>
        /// <param name="fillClaims">Async function call which adds claims to the <see cref="ClaimsIdentity"/> object</param>
        public static void UseOauthWithJwtTokens(
            this IAppBuilder app,
            Func<UserName, Password, Task<bool>> verifyCredentials,
            Func<UserName, ClaimsIdentity, Task> fillClaims)
        {
            var issuer = ConfigurationManager.AppSettings["Issuer"];
            var audienceId = ConfigurationManager.AppSettings["AudienceId"];
            var audienceSecret = TextEncodings.Base64Url.Decode(ConfigurationManager.AppSettings["AudienceSecret"]);

            app.ConfigureOAuthTokenGeneration(
                false,
                TokenEndpointPath,
                AccessTokenExpireTimeSpan,
                AllOrigins,
                issuer,
                audienceId,
                audienceSecret,
                verifyCredentials,
                fillClaims);

            app.ConfigureOAuthTokenConsumption(
                issuer,
                audienceId,
                audienceSecret);
        }

        /// <summary>
        /// Configures OAuth authentication with Json Web Tokens (JWT)
        /// </summary>
        /// <param name="app">The app builder to configure</param>
        /// <param name="configuration">An instance of <see cref="OAuthWithJwtTokens"/></param>
        public static void UseOauthWithJwtTokens(
            this IAppBuilder app,
            OAuthWithJwtTokens configuration)
        {
            app.ConfigureOAuthTokenGeneration(
                configuration.AllowInsecureHttp,
                configuration.TokenEndpointPath,
                configuration.AccessTokenExpireTimeSpan,
                configuration.AllowedOrigins,
                configuration.Issuer,
                configuration.AudienceId,
                configuration.AudienceSecret,
                configuration.VerifyCredentials,
                configuration.FillClaims);

            app.ConfigureOAuthTokenConsumption(
                configuration.Issuer,
                configuration.AudienceId,
                configuration.AudienceSecret);
        }
        
        private static void ConfigureOAuthTokenGeneration(
            this IAppBuilder app,
            bool allowInsecureHttp,
            string tokenEndpointPath,
            TimeSpan accessTokenExpireTimeSpan, 
            AllowedOrigins allowedOrigins,
            string issuer,
            string audienceId,
            byte[] audienceSecret,
            Func<UserName, Password, Task<bool>> verifyCredentials,
            Func<UserName, ClaimsIdentity, Task> fillClaims)
        {
            var oAuthServerOptions = new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString(tokenEndpointPath),
                AccessTokenExpireTimeSpan = accessTokenExpireTimeSpan,
                Provider = new JwtOAuthProvider(allowedOrigins, verifyCredentials, fillClaims),
                AccessTokenFormat = new JwtTokenFormat(issuer, audienceId, audienceSecret)
            };

            if (allowInsecureHttp)
            {
                oAuthServerOptions.AllowInsecureHttp = true;
            }

            app.UseOAuthAuthorizationServer(oAuthServerOptions);
        }

        private static void ConfigureOAuthTokenConsumption(this IAppBuilder app, string issuer, string audienceId, byte[] audienceSecret)
        {
            var authenticationOptions = new JwtBearerAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,
                AllowedAudiences = new[] { audienceId },
                IssuerSecurityTokenProviders = new IIssuerSecurityTokenProvider[]
                {
                    new SymmetricKeyIssuerSecurityTokenProvider(issuer, audienceSecret)
                }
            };

            app.UseJwtBearerAuthentication(authenticationOptions);
        }
    }
}