//-------------------------------------------------------------------------------
// <copyright file="JwtOAuthProvider.cs" company="frokonet.ch">
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
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.OAuth;

    /// <summary>
    /// OAuth authorization server provider for Json Web Tokens (JWT)
    /// </summary>
    public class JwtOAuthProvider : OAuthAuthorizationServerProvider
    {
        private readonly AllowedOrigins allowedOrigins;
        private readonly Func<UserName, Password, Task<bool>> verifyCredentials;
        private readonly Func<UserName, ClaimsIdentity, Task> fillClaims;

        /// <summary>
        /// Creates a new instance of <see cref="JwtOAuthProvider"/>
        /// </summary>
        /// <param name="allowedOrigins">A list of allowed origins represented by an instance of type <see cref="AllowedOrigins"/></param>
        /// <param name="verifyCredentials">Async function call which verifies credentials</param>
        /// <param name="fillClaims">Async function call which adds claims to the <see cref="ClaimsIdentity"/> object</param>
        public JwtOAuthProvider(
            AllowedOrigins allowedOrigins,
            Func<UserName, Password, Task<bool>> verifyCredentials,
            Func<UserName, ClaimsIdentity, Task> fillClaims)
        {
            this.allowedOrigins = allowedOrigins;
            this.verifyCredentials = verifyCredentials;
            this.fillClaims = fillClaims;
        }

        /// <inheritdoc />
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            context.AllowOrigins(this.allowedOrigins);

            if (!await context.HasValidCredentials(this.verifyCredentials).ConfigureAwait(false))
            {
                context.SetError("invalid_grant", "The user name or password is incorrect.");
                return;
            }

            var identity = await context.CreateIdentity(this.fillClaims).ConfigureAwait(false);
            var ticket = new AuthenticationTicket(identity, null);

            context.Validated(ticket);
        }
    }
}