//-------------------------------------------------------------------------------
// <copyright file="OAuthGrantResourceOwnerCredentialsContextExtensions.cs" company="frokonet.ch">
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

    using Microsoft.Owin.Security.OAuth;

    /// <summary>
    /// Extension methods for <see cref="OAuthGrantResourceOwnerCredentialsContext"/>
    /// </summary>
    public static class OAuthGrantResourceOwnerCredentialsContextExtensions
    {
        /// <summary>
        /// Allows origins by adding them to the response header with the "Access-Control-Allow-Origin" key
        /// </summary>
        /// <param name="context">The context to allow origins on</param>
        /// <param name="allowedOrigins">A list of allowed origins represented by an instance of type <see cref="AllowedOrigins"/></param>
        public static void AllowOrigins(
            this OAuthGrantResourceOwnerCredentialsContext context,
            AllowedOrigins allowedOrigins)
        {
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", allowedOrigins);
        }

        /// <summary>
        /// Returns the fact that the credentials within this context are valid
        /// </summary>
        /// <param name="context">The context on which the credentials are being validated</param>
        /// <param name="verifyCredentials">Async function call which verifies credentials</param>
        /// <returns></returns>
        public static Task<bool> HasValidCredentials(
            this OAuthGrantResourceOwnerCredentialsContext context,
            Func<UserName, Password, Task<bool>> verifyCredentials)
        {
            return verifyCredentials(context.UserName, context.Password);
        }

        /// <summary>
        /// Creates an identity represented as an instance of type <see cref="ClaimsIdentity"/> out of the context
        /// </summary>
        /// <param name="context">The context from which to create the identity</param>
        /// <param name="fillClaims">Async function call which adds claims to the <see cref="ClaimsIdentity"/> object</param>
        /// <returns></returns>
        public static async Task<ClaimsIdentity> CreateIdentity(
            this OAuthGrantResourceOwnerCredentialsContext context,
            Func<UserName, ClaimsIdentity, Task> fillClaims)
        {
            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));

            await fillClaims(context.UserName, identity).ConfigureAwait(false);

            return identity;
        }
    }
}